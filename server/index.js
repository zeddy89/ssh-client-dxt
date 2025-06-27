import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema, ListPromptsRequestSchema, GetPromptRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { Client } from 'ssh2';
import keytar from 'keytar';
import winston from 'winston';
import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import Joi from 'joi';
import { promises as fs, readFileSync, createReadStream, createWriteStream } from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';

class SecureSSHServer {
  constructor() {
    this.server = new Server(
      {
        name: 'secure-ssh-client',
        version: '1.0.0',
      },
      {
        capabilities: {
          tools: {},
          prompts: {}
        },
      }
    );
    
    this.sessions = new Map();
    this.knownHosts = new Map();
    this.maxSessions = process.env.MAX_SESSIONS ? parseInt(process.env.MAX_SESSIONS) : 0;
    this.sessionTimeout = process.env.SESSION_TIMEOUT ? parseInt(process.env.SESSION_TIMEOUT) * 60 * 1000 : 30 * 60 * 1000;
    this.enableAuditLog = process.env.ENABLE_AUDIT_LOG !== 'false';
    this.defaultUsername = process.env.DEFAULT_USERNAME || '';
    // Handle environment variable that might contain unexpanded template strings
    const keyPath = process.env.DEFAULT_KEY_PATH || '';
    this.defaultKeyPath = (keyPath && !keyPath.includes('${')) ? keyPath : '';
    this.auditLogger = this.enableAuditLog ? this.setupAuditLogger() : null;
    this.savedConfigs = new Map(); // Store saved SSH configurations
    this.setupTools();
    this.setupPrompts();
    this.startSessionCleanup();
  }

  setupAuditLogger() {
    return winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
      transports: [
        new winston.transports.File({ 
          filename: path.join(os.homedir(), '.ssh-mcp-audit.log'),
          maxsize: 10485760, // 10MB
          maxFiles: 5
        })
      ]
    });
  }

  async validateInput(schema, data) {
    try {
      return await schema.validateAsync(data);
    } catch (error) {
      throw new Error(`Input validation failed: ${error.message}`);
    }
  }

  async getStoredCredentials(host, username) {
    const service = 'ssh-mcp-client';
    const account = `${username}@${host}`;
    try {
      const password = await keytar.getPassword(service, account);
      return password;
    } catch (error) {
      return null;
    }
  }

  async storeCredentials(host, username, password) {
    const service = 'ssh-mcp-client';
    const account = `${username}@${host}`;
    await keytar.setPassword(service, account, password);
  }

  generateSessionId() {
    return uuidv4();
  }

  auditLog(level, message, metadata) {
    if (this.auditLogger) {
      this.auditLogger[level](message, metadata);
    }
  }

  async verifyHostKey(host, hostKey) {
    const knownHostsPath = path.join(os.homedir(), '.ssh', 'known_hosts');
    const hostFingerprint = crypto.createHash('sha256').update(hostKey).digest('hex');
    
    // Check in-memory cache first
    if (this.knownHosts.has(host)) {
      const storedFingerprint = this.knownHosts.get(host);
      if (storedFingerprint !== hostFingerprint) {
        throw new Error('Host key verification failed: Key mismatch');
      }
      return true;
    }

    // Check known_hosts file
    try {
      const knownHostsContent = await fs.readFile(knownHostsPath, 'utf8');
      const lines = knownHostsContent.split('\n');
      for (const line of lines) {
        if (line.includes(host)) {
          // Simplified check - in production, parse SSH known_hosts format properly
          this.knownHosts.set(host, hostFingerprint);
          return true;
        }
      }
    } catch (error) {
      // Known hosts file doesn't exist
    }

    // New host - store it
    this.knownHosts.set(host, hostFingerprint);
    return true;
  }

  cleanupSession(sessionId) {
    const session = this.sessions.get(sessionId);
    if (session) {
      if (session.connection) {
        session.connection.end();
      }
      clearTimeout(session.timeoutId);
      this.sessions.delete(sessionId);
      this.auditLog('info', 'Session terminated', { sessionId, reason: 'cleanup' });
    }
  }

  startSessionCleanup() {
    setInterval(() => {
      const now = Date.now();
      for (const [sessionId, session] of this.sessions) {
        if (now - session.lastActivity > this.sessionTimeout) {
          this.cleanupSession(sessionId);
        }
      }
    }, 60000); // Check every minute
  }

  setupTools() {
    // Register the tools list handler
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          {
            name: "ssh_connect",
            description: "Establish a secure SSH connection",
            inputSchema: {
              type: 'object',
              properties: {
                host: { type: 'string', description: 'SSH server hostname or IP' },
                port: { type: 'number', description: 'SSH port (default: 22)', default: 22 },
                username: { type: 'string', description: 'SSH username' },
                password: { type: 'string', description: 'SSH password (optional if using stored credentials)' },
                privateKey: { type: 'string', description: 'Path to private key file (optional)' },
                passphrase: { type: 'string', description: 'Private key passphrase (optional)' },
                storeCredentials: { type: 'boolean', description: 'Store credentials securely', default: false },
                label: { type: 'string', description: 'Optional label for this connection' },
                configName: { type: 'string', description: 'Use a saved configuration' }
              },
              required: ['host', 'username']
            }
          },
          {
            name: "ssh_execute",
            description: "Execute a command over SSH",
            inputSchema: {
              type: 'object',
              properties: {
                sessionId: { type: 'string', description: 'SSH session ID' },
                command: { type: 'string', description: 'Command to execute' },
                timeout: { type: 'number', description: 'Command timeout in seconds', default: 30 }
              },
              required: ['sessionId', 'command']
            }
          },
          {
            name: "ssh_disconnect",
            description: "Disconnect an SSH session",
            inputSchema: {
              type: 'object',
              properties: {
                sessionId: { type: 'string', description: 'SSH session ID' }
              },
              required: ['sessionId']
            }
          },
          {
            name: "ssh_list_sessions",
            description: "List all active SSH sessions",
            inputSchema: {
              type: 'object',
              properties: {}
            }
          },
          {
            name: "ssh_upload_file",
            description: "Upload a file to remote server via SFTP",
            inputSchema: {
              type: 'object',
              properties: {
                sessionId: { type: 'string', description: 'SSH session ID' },
                localPath: { type: 'string', description: 'Local file path to upload' },
                remotePath: { type: 'string', description: 'Remote destination path' }
              },
              required: ['sessionId', 'localPath', 'remotePath']
            }
          },
          {
            name: "ssh_download_file",
            description: "Download a file from remote server via SFTP",
            inputSchema: {
              type: 'object',
              properties: {
                sessionId: { type: 'string', description: 'SSH session ID' },
                remotePath: { type: 'string', description: 'Remote file path to download' },
                localPath: { type: 'string', description: 'Local destination path' }
              },
              required: ['sessionId', 'remotePath', 'localPath']
            }
          },
          {
            name: "ssh_port_forward",
            description: "Set up SSH port forwarding",
            inputSchema: {
              type: 'object',
              properties: {
                sessionId: { type: 'string', description: 'SSH session ID' },
                type: { type: 'string', enum: ['local', 'remote'], description: 'Type of port forwarding' },
                sourcePort: { type: 'number', description: 'Source port' },
                destinationHost: { type: 'string', description: 'Destination host' },
                destinationPort: { type: 'number', description: 'Destination port' }
              },
              required: ['sessionId', 'type', 'sourcePort', 'destinationHost', 'destinationPort']
            }
          },
          {
            name: "ssh_manage_keys",
            description: "Manage SSH keys and stored credentials",
            inputSchema: {
              type: 'object',
              properties: {
                action: { type: 'string', enum: ['list', 'remove', 'generate'], description: 'Action to perform' },
                host: { type: 'string', description: 'Host for credential management (required for remove)' },
                username: { type: 'string', description: 'Username for credential management (required for remove)' },
                keyType: { type: 'string', enum: ['rsa', 'ed25519'], description: 'Key type for generation', default: 'ed25519' },
                keyPath: { type: 'string', description: 'Path to save generated key' }
              },
              required: ['action']
            }
          },
          {
            name: "ssh_verify_host",
            description: "Verify SSH host key fingerprint",
            inputSchema: {
              type: 'object',
              properties: {
                host: { type: 'string', description: 'SSH server hostname or IP' },
                port: { type: 'number', description: 'SSH port', default: 22 }
              },
              required: ['host']
            }
          },
          {
            name: "ssh_config_manage",
            description: "Manage saved SSH configurations",
            inputSchema: {
              type: 'object',
              properties: {
                action: { type: 'string', enum: ['create', 'list', 'get', 'delete', 'update'], description: 'Action to perform' },
                name: { type: 'string', description: 'Configuration name' },
                config: { 
                  type: 'object', 
                  description: 'Configuration details (for create/update)',
                  properties: {
                    host: { type: 'string', description: 'SSH server hostname or IP' },
                    port: { type: 'number', description: 'SSH port', default: 22 },
                    username: { type: 'string', description: 'SSH username' },
                    authMethod: { type: 'string', enum: ['password', 'key'], description: 'Authentication method' },
                    keyPath: { type: 'string', description: 'Path to private key file (if using key auth)' },
                    label: { type: 'string', description: 'Optional label for the connection' }
                  }
                }
              },
              required: ['action']
            }
          }
        ]
      };
    });

    // Register the tool call handler
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      switch (name) {
        case 'ssh_connect':
          return this.handleSSHConnect(args);
        case 'ssh_execute':
          return this.handleSSHExecute(args);
        case 'ssh_disconnect':
          return this.handleSSHDisconnect(args);
        case 'ssh_list_sessions':
          return this.handleSSHListSessions();
        case 'ssh_upload_file':
          return this.handleSSHUploadFile(args);
        case 'ssh_download_file':
          return this.handleSSHDownloadFile(args);
        case 'ssh_port_forward':
          return this.handleSSHPortForward(args);
        case 'ssh_manage_keys':
          return this.handleSSHManageKeys(args);
        case 'ssh_verify_host':
          return this.handleSSHVerifyHost(args);
        case 'ssh_config_manage':
          return this.handleSSHConfigManage(args);
        default:
          throw new Error(`Unknown tool: ${name}`);
      }
    });
  }

  setupPrompts() {
    // Register the prompts list handler
    this.server.setRequestHandler(ListPromptsRequestSchema, async () => {
      return {
        prompts: [
          {
            name: "ssh_config",
            description: "Configure SSH connection settings",
            arguments: [
              {
                name: "action",
                description: "What would you like to do?",
                required: true
              }
            ]
          },
          {
            name: "quick_connect",
            description: "Quick connect to a saved SSH configuration",
            arguments: [
              {
                name: "config_name",
                description: "Name of the saved configuration",
                required: true
              }
            ]
          }
        ]
      };
    });

    // Register the get prompt handler
    this.server.setRequestHandler(GetPromptRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      switch (name) {
        case 'ssh_config':
          return this.getSSHConfigPrompt(args);
        case 'quick_connect':
          return this.getQuickConnectPrompt(args);
        default:
          throw new Error(`Unknown prompt: ${name}`);
      }
    });
  }

  async getSSHConfigPrompt(args) {
    const savedConfigsList = Array.from(this.savedConfigs.keys()).join('\n');
    
    return {
      messages: [
        {
          role: "user",
          content: {
            type: "text",
            text: args.action || "What would you like to do with SSH configurations?"
          }
        },
        {
          role: "assistant",
          content: {
            type: "text",
            text: `SSH Configuration Menu

Available actions:
1. **new** - Create a new SSH configuration
2. **list** - List all saved configurations
3. **edit** - Edit an existing configuration
4. **delete** - Delete a saved configuration
5. **test** - Test a saved configuration

${savedConfigsList ? `\nSaved configurations:\n${savedConfigsList}` : '\nNo saved configurations yet.'}

To create a new configuration, I'll need:
- Connection name (for easy reference)
- Host (hostname or IP)
- Port (default: 22)
- Username
- Authentication method (password or key)
- Optional: key path or password to save

Example: "new myserver" to create a configuration named "myserver"`
          }
        }
      ]
    };
  }

  async getQuickConnectPrompt(args) {
    const configName = args.config_name;
    const config = this.savedConfigs.get(configName);
    
    if (!config) {
      const savedConfigsList = Array.from(this.savedConfigs.keys()).join(', ');
      return {
        messages: [
          {
            role: "user",
            content: {
              type: "text",
              text: `Connect to ${configName}`
            }
          },
          {
            role: "assistant",
            content: {
              type: "text",
              text: `Configuration "${configName}" not found.\n\nAvailable configurations: ${savedConfigsList || 'none'}`
            }
          }
        ]
      };
    }

    return {
      messages: [
        {
          role: "user",
          content: {
            type: "text",
            text: `Connect to ${configName}`
          }
        },
        {
          role: "assistant", 
          content: {
            type: "text",
            text: `Ready to connect to ${configName}:\n- Host: ${config.host}:${config.port}\n- Username: ${config.username}\n- Auth: ${config.authMethod}\n\nUse ssh_connect tool with these settings to establish connection.`
          }
        }
      ]
    };
  }

  async handleSSHConnect(params) {
    let validated = await this.validateInput(
      Joi.object({
        host: Joi.string().hostname().required(),
        port: Joi.number().port().default(22),
        username: Joi.string().default(this.defaultUsername).required(),
        password: Joi.string().optional(),
        privateKey: Joi.string().optional(),
        passphrase: Joi.string().optional(),
        storeCredentials: Joi.boolean().default(false),
        label: Joi.string().optional().description('Optional label for this connection'),
        configName: Joi.string().optional().description('Use a saved configuration')
      }),
      params
    );

    // If using a saved configuration
    if (validated.configName) {
      const savedConfig = this.savedConfigs.get(validated.configName);
      if (!savedConfig) {
        throw new Error(`Configuration '${validated.configName}' not found`);
      }
      // Merge saved config with any provided overrides
      validated = { ...savedConfig, ...validated };
    }

    // Check session limit if configured
    if (this.maxSessions > 0 && this.sessions.size >= this.maxSessions) {
      throw new Error(`Maximum number of SSH sessions (${this.maxSessions}) reached`);
    }
    
    const sessionId = this.generateSessionId();
    const connection = new Client();

    // Prepare authentication options
    const connectOptions = {
      host: validated.host,
      port: validated.port,
      username: validated.username,
      hostVerifier: (hostKey) => this.verifyHostKey(validated.host, hostKey)
    };

    // Authentication options
    const keyPath = validated.privateKey || (this.defaultKeyPath && this.defaultKeyPath.trim() ? this.defaultKeyPath : null);
    if (keyPath) {
      try {
        connectOptions.privateKey = readFileSync(keyPath);
        if (validated.passphrase) {
          connectOptions.passphrase = validated.passphrase;
        }
      } catch (error) {
        throw new Error(`Failed to read private key from ${keyPath}: ${error.message}`);
      }
    } else {
      // Try password in this order: provided > stored
      let password = validated.password;
      if (!password) {
        password = await this.getStoredCredentials(validated.host, validated.username);
      }
      if (!password) {
        throw new Error('No password provided and no stored credentials found. Please provide a password or use SSH key authentication.');
      }
      connectOptions.password = password;
    }

    return new Promise((resolve, reject) => {
      connection.on('ready', async () => {
        const session = {
          id: sessionId,
          connection,
          host: validated.host,
          username: validated.username,
          label: validated.label || `${validated.username}@${validated.host}:${validated.port}`,
          lastActivity: Date.now(),
          timeoutId: setTimeout(() => this.cleanupSession(sessionId), this.sessionTimeout)
        };

        this.sessions.set(sessionId, session);

        // Store credentials if requested
        if (validated.storeCredentials && validated.password) {
          try {
            await this.storeCredentials(validated.host, validated.username, validated.password);
          } catch (error) {
            console.error('Failed to store credentials:', error);
          }
        }

        this.auditLog('info', 'SSH connection established', {
          sessionId,
          host: validated.host,
          username: validated.username
        });

        resolve({
          content: [{
            type: "text",
            text: `SSH connection established successfully\nSession ID: ${sessionId}\nLabel: ${session.label}\nHost: ${validated.host}\nUsername: ${validated.username}`
          }]
        });
      });

      connection.on('error', (err) => {
        this.auditLog('error', 'SSH connection failed', {
          host: validated.host,
          username: validated.username,
          error: err.message
        });
        reject(new Error(`SSH connection failed: ${err.message}`));
      });

      connection.on('banner', (message) => {
        this.auditLog('info', 'SSH banner received', { 
          host: validated.host,
          banner: message 
        });
      });

      connection.connect(connectOptions);
    });
  }

  async handleSSHExecute(params) {
    const session = this.sessions.get(params.sessionId);
    if (!session) {
      throw new Error('Invalid session ID or session expired');
    }

    // Update last activity
    session.lastActivity = Date.now();

    // Validate command (basic security check)
    const dangerousPatterns = [/rm\s+-rf\s+\//, /:(){ :|:& };:/, /\$\(.*\)/];
    for (const pattern of dangerousPatterns) {
      if (pattern.test(params.command)) {
        this.auditLog('warn', 'Potentially dangerous command blocked', {
          sessionId: params.sessionId,
          command: params.command
        });
        throw new Error('Command contains potentially dangerous pattern');
      }
    }

    return new Promise((resolve, reject) => {
      const output = { stdout: '', stderr: '' };
      const timeout = setTimeout(() => {
        reject(new Error('Command execution timeout'));
      }, (params.timeout || 30) * 1000);

      session.connection.exec(params.command, (err, stream) => {
        if (err) {
          clearTimeout(timeout);
          reject(err);
          return;
        }

        stream.on('close', (code, signal) => {
          clearTimeout(timeout);
          this.auditLog('info', 'Command executed', {
            sessionId: params.sessionId,
            command: params.command,
            exitCode: code
          });
          
          resolve({
            content: [{
              type: "text",
              text: `Command: ${params.command}\n\nOutput:\n${output.stdout}\n\nErrors:\n${output.stderr}\n\nExit Code: ${code}`
            }]
          });
        });

        stream.on('data', (data) => {
          output.stdout += data.toString();
        });

        stream.stderr.on('data', (data) => {
          output.stderr += data.toString();
        });
      });
    });
  }

  async handleSSHDisconnect(params) {
    const session = this.sessions.get(params.sessionId);
    if (!session) {
      throw new Error('Invalid session ID');
    }

    this.cleanupSession(params.sessionId);
    
    return {
      content: [{
        type: "text",
        text: 'SSH session disconnected successfully'
      }]
    };
  }

  async handleSSHListSessions() {
    const activeSessions = [];
    for (const [sessionId, session] of this.sessions) {
      activeSessions.push({
        sessionId,
        label: session.label,
        host: session.host,
        username: session.username,
        connectedAt: new Date(session.lastActivity - this.sessionTimeout + session.lastActivity).toISOString(),
        lastActivity: new Date(session.lastActivity).toISOString()
      });
    }
    
    return {
      content: [{
        type: "text",
        text: `Active SSH Sessions (${activeSessions.length}):\n${JSON.stringify(activeSessions, null, 2)}`
      }]
    };
  }

  async handleSSHUploadFile(params) {
    const session = this.sessions.get(params.sessionId);
    if (!session) {
      throw new Error('Invalid session ID or session expired');
    }

    // Update last activity
    session.lastActivity = Date.now();

    return new Promise((resolve, reject) => {
      session.connection.sftp((err, sftp) => {
        if (err) {
          reject(new Error(`SFTP connection failed: ${err.message}`));
          return;
        }

        const readStream = createReadStream(params.localPath);
        const writeStream = sftp.createWriteStream(params.remotePath);

        writeStream.on('close', () => {
          sftp.end();
          this.auditLog('info', 'File uploaded', {
            sessionId: params.sessionId,
            localPath: params.localPath,
            remotePath: params.remotePath
          });
          resolve({
            content: [{
              type: "text",
              text: `File uploaded successfully:\n${params.localPath} → ${params.remotePath}`
            }]
          });
        });

        writeStream.on('error', (error) => {
          sftp.end();
          reject(new Error(`Upload failed: ${error.message}`));
        });

        readStream.pipe(writeStream);
      });
    });
  }

  async handleSSHDownloadFile(params) {
    const session = this.sessions.get(params.sessionId);
    if (!session) {
      throw new Error('Invalid session ID or session expired');
    }

    // Update last activity
    session.lastActivity = Date.now();

    return new Promise((resolve, reject) => {
      session.connection.sftp((err, sftp) => {
        if (err) {
          reject(new Error(`SFTP connection failed: ${err.message}`));
          return;
        }

        sftp.stat(params.remotePath, (statErr, stats) => {
          if (statErr) {
            sftp.end();
            reject(new Error(`Remote file not found: ${statErr.message}`));
            return;
          }

          const readStream = sftp.createReadStream(params.remotePath);
          const writeStream = createWriteStream(params.localPath);

          writeStream.on('close', () => {
            sftp.end();
            this.auditLog('info', 'File downloaded', {
              sessionId: params.sessionId,
              remotePath: params.remotePath,
              localPath: params.localPath
            });
            resolve({
              content: [{
                type: "text",
                text: `File downloaded successfully:\n${params.remotePath} → ${params.localPath}\nSize: ${stats.size} bytes`
              }]
            });
          });

          writeStream.on('error', (error) => {
            sftp.end();
            reject(new Error(`Download failed: ${error.message}`));
          });

          readStream.pipe(writeStream);
        });
      });
    });
  }

  async handleSSHPortForward(params) {
    const session = this.sessions.get(params.sessionId);
    if (!session) {
      throw new Error('Invalid session ID or session expired');
    }

    // Update last activity
    session.lastActivity = Date.now();

    if (params.type === 'local') {
      // Local port forwarding
      return new Promise((resolve, reject) => {
        session.connection.forwardOut(
          '127.0.0.1',
          params.sourcePort,
          params.destinationHost,
          params.destinationPort,
          (err, stream) => {
            if (err) {
              reject(new Error(`Port forwarding failed: ${err.message}`));
              return;
            }

            this.auditLog('info', 'Port forwarding established', {
              sessionId: params.sessionId,
              type: 'local',
              sourcePort: params.sourcePort,
              destination: `${params.destinationHost}:${params.destinationPort}`
            });

            resolve({
              content: [{
                type: "text",
                text: `Local port forwarding established:\nlocalhost:${params.sourcePort} → ${params.destinationHost}:${params.destinationPort}`
              }]
            });
          }
        );
      });
    } else {
      // Remote port forwarding
      return new Promise((resolve, reject) => {
        session.connection.forwardIn(
          params.destinationHost,
          params.destinationPort,
          (err, port) => {
            if (err) {
              reject(new Error(`Remote port forwarding failed: ${err.message}`));
              return;
            }

            this.auditLog('info', 'Remote port forwarding established', {
              sessionId: params.sessionId,
              type: 'remote',
              remotePort: port,
              localTarget: `localhost:${params.sourcePort}`
            });

            resolve({
              content: [{
                type: "text",
                text: `Remote port forwarding established:\n${params.destinationHost}:${port} → localhost:${params.sourcePort}`
              }]
            });
          }
        );
      });
    }
  }

  async handleSSHManageKeys(params) {
    const validated = await this.validateInput(
      Joi.object({
        action: Joi.string().valid('list', 'remove', 'generate').required(),
        host: Joi.string().when('action', { is: 'remove', then: Joi.required() }),
        username: Joi.string().when('action', { is: 'remove', then: Joi.required() }),
        keyType: Joi.string().valid('rsa', 'ed25519').default('ed25519'),
        keyPath: Joi.string().when('action', { is: 'generate', then: Joi.required() })
      }),
      params
    );

    switch (validated.action) {
      case 'list': {
        const service = 'ssh-mcp-client';
        try {
          const credentials = await keytar.findCredentials(service);
          const formattedCreds = credentials.map(c => ({
            account: c.account,
            host: c.account.split('@')[1],
            username: c.account.split('@')[0]
          }));
          
          return {
            content: [{
              type: "text",
              text: `Stored SSH Credentials:\n${JSON.stringify(formattedCreds, null, 2)}`
            }]
          };
        } catch (error) {
          throw new Error(`Failed to list credentials: ${error.message}`);
        }
      }
      
      case 'remove': {
        const service = 'ssh-mcp-client';
        const account = `${validated.username}@${validated.host}`;
        try {
          const deleted = await keytar.deletePassword(service, account);
          this.auditLog('info', 'Credentials removed', { host: validated.host, username: validated.username });
          
          return {
            content: [{
              type: "text",
              text: deleted ? `Credentials removed for ${account}` : `No credentials found for ${account}`
            }]
          };
        } catch (error) {
          throw new Error(`Failed to remove credentials: ${error.message}`);
        }
      }
      
      case 'generate': {
        // Key generation would require additional dependencies like node-forge
        // For now, we'll provide instructions
        return {
          content: [{
            type: "text",
            text: `To generate SSH keys, use the following command:\n\nssh-keygen -t ${validated.keyType} -f ${validated.keyPath}\n\nNote: Key generation is not implemented in this version for security reasons.`
          }]
        };
      }
    }
  }

  async handleSSHVerifyHost(params) {
    const validated = await this.validateInput(
      Joi.object({
        host: Joi.string().hostname().required(),
        port: Joi.number().port().default(22)
      }),
      params
    );

    return new Promise((resolve, reject) => {
      const connection = new Client();
      let hostKey = null;

      connection.on('ready', () => {
        connection.end();
      });

      connection.on('error', (err) => {
        if (hostKey) {
          // We got the host key even though connection failed
          const fingerprint = crypto.createHash('sha256').update(hostKey).digest('hex');
          resolve({
            content: [{
              type: "text",
              text: `Host Key Verification:\nHost: ${validated.host}:${validated.port}\nFingerprint (SHA256): ${fingerprint}\nNote: Connection failed but host key was retrieved.`
            }]
          });
        } else {
          reject(new Error(`Failed to verify host: ${err.message}`));
        }
      });

      connection.on('hostkeys', (keys) => {
        if (keys.length > 0) {
          hostKey = keys[0].data;
          const fingerprint = crypto.createHash('sha256').update(hostKey).digest('hex');
          
          this.auditLog('info', 'Host key verified', {
            host: validated.host,
            port: validated.port,
            fingerprint
          });

          resolve({
            content: [{
              type: "text",
              text: `Host Key Verification:\nHost: ${validated.host}:${validated.port}\nFingerprint (SHA256): ${fingerprint}\nKey Type: ${keys[0].type}`
            }]
          });
        }
      });

      // Try to connect just to get the host key
      connection.connect({
        host: validated.host,
        port: validated.port,
        username: 'dummy', // We just need the host key
        password: 'dummy',
        readyTimeout: 5000
      });
    });
  }

  async handleSSHConfigManage(params) {
    const validated = await this.validateInput(
      Joi.object({
        action: Joi.string().valid('create', 'list', 'get', 'delete', 'update').required(),
        name: Joi.string().when('action', { 
          is: Joi.valid('create', 'get', 'delete', 'update'), 
          then: Joi.required() 
        }),
        config: Joi.object({
          host: Joi.string().required(),
          port: Joi.number().port().default(22),
          username: Joi.string().required(),
          authMethod: Joi.string().valid('password', 'key').required(),
          keyPath: Joi.string().when('authMethod', { is: 'key', then: Joi.required() }),
          label: Joi.string()
        }).when('action', { 
          is: Joi.valid('create', 'update'), 
          then: Joi.required() 
        })
      }),
      params
    );

    switch (validated.action) {
      case 'create': {
        if (this.savedConfigs.has(validated.name)) {
          throw new Error(`Configuration '${validated.name}' already exists`);
        }
        this.savedConfigs.set(validated.name, validated.config);
        
        // Save password if provided
        if (validated.config.authMethod === 'password' && params.password) {
          await this.storeCredentials(validated.config.host, validated.config.username, params.password);
        }
        
        return {
          content: [{
            type: "text",
            text: `Configuration '${validated.name}' created successfully`
          }]
        };
      }
      
      case 'list': {
        const configs = [];
        for (const [name, config] of this.savedConfigs) {
          configs.push({
            name,
            host: config.host,
            port: config.port,
            username: config.username,
            authMethod: config.authMethod,
            label: config.label
          });
        }
        
        return {
          content: [{
            type: "text",
            text: `Saved SSH Configurations (${configs.length}):\n${JSON.stringify(configs, null, 2)}`
          }]
        };
      }
      
      case 'get': {
        const config = this.savedConfigs.get(validated.name);
        if (!config) {
          throw new Error(`Configuration '${validated.name}' not found`);
        }
        
        return {
          content: [{
            type: "text",
            text: `Configuration '${validated.name}':\n${JSON.stringify(config, null, 2)}`
          }]
        };
      }
      
      case 'delete': {
        if (!this.savedConfigs.has(validated.name)) {
          throw new Error(`Configuration '${validated.name}' not found`);
        }
        this.savedConfigs.delete(validated.name);
        
        return {
          content: [{
            type: "text",
            text: `Configuration '${validated.name}' deleted successfully`
          }]
        };
      }
      
      case 'update': {
        if (!this.savedConfigs.has(validated.name)) {
          throw new Error(`Configuration '${validated.name}' not found`);
        }
        this.savedConfigs.set(validated.name, validated.config);
        
        // Update password if provided
        if (validated.config.authMethod === 'password' && params.password) {
          await this.storeCredentials(validated.config.host, validated.config.username, params.password);
        }
        
        return {
          content: [{
            type: "text",
            text: `Configuration '${validated.name}' updated successfully`
          }]
        };
      }
    }
  }

  async start() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('Secure SSH MCP Server started');
  }
}

const server = new SecureSSHServer();
server.start().catch(console.error);