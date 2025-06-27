import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';

console.error('Starting simple SSH MCP server...');

const server = new Server(
  {
    name: 'secure-ssh-client',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Register handlers
server.setRequestHandler(ListToolsRequestSchema, async () => {
  console.error('ListTools request received');
  return {
    tools: [
      {
        name: 'test_tool',
        description: 'A simple test tool',
        inputSchema: {
          type: 'object',
          properties: {
            message: { type: 'string' }
          }
        }
      }
    ]
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  console.error('CallTool request received:', request.params.name);
  return {
    content: [{
      type: 'text',
      text: `Tool ${request.params.name} called with: ${JSON.stringify(request.params.arguments)}`
    }]
  };
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Server connected and ready');
}

main().catch(error => {
  console.error('Server error:', error);
  process.exit(1);
});