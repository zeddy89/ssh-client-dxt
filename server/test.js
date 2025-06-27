const { MCPServer } = require('@modelcontextprotocol/sdk');

console.log('Testing MCP Server...');
console.log('MCPServer:', MCPServer);

try {
  const server = new MCPServer();
  console.log('Server created successfully');
  console.log('Server object:', server);
} catch (error) {
  console.error('Error creating server:', error);
}