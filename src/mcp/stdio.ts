import { startStdioBridge } from "./bridge.js";

try {
  await startStdioBridge(process.env.MCP_SSH_URL || "http://127.0.0.1:7778/mcp", process.env.MCP_SSH_TOKEN || "");
} catch {
  console.error("Cannot start MCP SSH bridge. Set MCP_SSH_URL using the configuration from the web UI and sign in with OAuth.");
  process.exitCode = 1;
}
