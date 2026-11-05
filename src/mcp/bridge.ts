import { UnauthorizedError } from "@modelcontextprotocol/sdk/client/auth.js";
import { BridgeOAuth } from "./oauthClient.js";
import { StreamableHTTPClientTransport, StreamableHTTPError } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { isJSONRPCRequest } from "@modelcontextprotocol/sdk/types.js";

/** Relay the protocol to the running gateway; all token, vault and policy checks stay there. */
export async function startStdioBridge(endpoint: string, token = "") {
  const url = new URL(endpoint);
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) throw new Error("Invalid MCP_SSH_URL");
  if (token) throw new Error("Static tokens are no longer supported. Remove MCP_SSH_TOKEN and sign in with OAuth.");
  if (url.protocol !== "https:" && !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)) throw new Error("Remote MCP requires HTTPS");
  const oauth = new BridgeOAuth(endpoint);
  await oauth.prepare();
  const http = new StreamableHTTPClientTransport(url, {
    authProvider: oauth,
  });
  const stdio = new StdioServerTransport();
  let closing = false;
  const report = (e: unknown) => {
    // Do not print server response bodies or credentials to the client's logs.
    const status = e instanceof StreamableHTTPError ? e.code : undefined;
    return status === 401 ? "OAuth credentials rejected; sign in again."
      : status === 503 ? "MCP gateway temporarily unavailable; check the running service and retry."
      : "MCP gateway connection failed; check that the service is running and the configured URL is correct.";
  };
  const close = async () => {
    if (closing) return;
    closing = true;
    process.stdin.off("end", onEnd);
    process.off("SIGINT", onEnd);
    process.off("SIGTERM", onEnd);
    oauth.close();
    await Promise.allSettled([http.close(), stdio.close()]);
  };
  const onEnd = () => { void close(); };
  stdio.onmessage = (message) => {
    void http.send(message).catch(async (error) => {
      if (error instanceof UnauthorizedError) { const code = await oauth.authorizationCode(); await http.finishAuth(code); await http.send(message); return; }
      if (closing) return;
      const explanation = report(error);
      console.error(explanation);
      if (isJSONRPCRequest(message)) {
        await stdio.send({ jsonrpc: "2.0", id: message.id, error: { code: -32000, message: explanation } });
      }
    }).catch(() => { void close(); });
  };
  http.onmessage = (message) => {
    if ("result" in message && message.result && typeof message.result === "object" && "protocolVersion" in message.result && typeof message.result.protocolVersion === "string") {
      http.setProtocolVersion(message.result.protocolVersion);
    }
    void stdio.send(message).catch(() => { void close(); });
  };
  stdio.onerror = () => { console.error("Invalid MCP message on stdin."); };
  http.onerror = () => {}; // send() reports request failures, including their request ID.
  http.onclose = onEnd;
  stdio.onclose = onEnd;
  process.stdin.once("end", onEnd);
  process.once("SIGINT", onEnd);
  process.once("SIGTERM", onEnd);
  await http.start();
  await stdio.start();
  return close;
}
