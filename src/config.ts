import { existsSync, readFileSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import { isIP } from "node:net";

export function portNumber(value: string | undefined, fallback: number, name: string): number {
  if (value === undefined) return fallback;
  if (!/^\d+$/.test(value) || Number(value) < 1 || Number(value) > 65535) throw new Error(`${name} must be a port from 1 to 65535`);
  return Number(value);
}

/** The external listener is opt-in; internal administration always stays on loopback. */
export function runtimeConfig(env: NodeJS.ProcessEnv = process.env) {
  const adminPort = portNumber(env.ADMIN_PORT, 7777, "ADMIN_PORT");
  const mcpPort = portNumber(env.MCP_PORT, 7778, "MCP_PORT");
  const gatewayPort = env.GATEWAY_PORT === undefined ? undefined : portNumber(env.GATEWAY_PORT, 8080, "GATEWAY_PORT");
  if (new Set([adminPort, mcpPort, gatewayPort].filter(x => x !== undefined)).size !== (gatewayPort ? 3 : 2)) throw new Error("Listener ports must be distinct");
  const gatewayBind = env.GATEWAY_BIND ?? "127.0.0.1";
  if (!isIP(gatewayBind)) throw new Error("GATEWAY_BIND must be an IP address");
  if (gatewayPort) {
    if (!env.AUTH_URL || !env.MCP_PUBLIC_URL) throw new Error("Gateway requires AUTH_URL and MCP_PUBLIC_URL");
    const issuer = new URL(env.AUTH_URL), resource = new URL(env.MCP_PUBLIC_URL);
    if (issuer.protocol !== "https:" || issuer.pathname !== "/" || issuer.search || issuer.hash || issuer.username || issuer.password || resource.href !== new URL("/mcp", issuer).href) throw new Error("Gateway requires an HTTPS AUTH_URL origin and MCP_PUBLIC_URL at the same origin /mcp");
  }
  return { adminPort, mcpPort, gatewayPort, gatewayBind };
}

/** Installed applications keep their data outside the replaceable program files. */
export function resolveDataDir(root: string, env: NodeJS.ProcessEnv = process.env): string {
  if (env.MCP_SSH_DATA) return resolve(env.MCP_SSH_DATA);
  const configPath = join(root, "install.json");
  if (!existsSync(configPath)) return join(root, "data");
  const config = JSON.parse(readFileSync(configPath, "utf8"));
  if (config.schemaVersion !== 1 || typeof config.dataDir !== "string" || !isAbsolute(config.dataDir)) {
    throw new Error(`Invalid installation configuration: ${configPath}`);
  }
  return config.dataDir;
}
