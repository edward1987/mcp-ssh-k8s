import { existsSync, readFileSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";

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
