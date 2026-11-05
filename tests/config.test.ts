import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, expect, it } from "vitest";
import { resolveDataDir, runtimeConfig } from "../src/config.js";

const roots: string[] = [];
const root = () => { const p = mkdtempSync(join(tmpdir(), "mcp-install-")); roots.push(p); return p; };
afterEach(() => roots.splice(0).forEach((p) => rmSync(p, { recursive: true, force: true })));

it("preserves the source checkout data location", () => {
  const p = root();
  expect(resolveDataDir(p, {})).toBe(join(p, "data"));
});

it("uses an existing external vault folder after installation, with environment override", () => {
  const p = root(), dataDir = join(p, "external data");
  writeFileSync(join(p, "install.json"), JSON.stringify({ schemaVersion: 1, dataDir }));
  expect(resolveDataDir(p, {})).toBe(dataDir);
  expect(resolveDataDir(p, { MCP_SSH_DATA: "my-data" })).toBe(resolve("my-data"));
});

it("fails explicitly on broken install configuration instead of creating an empty vault", () => {
  const p = root();
  for (const config of [{ schemaVersion: 1, dataDir: "relative" }, { dataDir: p }, { schemaVersion: 1 }]) {
    writeFileSync(join(p, "install.json"), JSON.stringify(config));
    expect(() => resolveDataDir(p, {})).toThrow("Invalid installation configuration");
  }
  writeFileSync(join(p, "install.json"), "{");
  expect(() => resolveDataDir(p, {})).toThrow();
});

it('keeps workstation ports local by default and validates server configuration before startup', () => {
  expect(runtimeConfig({})).toEqual({ adminPort: 7777, mcpPort: 7778, gatewayPort: undefined, gatewayBind: '127.0.0.1' });
  const env = { GATEWAY_PORT: '8080', GATEWAY_BIND: '0.0.0.0', AUTH_URL: 'https://mcp.example.com', MCP_PUBLIC_URL: 'https://mcp.example.com/mcp' };
  expect(runtimeConfig(env).gatewayPort).toBe(8080);
  for (const extra of [{ ADMIN_PORT: '' }, { ADMIN_PORT: '0' }, { MCP_PORT: 'NaN' }, { MCP_PORT: '65536' }, { MCP_PORT: '7777' }, { GATEWAY_PORT: '7778' }, { AUTH_URL: 'http://mcp.example.com' }, { AUTH_URL: 'https://mcp.example.com/path' }, { MCP_PUBLIC_URL: 'https://other.example.com/mcp' }, { GATEWAY_BIND: 'example.com' }]) expect(() => runtimeConfig({ ...env, ...extra })).toThrow();
  expect(() => runtimeConfig({ GATEWAY_PORT: '8080' })).toThrow('requires');
});
