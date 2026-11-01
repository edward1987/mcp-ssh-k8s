import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, expect, it } from "vitest";
import { resolveDataDir } from "../src/config.js";

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
