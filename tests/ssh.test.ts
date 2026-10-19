import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import ssh2 from "ssh2";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Audit } from "../src/audit.js";
import { Approvals } from "../src/policy/policy.js";
import { runCommand } from "../src/service.js";
import { Vault } from "../src/vault/store.js";

const { Server, utils } = ssh2;
const hostKey = utils.generateKeyPairSync("ed25519").private;
const userKey = utils.generateKeyPairSync("ed25519");

let server: InstanceType<typeof Server>;
let port: number;
let ctx: { vault: Vault; audit: Audit; approvals: Approvals };

beforeAll(async () => {
  server = new Server({ hostKeys: [hostKey] }, (client) => {
    client.on("error", () => {});
    client.on("authentication", (c) => (c.method === "publickey" ? c.accept() : c.reject()));
    client.on("ready", () =>
      client.on("session", (accept) =>
        accept().on("exec", (acceptExec, _r, info) => {
          const s = acceptExec();
          s.write(`ran: ${info.command}\n`);
          s.exit(0);
          s.end();
        }),
      ),
    );
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as AddressInfo).port;

  const dir = mkdtempSync(join(tmpdir(), "e2e-"));
  const vault = new Vault(join(dir, "vault.json"));
  await vault.create("correct horse battery");
  vault.d.keys.push({ id: "k", name: "k", privateKey: userKey.private });
  for (const mode of ["read-only", "approval", "free"] as const)
    vault.d.hosts.push({ id: mode, name: mode, hostname: "127.0.0.1", port, user: "u", auth: "key", keyId: "k", mode, allowlist: [] });
  ctx = { vault, audit: new Audit(join(dir, "audit.jsonl")), approvals: new Approvals() };
});
afterAll(() => server.close());

describe("run_command end to end", () => {
  it("runs allowlisted command on read-only host and pins host key", async () => {
    const r = await runCommand(ctx, "t", "read-only", "uptime");
    expect(r.stdout).toBe("ran: uptime\n");
    expect(r.exitCode).toBe(0);
    expect(ctx.vault.d.knownHosts["read-only"]).toMatch(/^SHA256:/);
  });
  it("blocks non-allowlisted command and audits it", async () => {
    await expect(runCommand(ctx, "t", "read-only", "rm -rf /")).rejects.toThrow(/Blocked/);
    expect(ctx.audit.tail(1)[0].outcome).toMatch(/^blocked/);
  });
  it("rejects a changed host key", async () => {
    ctx.vault.d.knownHosts["free"] = "SHA256:bogus";
    await expect(runCommand(ctx, "t", "free", "id")).rejects.toThrow();
  });
  it("waits for approval, then runs", async () => {
    const p = runCommand(ctx, "t", "approval", "whoami");
    await new Promise((r) => setTimeout(r, 100));
    const [pending] = ctx.approvals.list();
    expect(pending.command).toBe("whoami");
    ctx.approvals.decide(pending.id, "approved");
    expect((await p).stdout).toContain("whoami");
  });
  it("denied approval never connects", async () => {
    const p = runCommand(ctx, "t", "approval", "reboot");
    await new Promise((r) => setTimeout(r, 100));
    ctx.approvals.decide(ctx.approvals.list()[0].id, "denied");
    await expect(p).rejects.toThrow(/denied/);
  });
});
