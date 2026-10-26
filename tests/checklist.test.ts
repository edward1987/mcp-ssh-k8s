import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { checkReadOnly } from "../src/policy/policy.js";
import { Vault } from "../src/vault/store.js";

const tmp = () => join(mkdtempSync(join(tmpdir(), "vault-checklist-")), "vault.json");

describe("checklist storage & operations", () => {
  it("initializes with empty checklist and persists items across save and unlock", async () => {
    const p = tmp();
    const v = new Vault(p);
    await v.create("correct horse battery");
    expect(v.d.checklist).toEqual([]);

    v.d.hosts.push({
      id: "h1",
      name: "srv1",
      hostname: "192.168.1.50",
      port: 22,
      user: "root",
      auth: "key",
      mode: "read-only",
      allowlist: [],
    });

    const now = new Date().toISOString();
    v.d.checklist.push({
      hostId: "h1",
      addedAt: now,
      notes: "check auth.log and nginx",
      lastStatus: "ok",
      lastSummary: "All clean",
    });

    v.save();
    v.lock();

    const v2 = new Vault(p);
    await v2.unlock("correct horse battery");
    expect(v2.d.checklist.length).toBe(1);
    expect(v2.d.checklist[0].hostId).toBe("h1");
    expect(v2.d.checklist[0].notes).toBe("check auth.log and nginx");
    expect(v2.d.checklist[0].lastStatus).toBe("ok");
  });

  it("handles older vault files missing checklist property gracefully", async () => {
    const p = tmp();
    const v = new Vault(p);
    await v.create("correct horse battery");
    // Simulate legacy vault data saved without checklist
    delete (v.d as any).checklist;
    v.save();
    v.lock();

    const v2 = new Vault(p);
    await v2.unlock("correct horse battery");
    expect(Array.isArray(v2.d.checklist)).toBe(true);
    expect(v2.d.checklist.length).toBe(0);
  });
});

describe("security check read-only allowlist", () => {
  const ok = (c: string) => checkReadOnly(c, []).ok;

  it("allows read-only audit commands", () => {
    expect(ok("uname -a")).toBe(true);
    expect(ok("uptime")).toBe(true);
    expect(ok("w")).toBe(true);
    expect(ok("last -n 5")).toBe(true);
    expect(ok("ss -tulpn")).toBe(true);
    expect(ok("systemctl list-units --failed")).toBe(true);
    expect(ok("systemctl --failed")).toBe(true);
    expect(ok("df -h")).toBe(true);
    expect(ok("free -m")).toBe(true);
    expect(ok("journalctl -u ssh -p err --no-pager -n 30")).toBe(true);
  });
});
