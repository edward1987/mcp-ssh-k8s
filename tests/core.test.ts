import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseSshConfig } from "../src/import/sshconfig.js";
import { parseTermiusCsv } from "../src/import/termius.js";
import { checkReadOnly } from "../src/policy/policy.js";
import { Vault } from "../src/vault/store.js";

const tmp = () => join(mkdtempSync(join(tmpdir(), "vault-")), "vault.json");

describe("vault", () => {
  it("roundtrips and never stores plaintext secrets", async () => {
    const p = tmp();
    const v = new Vault(p);
    await v.create("correct horse battery");
    v.d.keys.push({ id: "1", name: "k", privateKey: "TOP-SECRET-KEY" });
    v.save();
    expect(readFileSync(p, "utf8")).not.toContain("TOP-SECRET");
    v.lock();
    const v2 = new Vault(p);
    await expect(v2.unlock("wrong password!!")).rejects.toThrow("wrong password");
    await v2.unlock("correct horse battery");
    expect(v2.d.keys[0].privateKey).toBe("TOP-SECRET-KEY");
  });

  it("detects tampering", async () => {
    const p = tmp();
    const v = new Vault(p);
    await v.create("correct horse battery");
    const f = JSON.parse(readFileSync(p, "utf8"));
    f.ct = Buffer.from("x" + Buffer.from(f.ct, "base64").toString("latin1").slice(1), "latin1").toString("base64");
    writeFileSync(p, JSON.stringify(f));
    await expect(new Vault(p).unlock("correct horse battery")).rejects.toThrow();
  });

  it("verifies tokens by hash only", async () => {
    const v = new Vault(tmp());
    await v.create("correct horse battery");
    const { sha256 } = await import("../src/vault/store.js");
    v.d.tokens.push({ id: "t", name: "c", hash: sha256("mcp_abc"), created: "" });
    expect(v.verifyToken("mcp_abc")?.name).toBe("c");
    expect(v.verifyToken("mcp_abd")).toBeNull();
  });
});

describe("read-only policy", () => {
  const ok = (c: string) => checkReadOnly(c, []).ok;
  it("allows simple allowlisted commands", () => {
    expect(ok("ls -la /var/log")).toBe(true);
    expect(ok("systemctl status nginx")).toBe(true);
    expect(ok("docker ps -a")).toBe(true);
  });
  it("blocks bypass attempts", () => {
    for (const c of ["ls; rm -rf /", "ls && id", "ls | sh", "cat $(id)", "cat `id`", "ls\nid", "ls > /etc/x", "rm -rf /", "systemctl restart nginx", "docker run x", "find / -exec id {} ;", "lsx", "cat \\x"])
      expect(ok(c), c).toBe(false);
  });
  it("honours per-host allowlist", () => {
    expect(checkReadOnly("nginx -t", ["nginx -t"]).ok).toBe(true);
    expect(checkReadOnly("nginx -s stop", ["nginx -t"]).ok).toBe(false);
  });
});

describe("importers", () => {
  it("parses ssh config", () => {
    const h = parseSshConfig("Host *\n  User bob\nHost web\n  HostName 10.0.0.5\n  Port 2222\n  IdentityFile ~/.ssh/id_web\nHost db-*\n  User x");
    expect(h).toEqual([expect.objectContaining({ name: "web", hostname: "10.0.0.5", port: 2222, user: "bob", identityFile: "~/.ssh/id_web" })]);
  });
  it("parses termius csv with aliases and quotes", () => {
    const h = parseTermiusCsv('Groups,Label,Tags,Hostname/IP,Port,Username,Password\n"Prod, EU",web1,"a;b",1.2.3.4,22,root,"p""w"\n');
    expect(h[0]).toMatchObject({ name: "web1", hostname: "1.2.3.4", user: "root", password: 'p"w', group: "Prod, EU", tags: ["a", "b"] });
  });
});
