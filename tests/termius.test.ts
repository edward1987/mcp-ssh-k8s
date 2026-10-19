import nacl from "tweetnacl";
import { describe, expect, it } from "vitest";
import { buildFromDump, decryptBlob, type Dump } from "../src/import/termiusLocal.js";

const key = nacl.randomBytes(32);
const enc = (text: string) => {
  const nonce = nacl.randomBytes(24);
  const box = nacl.secretbox(new TextEncoder().encode(text), nonce, key);
  return Buffer.concat([Buffer.from([4, 1]), Buffer.from(nonce), Buffer.from(box)]).toString("base64");
};
const ref = (id: number) => ({ id, local_id: 1 });

describe("termius local decrypt", () => {
  it("roundtrips, including the empty string", () => {
    expect(decryptBlob(enc("hello"), [key])).toBe("hello");
    expect(decryptBlob(enc(""), [key])).toBe("");
    expect(decryptBlob(enc("x"), [nacl.randomBytes(32)])).toBeNull();
  });
});

describe("termius model", () => {
  const dump: Dump = {
    keys: [{ id: 9, updated_at: "2024", private_key: enc("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n"), label: enc("prod key"), passphrase: enc("pp") }],
    ssh_identities: [
      { id: 1, updated_at: "2024", username: enc("root"), password: enc(""), ssh_key: ref(9) },
      { id: 2, updated_at: "2024", username: enc("bob"), password: enc("s3cret"), ssh_key: null },
    ],
    ssh_configs: [
      { id: 10, updated_at: "2024", port: 2222, identity: ref(1) },
      { id: 11, updated_at: "2024", port: 22, identity: ref(2) },
      { id: 12, updated_at: "2024", port: 22, identity: ref(2) },
    ],
    groups: [
      { id: 100, updated_at: "2024", label: enc("Prod"), parent_group: null, ssh_config: ref(11) },
      { id: 101, updated_at: "2024", label: enc("EU"), parent_group: ref(100), ssh_config: null },
    ],
    hosts: [
      { id: 1, updated_at: "2023", address: enc("old.example"), label: enc("old"), ssh_config: ref(10), group: null },
      { id: 1, updated_at: "2024", address: enc("1.2.3.4"), label: enc("web"), ssh_config: ref(10), group: null },
      { id: 2, updated_at: "2024", address: enc("5.6.7.8"), label: enc(""), ssh_config: null, group: ref(101) },
      { id: 3, updated_at: "2024", address: enc("9.9.9.9"), label: enc("gone"), ssh_config: ref(12), group: null, status: "DELETED" },
    ],
  };
  const r = buildFromDump(dump, [key]);

  it("keeps the newest version of a record and drops deleted ones", () => {
    expect(r.hosts.map((h) => h.address).sort()).toEqual(["1.2.3.4", "5.6.7.8"]);
  });
  it("resolves host -> config -> identity -> key", () => {
    const web = r.hosts.find((h) => h.name === "web")!;
    expect(web).toMatchObject({ user: "root", port: 2222, keyId: 9, password: undefined });
    expect(r.keys[0]).toMatchObject({ label: "prod key", passphrase: "pp" });
  });
  it("inherits credentials from the group chain and builds the group path", () => {
    const h = r.hosts.find((x) => x.address === "5.6.7.8")!;
    expect(h).toMatchObject({ name: "5.6.7.8", user: "bob", password: "s3cret", group: "Prod/EU" });
  });
});
