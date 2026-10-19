import type { ImportedHost } from "./sshconfig.js";

/** Minimal RFC4180 CSV parser (quoted fields, escaped quotes, CRLF). */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [], f = "", q = false;
  const s = text.replace(/^﻿/, "");
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) {
      if (c === '"' && s[i + 1] === '"') { f += '"'; i++; }
      else if (c === '"') q = false;
      else f += c;
    } else if (c === '"') q = true;
    else if (c === ",") { row.push(f); f = ""; }
    else if (c === "\n" || c === "\r") {
      if (c === "\r" && s[i + 1] === "\n") i++;
      row.push(f); f = "";
      if (row.some((x) => x !== "")) rows.push(row);
      row = [];
    } else f += c;
  }
  row.push(f);
  if (row.some((x) => x !== "")) rows.push(row);
  return rows;
}

const ALIASES: Record<string, string[]> = {
  name: ["label", "name", "alias", "title", "host name"],
  hostname: ["hostname/ip", "hostname", "address", "host", "ip", "ip address", "hostname or ip"],
  port: ["port", "ssh port"],
  user: ["username", "user", "login"],
  password: ["password", "pass"],
  group: ["groups", "group", "folder", "parent group"],
  tags: ["tags", "tag"],
  identityFile: ["ssh key", "key", "identity file", "keys", "identity"],
};

/**
 * Termius host export (CSV). Column names vary between versions, so headers are matched by alias.
 * Private keys are not part of the export: they are attached separately in the UI.
 */
export function parseTermiusCsv(text: string): ImportedHost[] {
  const rows = parseCsv(text);
  if (rows.length < 2) return [];
  const header = rows[0].map((h) => h.trim().toLowerCase());
  const col: Record<string, number> = {};
  for (const [field, names] of Object.entries(ALIASES)) {
    const i = header.findIndex((h) => names.includes(h));
    if (i >= 0) col[field] = i;
  }
  if (col.hostname === undefined) throw new Error("could not find a hostname/address column in the CSV");
  const get = (r: string[], f: string) => (col[f] === undefined ? "" : (r[col[f]] ?? "").trim());
  return rows.slice(1).flatMap((r) => {
    const hostname = get(r, "hostname");
    if (!hostname) return [];
    return [{
      name: get(r, "name") || hostname,
      hostname,
      port: parseInt(get(r, "port"), 10) || 22,
      user: get(r, "user"),
      password: get(r, "password") || undefined,
      group: get(r, "group") || undefined,
      tags: get(r, "tags") ? get(r, "tags").split(/[;,|]/).map((t) => t.trim()).filter(Boolean) : undefined,
      identityFile: get(r, "identityFile") || undefined,
    }];
  });
}
