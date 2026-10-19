export interface ImportedHost {
  name: string;
  hostname: string;
  port: number;
  user: string;
  identityFile?: string;
  password?: string;
  group?: string;
  tags?: string[];
  note?: string;
}

/** Parse OpenSSH client config. Wildcard Host entries are skipped; `Host *` values are used as defaults. */
export function parseSshConfig(text: string): ImportedHost[] {
  type Block = { patterns: string[]; opts: Record<string, string> };
  const blocks: Block[] = [];
  let cur: Block = { patterns: ["*"], opts: {} };
  blocks.push(cur);
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, "").trim();
    if (!line) continue;
    const m = /^(\S+?)(?:\s*=\s*|\s+)(.+)$/.exec(line);
    if (!m) continue;
    const key = m[1].toLowerCase();
    const val = m[2].trim().replace(/^"(.*)"$/, "$1");
    if (key === "host") {
      cur = { patterns: val.split(/\s+/), opts: {} };
      blocks.push(cur);
    } else if (!(key in cur.opts)) {
      cur.opts[key] = val;
    }
  }
  const defaults = blocks.filter((b) => b.patterns.includes("*")).reduce((a, b) => ({ ...b.opts, ...a }), {} as Record<string, string>);
  const out: ImportedHost[] = [];
  for (const b of blocks) {
    for (const p of b.patterns) {
      if (/[*?!]/.test(p)) continue;
      const o = { ...defaults, ...b.opts };
      out.push({
        name: p,
        hostname: o["hostname"] ?? p,
        port: parseInt(o["port"] ?? "22", 10) || 22,
        user: o["user"] ?? "",
        identityFile: o["identityfile"],
        note: o["proxyjump"] ? `ProxyJump ${o["proxyjump"]} (not supported yet)` : undefined,
      });
    }
  }
  return out;
}
