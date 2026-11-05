import { mkdtempSync, rmSync, readFileSync, statSync, appendFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { Audit, redactAudit } from '../src/audit.js';
const dirs: string[] = [];
afterEach(() => dirs.splice(0).forEach(dir => rmSync(dir, { recursive: true, force: true })));
it('redacts common command credentials and writes a private audit file on Linux', () => {
  const dir = mkdtempSync(join(tmpdir(), 'audit-test-')); dirs.push(dir);
  const path = join(dir, 'audit.jsonl'), audit = new Audit(path);
  audit.log({ client: 'test', host: 'test', action: 'run', command: 'curl --token=TOPSECRET --password "PRIVATE VALUE" https://user:URLSECRET@example.com', outcome: 'Bearer TOKENVALUE' });
  const disk = readFileSync(path, 'utf8');
  for (const secret of ['TOPSECRET', 'PRIVATE VALUE', 'URLSECRET', 'TOKENVALUE']) expect(disk).not.toContain(secret);
  expect(audit.tail()[0].command).toContain('[REDACTED]');
  if (process.platform !== 'win32') expect(statSync(path).mode & 0o777).toBe(0o600);
  expect(redactAudit('-----BEGIN OPENSSH PRIVATE KEY-----\nSECRET\n-----END OPENSSH PRIVATE KEY-----')).toBe('[REDACTED KEY]');
});
it('reads a bounded suffix of a large log and skips a partial first record', () => {
  const dir = mkdtempSync(join(tmpdir(), 'audit-test-')); dirs.push(dir);
  const path = join(dir, 'audit.jsonl'), audit = new Audit(path);
  appendFileSync(path, JSON.stringify({ padding: 'x'.repeat(5 * 1024 * 1024) }) + '\n');
  for (let n = 0; n < 3; n++) audit.log({ client: 'test', host: 'test', action: String(n), outcome: 'ok' });
  expect(audit.tail(2).map(e => e.action)).toEqual(['2', '1']);
});
