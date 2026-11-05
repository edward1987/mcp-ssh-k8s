import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, copyFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { afterEach, expect, it, vi } from 'vitest';
import { createManifest, verifyIntegrity } from '../scripts/integrity.mjs';
import { IntegrityMonitor } from '../src/integrity.js';
const dirs: string[] = [], children: ChildProcess[] = [];
afterEach(async () => { vi.unstubAllEnvs(); for (const child of children.splice(0)) { if (child.exitCode === null && child.signalCode === null) { const closed = new Promise<void>(r => child.once('exit', () => r())); child.kill(); await closed; } } for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
const fixture = () => {
  const dir = mkdtempSync(join(tmpdir(), 'app-integrity-')); dirs.push(dir);
  for (const name of ['dist', 'web', 'node_modules', 'scripts']) mkdirSync(join(dir, name));
  for (const name of ['start.mjs', 'integrity.mjs']) copyFileSync(resolve('scripts', name), join(dir, 'scripts', name));
  for (const name of ['package.json', 'package-lock.json']) writeFileSync(join(dir, name), '{}');
  writeFileSync(join(dir, 'dist/index.js'), 'process.stdout.write("APP_STARTED")');
  writeFileSync(join(dir, 'web/app.js'), '// original');
  writeFileSync(join(dir, 'node_modules/dependency.js'), '// original');
  writeFileSync(join(dir, 'scripts/termius_dump.py'), '# original');
  createManifest(dir); return dir;
};
it('detects modified UI, dependencies, missing files and additional executable files', () => {
  for (const path of ['web/app.js', 'node_modules/dependency.js', 'dist/index.js']) {
    const dir = fixture(); expect(verifyIntegrity(dir)).toBe(true);
    writeFileSync(join(dir, path), 'modified'); expect(verifyIntegrity(dir)).toBe(false);
  }
  const dir = fixture(); writeFileSync(join(dir, 'web/extra.js'), 'extra'); expect(verifyIntegrity(dir)).toBe(false);
  rmSync(join(dir, 'web/extra.js')); rmSync(join(dir, 'dist/index.js')); expect(verifyIntegrity(dir)).toBe(false);
});
it('does not treat test runner caches as application code', () => {
  const dir = fixture();
  for (const cache of ['.vite', '.vitest-cache']) { mkdirSync(join(dir, 'node_modules', cache)); writeFileSync(join(dir, 'node_modules', cache, 'results.json'), '{}'); }
  expect(verifyIntegrity(dir)).toBe(true);
});
it('pins the baseline in memory, locks on detection and requires restart even after file restoration', () => {
  const dir = fixture(); let locks = 0;
  const monitor = new IntegrityMonitor(dir, () => locks++);
  expect(monitor.check(true)).toBe(true);
  const original = readFileSync(join(dir, 'web/app.js'));
  writeFileSync(join(dir, 'web/app.js'), 'modified'); createManifest(dir);
  expect(monitor.check(true)).toBe(false); expect(locks).toBe(1);
  writeFileSync(join(dir, 'web/app.js'), original); createManifest(dir);
  expect(monitor.check(true)).toBe(false); expect(locks).toBe(1);
});
it('exits with code 78 before loading altered modules and persists the incident across restart', () => {
  const dir = fixture();
  const run = () => spawnSync(process.execPath, [join(dir, 'scripts/start.mjs')], { env: { ...process.env, MCP_SSH_DATA: join(dir, 'data') }, encoding: 'utf8', timeout: 5000, windowsHide: true });
  const valid = run();
  expect(valid.status).toBe(0); expect(valid.stdout).toBe('APP_STARTED');
  writeFileSync(join(dir, 'dist/index.js'), 'process.stdout.write("COMPROMISED_MODULE_EXECUTED")');
  const invalid = run();
  expect(invalid.status).toBe(78); expect(invalid.stdout).toBe(''); expect(invalid.stderr).toContain('integrity verification failed');
  expect(JSON.parse(readFileSync(join(dir, 'data/integrity-incident.json'), 'utf8')).exitCode).toBe(78);
  writeFileSync(join(dir, 'dist/index.js'), 'process.stdout.write("APP_STARTED")');
  expect(verifyIntegrity(dir)).toBe(true);
  expect(run().status).toBe(78);
});
it('detects a write-and-restore event without waiting for periodic checksum verification', async () => {
  const dir = fixture(); let detected!: () => void;
  const event = new Promise<void>(resolve => { detected = resolve; });
  const monitor = new IntegrityMonitor(dir, detected);
  try {
    monitor.start();
    const original = readFileSync(join(dir, 'web/app.js'));
    writeFileSync(join(dir, 'web/app.js'), 'modified'); writeFileSync(join(dir, 'web/app.js'), original);
    await Promise.race([event, new Promise((_, reject) => { const t = setTimeout(() => reject(new Error('No file event detected')), 2000); t.unref(); })]);
    expect(verifyIntegrity(dir)).toBe(true); expect(monitor.check()).toBe(false);
  } finally { monitor.stop(); }
});
it('terminates a running process on a file event and records a persistent incident', async () => {
  const dir = fixture(), source = pathToFileURL(resolve('src/integrity.ts')).href, helper = pathToFileURL(resolve('scripts/integrity.mjs')).href;
  const code = `import {IntegrityMonitor} from ${JSON.stringify(source)}; import {recordIntegrityIncident} from ${JSON.stringify(helper)}; const root=${JSON.stringify(dir)}; new IntegrityMonitor(root,()=>{recordIntegrityIncident(root,'test-runtime-change');process.exit(78)}).start(); console.log('READY'); setInterval(()=>{},1000);`;
  const child = spawn(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', code], { env: { ...process.env, MCP_SSH_DATA: join(dir, 'data') }, windowsHide: true }); children.push(child);
  const closed = new Promise<number | null>(resolve => child.once('exit', resolve));
  await new Promise<void>((resolve, reject) => { child.stdout.on('data', chunk => { if (String(chunk).includes('READY')) resolve(); }); child.once('error', reject); child.once('exit', () => reject(new Error('Process exited before watcher startup'))); });
  writeFileSync(join(dir, 'web/app.js'), 'altered');
  expect(await closed).toBe(78);
  expect(JSON.parse(readFileSync(join(dir, 'data/integrity-incident.json'), 'utf8')).reason).toBe('test-runtime-change');
});
it('requires an authentic signed release manifest and rejects rehashed files, forged signatures and unsigned downgrade', () => {
  const dir = fixture(), { privateKey, publicKey } = generateKeyPairSync('ed25519');
  createManifest(dir, privateKey.export({ format: 'pem', type: 'pkcs8' }).toString());
  vi.stubEnv('MCP_SSH_INTEGRITY_PUBLIC_KEY', publicKey.export({ format: 'der', type: 'spki' }).toString('base64'));
  expect(verifyIntegrity(dir)).toBe(true);
  const baseline = JSON.parse(readFileSync(join(dir, 'integrity.json'), 'utf8'));
  baseline.files['web/app.js'] = '0'.repeat(64);
  writeFileSync(join(dir, 'integrity.json'), JSON.stringify(baseline)); expect(verifyIntegrity(dir)).toBe(false);
  createManifest(dir, generateKeyPairSync('ed25519').privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()); expect(verifyIntegrity(dir)).toBe(false);
  rmSync(join(dir, 'integrity.sig')); createManifest(dir); expect(verifyIntegrity(dir)).toBe(false);
});
