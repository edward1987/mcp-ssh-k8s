import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Local tamper detection, not remote attestation: protect this verifier and its
// baseline with OS permissions / trusted distribution outside the app's control.
const hash = file => createHash('sha256').update(readFileSync(file)).digest('hex');
export const INTEGRITY_EXIT_CODE = 78;
export function incidentPath(root) {
  let dir = process.env.MCP_SSH_DATA;
  if (!dir && existsSync(join(root, 'install.json'))) {
    const config = JSON.parse(readFileSync(join(root, 'install.json'), 'utf8'));
    if (config.schemaVersion !== 1 || typeof config.dataDir !== 'string' || !isAbsolute(config.dataDir)) throw new Error('Invalid installation configuration');
    dir = config.dataDir;
  }
  return join(resolve(dir || join(root, 'data')), 'integrity-incident.json');
}
export function recordIntegrityIncident(root, reason) {
  const path = incidentPath(root);
  mkdirSync(resolve(path, '..'), { recursive: true, mode: 0o700 });
  if (!existsSync(path)) writeFileSync(path, JSON.stringify({ timestamp: new Date().toISOString(), reason, exitCode: INTEGRITY_EXIT_CODE }) + '\n', { mode: 0o600, flag: 'wx' });
}
function inventory(root) {
  const files = [];
  const visit = relative => {
    const path = join(root, relative), stat = lstatSync(path);
    if (stat.isSymbolicLink()) throw new Error('Symlinks are not supported in protected application files');
    if (stat.isDirectory()) {
      for (const name of readdirSync(path).sort()) {
        // npm shims and the development test runner's cache are not runtime modules.
        if (relative === 'node_modules' && ['.bin', '.vite', '.vitest-cache'].includes(name)) continue;
        visit(relative + '/' + name);
      }
    } else if (stat.isFile()) files.push(relative);
    else throw new Error('Unsupported application file');
  };
  for (const relative of ['dist', 'web', 'node_modules', 'package.json', 'package-lock.json', 'scripts/start.mjs', 'scripts/integrity.mjs', 'scripts/termius_dump.py']) visit(relative);
  for (const relative of ['scripts/bootstrap.mjs', 'scripts/healthcheck.mjs', 'integrity.pub', 'runtime', 'mcp-ssh-service.exe', 'configure.ps1', 'launch.ps1', 'stop.ps1']) if (existsSync(join(root, relative))) visit(relative);
  return files;
}
export function createManifest(root, signingKey) {
  let privateKey;
  if (signingKey) {
    privateKey = createPrivateKey(signingKey);
    if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error('Integrity signing requires an Ed25519 key');
    writeFileSync(join(root, 'integrity.pub'), createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).toString('base64') + '\n');
  } else if (existsSync(join(root, 'integrity.sig'))) throw new Error('Cannot replace a signed baseline without its signing key');
  const files = Object.fromEntries(inventory(root).map(path => [path, hash(join(root, path))]));
  const baseline = JSON.stringify({ version: 1, algorithm: 'sha256', signed: !!privateKey, files }, null, 2) + '\n';
  writeFileSync(join(root, 'integrity.json'), baseline);
  if (privateKey) writeFileSync(join(root, 'integrity.sig'), sign(null, Buffer.from(baseline), privateKey).toString('base64') + '\n');
}
export function verifyIntegrity(root, baseline = readFileSync(join(root, 'integrity.json'), 'utf8')) {
  try {
    const manifest = JSON.parse(baseline);
    if (manifest.version !== 1 || manifest.algorithm !== 'sha256' || !manifest.files || Array.isArray(manifest.files)) return false;
    const publicKey = process.env.MCP_SSH_INTEGRITY_PUBLIC_KEY;
    if (manifest.signed || publicKey || process.env.MCP_SSH_REQUIRE_SIGNED_INTEGRITY === '1' || existsSync(join(root, 'integrity.sig'))) {
      // The trust anchor comes from deployment configuration, never from the manifest.
      if (!publicKey || !manifest.signed) return false;
      const key = createPublicKey({ key: Buffer.from(publicKey, 'base64'), format: 'der', type: 'spki' });
      if (key.asymmetricKeyType !== 'ed25519' || !verify(null, Buffer.from(baseline), key, Buffer.from(readFileSync(join(root, 'integrity.sig'), 'utf8').trim(), 'base64'))) return false;
    }
    const files = inventory(root);
    if (files.length !== Object.keys(manifest.files).length) return false;
    return files.every(path => /^[a-f0-9]{64}$/.test(manifest.files[path]) && hash(join(root, path)) === manifest.files[path]);
  } catch { return false; }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = resolve(process.argv[3] || join(fileURLToPath(new URL('.', import.meta.url)), '..'));
  if (process.argv[2] === 'create') {
    const signed = process.argv.includes('--signed');
    const key = signed ? process.env.MCP_SSH_INTEGRITY_SIGNING_KEY || (process.env.MCP_SSH_INTEGRITY_SIGNING_KEY_FILE ? readFileSync(process.env.MCP_SSH_INTEGRITY_SIGNING_KEY_FILE, 'utf8') : undefined) : undefined;
    if (signed && !key) throw new Error('Release signing key is missing; configure the protected CI secret MCP_SSH_INTEGRITY_SIGNING_KEY');
    createManifest(root, key);
  }
  else if (process.argv[2] === 'verify') { if (!verifyIntegrity(root)) { console.error('Application integrity verification failed. Do not enter passwords.'); process.exitCode = 1; } }
  else throw new Error('Use integrity.mjs create|verify [application-root]');
}
