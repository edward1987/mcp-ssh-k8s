import { spawnSync } from 'node:child_process';
import { createPrivateKey, createPublicKey, generateKeyPairSync } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const args = process.argv.slice(2);
const value = name => { const index = args.indexOf(name); if (index < 0) return undefined; if (!args[index + 1] || args[index + 1].startsWith('--')) throw new Error(`Missing ${name}`); return args[index + 1]; };
const tag = value('--tag') || 'mcp-ssh-k8s:local';
const platform = value('--platform') || 'linux/amd64';
if (!['linux/amd64', 'linux/arm64'].includes(platform)) throw new Error('Build and load one Linux architecture at a time');
const testKey = args.includes('--test-key');
const signingKey = testKey ? generateKeyPairSync('ed25519').privateKey : process.env.MCP_SSH_INTEGRITY_SIGNING_KEY ? createPrivateKey(process.env.MCP_SSH_INTEGRITY_SIGNING_KEY) : undefined;
if (!signingKey || signingKey.asymmetricKeyType !== 'ed25519') throw new Error('An Ed25519 CI signing key is required. For isolated tests only, pass --test-key.');
const publicKey = createPublicKey(signingKey).export({ format: 'der', type: 'spki' }).toString('base64');
const version = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8')).version;
const build = spawnSync('docker', ['buildx', 'build', '--load', '--platform', platform, '--target', 'runtime', '--tag', tag, '--secret', 'id=integrity_key,env=MCP_SSH_INTEGRITY_SIGNING_KEY', '--build-arg', `INTEGRITY_PUBLIC_KEY=${publicKey}`, '--build-arg', `APP_VERSION=${version}`, '--build-arg', `VCS_REF=${process.env.GITHUB_SHA || 'local'}`, '--build-arg', `SOURCE_URL=${process.env.GITHUB_REPOSITORY ? 'https://github.com/' + process.env.GITHUB_REPOSITORY : ''}`, root], {
  stdio: 'inherit', windowsHide: true,
  env: { ...process.env, MCP_SSH_INTEGRITY_SIGNING_KEY: signingKey.export({ format: 'pem', type: 'pkcs8' }).toString() },
});
if (build.status !== 0) throw new Error(`Signed container build failed (${build.status ?? build.error?.message})`);
const output = value('--output');
if (output) {
  const path = resolve(output); mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify({ image: tag, platform, version, publicKey, testKey, revision: process.env.GITHUB_SHA || 'local' }, null, 2) + '\n');
}
console.log(`Signed image loaded: ${tag} (${platform}; ${testKey ? 'ephemeral test key, never publish' : 'release signing key'})`);
