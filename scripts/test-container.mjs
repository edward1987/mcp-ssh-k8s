import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { request } from 'node:http';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const image = process.env.TEST_IMAGE ?? 'mcp-ssh-k8s:local';
const name = 'mcp-ssh-test-' + randomUUID(), volume = name + '-data';
const tamperName = name + '-tamper', tamperVolume = tamperName + '-data';
const fixture = mkdtempSync(join(tmpdir(), 'mcp-container-tamper-')), asset = join(fixture, 'app.js');
const docker = (...args) => {
  const r = spawnSync('docker', args, { encoding: 'utf8', timeout: 60_000, windowsHide: true });
  if (r.status !== 0) throw new Error(`docker ${args[0]} failed: ${r.stderr || r.error?.message || r.stdout}`);
  return r.stdout.trim();
};
let port;
const call = (path, options = {}) => new Promise((resolve, reject) => {
  const req = request({ hostname: '127.0.0.1', port, path, method: options.method ?? 'GET', headers: { Host: 'mcp.example.test', ...options.headers } }, res => {
    res.resume(); res.on('end', () => resolve({ status: res.statusCode }));
  });
  req.setTimeout(5000, () => req.destroy(new Error('Request timeout')));
  req.on('error', reject); req.end(options.body);
});
const ready = async () => {
  for (let n = 0; n < 60; n++) {
    try { if ((await call('/readyz')).status === 200) return; } catch {}
    await delay(500);
  }
  throw new Error('Container did not become ready');
};
try {
  docker('run', '-d', '--name', name, '--init', '--user', '1000:1000', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit', '128', '--memory', '768m', '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=64m', '--mount', `type=volume,source=${volume},target=/var/lib/mcp-ssh`, '-p', '127.0.0.1::8080', '-e', 'AUTH_URL=https://mcp.example.test', '-e', 'MCP_PUBLIC_URL=https://mcp.example.test/mcp', image);
  port = Number(docker('port', name, '8080/tcp').split(':').at(-1));
  await ready();
  const config = JSON.parse(docker('inspect', name))[0];
  assert(config.Config.Env.includes('MCP_SSH_REQUIRE_SIGNED_INTEGRITY=1'));
  assert(config.Config.Env.some(entry => entry.startsWith('MCP_SSH_INTEGRITY_PUBLIC_KEY=') && entry.length > 40));
  docker('exec', name, 'node', 'scripts/integrity.mjs', 'verify', '/app');
  docker('exec', name, 'node', '--input-type=module', '-e', `import{existsSync,writeFileSync}from'node:fs';if(process.env.MCP_SSH_INTEGRITY_SIGNING_KEY||existsSync('/run/secrets/integrity_key'))throw Error('build signing secret leaked');try{writeFileSync('/app/web/app.js','synthetic forbidden write');process.exit(1)}catch(e){if(!['EROFS','EACCES'].includes(e.code))throw e;}`);
  assert.equal(config.Config.User, '1000:1000'); assert.equal(config.HostConfig.ReadonlyRootfs, true);
  assert.deepEqual(config.HostConfig.CapDrop, ['ALL']);
  assert.equal((await call('/')).status, 200);
  assert.equal((await call('/styles.css')).status, 200);
  assert.equal((await call('/identity/login')).status, 200);
  assert.equal((await call('/api/status')).status, 401);
  assert.equal((await call('/mcp', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })).status, 401);
  assert.equal((await call('/.well-known/oauth-authorization-server')).status, 200);
  assert.equal((await call('/', { headers: { Host: 'attacker.test' } })).status, 403);
  assert.equal((await call('/', { headers: { Origin: 'http://mcp.example.test' } })).status, 403);
  assert.equal((await call('/identity/bootstrap')).status, 403);
  assert.equal((await call('/IDENTITY/BOOTSTRAP')).status, 403);
  assert.equal((await call('/identity/%62ootstrap')).status, 400);
  docker('exec', name, 'node', 'scripts/healthcheck.mjs');
  docker('exec', name, 'node', '--input-type=module', '-e', `import{spawnSync}from'node:child_process';const r=spawnSync('unzip',['-v'],{encoding:'utf8'});if(r.status!==0)throw Error('archive extractor dependencies missing');`);
  const client = JSON.parse(docker('exec', name, 'kubectl', 'version', '--client', '-o', 'json'));
  assert.match(client.clientVersion.gitVersion, /^v1\./);
  // Synthetic credentials and data only. Bootstrap runs against the trusted loopback listener.
  const bootstrap = docker('exec', name, 'node', '--input-type=module', '-e', `const r=await fetch('http://127.0.0.1:7777/identity/bootstrap',{method:'POST',redirect:'manual',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({name:'container-test',master:'container-test-only-password'})}); if(r.status!==302)throw Error('local bootstrap failed'); console.log('ok');`);
  assert.equal(bootstrap, 'ok');
  const fingerprint = () => docker('exec', name, 'node', '--input-type=module', '-e', `import{readFileSync,statSync}from'node:fs';import{createHash}from'node:crypto';const dir='/var/lib/mcp-ssh/';console.log(JSON.stringify(['vault.json','identity/identity.key'].map(p=>{const b=readFileSync(dir+p);if(b.includes('container-test-only-password'))throw Error('plaintext password');if((statSync(dir+p).mode&0o077)!==0)throw Error('unsafe permissions');return createHash('sha256').update(b).digest('hex')})));`);
  const before = fingerprint();
  docker('restart', '-t', '15', name);
  port = Number(docker('port', name, '8080/tcp').split(':').at(-1));
  await ready();
  assert.equal(fingerprint(), before);
  assert.equal((await call('/mcp', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })).status, 401);
  docker('stop', '-t', '15', name);
  assert.equal(JSON.parse(docker('inspect', name))[0].State.ExitCode, 0);
  // A persistent integrity incident must prevent recovery by automatic restart.
  docker('start', name); port = Number(docker('port', name, '8080/tcp').split(':').at(-1)); await ready();
  docker('exec', name, 'node', '--input-type=module', '-e', `import{writeFileSync}from'node:fs';writeFileSync('/var/lib/mcp-ssh/integrity-incident.json',JSON.stringify({reason:'synthetic-container-test',exitCode:78}),{mode:0o600});`);
  docker('restart', '-t', '15', name);
  for (let i = 0; i < 50 && JSON.parse(docker('inspect', name))[0].State.Running; i++) await delay(100);
  assert.equal(JSON.parse(docker('inspect', name))[0].State.ExitCode, 78);
  // A bind-mounted copy of a public asset allows a controlled host-side tamper
  // simulation without making the production filesystem writable.
  docker('cp', `${name}:/app/web/app.js`, asset);
  const original = readFileSync(asset);
  docker('run', '-d', '--name', tamperName, '--init', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit', '128', '--memory', '768m', '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=64m', '--mount', `type=volume,source=${tamperVolume},target=/var/lib/mcp-ssh`, '--mount', `type=bind,source=${asset},target=/app/web/app.js,readonly`, '-e', 'AUTH_URL=https://mcp.example.test', '-e', 'MCP_PUBLIC_URL=https://mcp.example.test/mcp', image);
  for (let i = 0; i < 60; i++) {
    const probe = spawnSync('docker', ['exec', tamperName, 'node', 'scripts/healthcheck.mjs'], { stdio: 'ignore', windowsHide: true });
    if (probe.status === 0) break;
    if (i === 59) throw new Error('Tamper fixture did not become ready');
    await delay(100);
  }
  writeFileSync(asset, Buffer.concat([original, Buffer.from('\n// synthetic integrity incident\n')]));
  for (let i = 0; i < 100 && JSON.parse(docker('inspect', tamperName))[0].State.Running; i++) await delay(100);
  assert.equal(JSON.parse(docker('inspect', tamperName))[0].State.ExitCode, 78);
  writeFileSync(asset, original);
  docker('start', tamperName);
  for (let i = 0; i < 50 && JSON.parse(docker('inspect', tamperName))[0].State.Running; i++) await delay(100);
  assert.equal(JSON.parse(docker('inspect', tamperName))[0].State.ExitCode, 78);
  console.log('Container checks passed: signed manifest, Linux, non-root/read-only, auth, health, kubectl, private persistent data, restart, SIGTERM and persistent integrity lockout.');
} catch (error) {
  try { console.error(docker('logs', '--tail', '50', name)); } catch {}
  throw error;
} finally {
  // Remove only the uniquely named test resources created above.
  spawnSync('docker', ['rm', '-f', name], { stdio: 'ignore', windowsHide: true });
  spawnSync('docker', ['volume', 'rm', volume], { stdio: 'ignore', windowsHide: true });
  spawnSync('docker', ['rm', '-f', tamperName], { stdio: 'ignore', windowsHide: true });
  spawnSync('docker', ['volume', 'rm', tamperVolume], { stdio: 'ignore', windowsHide: true });
  const target = resolve(fixture), parent = resolve(tmpdir());
  if (target.startsWith(parent + '/') || target.startsWith(parent + '\\')) rmSync(target, { recursive: true, force: true });
}
