import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const stage = join(root, 'release/payload');
const temporary = mkdtempSync(join(tmpdir(), 'mcp-release-'));
const data = join(temporary, 'data with spaces & unicode ș');
async function freePort() {
  const server = createServer();
  await new Promise((res) => server.listen(0, '127.0.0.1', res));
  const port = server.address().port;
  await new Promise((res) => server.close(res));
  return port;
}
const adminPort = await freePort(), mcpPort = await freePort();
const serviceName = `McpSshK8sSmoke-${process.pid}`;
const url = `http://127.0.0.1:${adminPort}`;
const password = 'release smoke test password';
const elevated = spawnSync('powershell.exe', ['-NoProfile', '-Command', '[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)'], { encoding: 'utf8', windowsHide: true }).stdout.trim() === 'True';
let running = false, cookie, csrf, recoveryCodes;
const hash = (file) => createHash('sha256').update(readFileSync(file)).digest('hex');
function powershell(script, args = [], allowFailure = false) {
  const r = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', script, ...args], { encoding: 'utf8', windowsHide: true, timeout: 60000, ...(script.endsWith('launch.ps1') ? { stdio: 'ignore' } : {}) });
  if (!allowFailure) assert.equal(r.status, 0, r.stderr || r.stdout || r.error?.message);
  return r;
}
function configure(action, folder = data, enableService = 0) {
  return powershell(join(stage, 'configure.ps1'), ['-Action', action, '-InstallDir', stage, '-DataDir', folder, '-EnableService', String(enableService), '-ServiceName', serviceName, '-AdminPort', String(adminPort), '-McpPort', String(mcpPort)]);
}
async function request(path, method = 'GET', body) {
  const r = await fetch(url + path, { method, headers: { 'Content-Type': 'application/json', Connection: 'close', ...(cookie ? { Cookie: cookie } : {}), ...(csrf ? { 'X-CSRF-Token': csrf } : {}) }, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(10000) });
  assert.equal(r.status, 200, await (r.status === 200 ? Promise.resolve('') : r.text()));
  if (r.headers.has('set-cookie')) cookie = r.headers.get('set-cookie').split(';')[0];
  return r.json();
}
function start() {
  powershell(join(stage, 'launch.ps1'), ['-NoBrowser']);
  running = true;
}
function stop() {
  powershell(join(stage, 'stop.ps1'), ['-Quiet']);
  running = false;
}
try {
  assert(!existsSync(join(stage, 'data')), 'Source data must never be packaged');
  // Validate the independent production dependencies with a real SSH handshake.
  const packagedRequire = createRequire(join(stage, 'package.json'));
  const { Server } = packagedRequire('ssh2');
  const { runSsh } = await import(pathToFileURL(join(stage, 'dist/ssh/exec.js')).href);
  const hostKey = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs1', format: 'pem' });
  const server = new Server({ hostKeys: [hostKey] }, (client) => {
    client.on('authentication', (ctx) => ctx.method === 'password' && ctx.password === 'test-password' ? ctx.accept() : ctx.reject());
    client.on('ready', () => client.on('session', (accept) => accept().on('exec', (accept) => { const stream = accept(); stream.write('packaged SSH works\n'); stream.exit(0); stream.end(); })));
  });
  await new Promise((res) => server.listen(0, '127.0.0.1', res));
  try {
    const vault = { d: { settings: { maxOutputBytes: 4096 }, knownHosts: {} }, save() {} };
    const result = await runSsh(vault, { id: 'smoke', name: 'smoke', hostname: '127.0.0.1', port: server.address().port, user: 'test', auth: 'password', password: 'test-password', mode: 'free', allowlist: [] }, 'uptime', 5);
    assert.match(result.stdout, /packaged SSH works/);
  } finally { await new Promise((res) => server.close(res)); }

  configure('Configure');
  console.log('Configured temporary data folder.');
  start();
  console.log('Packaged app started.');
  assert.equal((await fetch(url + '/api/status')).status, 401);
  assert.match(await (await fetch(url)).text(), /MCP SSH/);
  const bootstrap = await fetch(url + '/identity/bootstrap', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ master: password, name: 'smoke-admin' }), redirect: 'manual' });
  assert.equal(bootstrap.status, 302);
  const activationUrl = new URL(bootstrap.headers.get('location'), url);
  const activationPage = await (await fetch(activationUrl)).text();
  const secret = /<code>([^<]+)<\/code>/.exec(activationPage)[1];
  const { TOTP, Secret } = packagedRequire('otpauth');
  const activated = await fetch(url + '/identity/activate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: activationUrl.searchParams.get('token'), password: 'account password distinct', otp: new TOTP({ secret: Secret.fromBase32(secret) }).generate() }) });
  assert.equal(activated.status, 200);
  recoveryCodes = /<pre>([^<]+)<\/pre>/.exec(await activated.text())[1].split('\n');
  async function login(code) {
    const response = await fetch(url + '/identity/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: 'smoke-admin', password: 'account password distinct', otp: code }), redirect: 'manual' });
    assert.equal(response.status, 302); cookie = response.headers.get('set-cookie').split(';')[0];
  }
  await login(recoveryCodes[0]);
  const identityCookie = cookie;
  csrf = (await request('/api/migrate', 'POST', { oldPassword: password, password })).csrf;
  cookie = identityCookie + '; ' + cookie;
  const actualDirectory = statSync((await request('/api/storage')).dataDir, { bigint: true });
  const expectedDirectory = statSync(data, { bigint: true });
  assert.deepEqual([actualDirectory.dev, actualDirectory.ino], [expectedDirectory.dev, expectedDirectory.ino]);
  assert.equal((await fetch(url + '/api/tokens', { method: 'POST', headers: { Cookie: cookie } })).status, 410);
  const vaultPath = join(data, 'vault.json');
  assert(!readFileSync(vaultPath, 'utf8').includes('account password distinct'));
  writeFileSync(join(data, 'audit.jsonl'), '{"ts":"2026-01-01","action":"smoke-test"}\n');
  stop();
  const beforeVault = hash(vaultPath), beforeAudit = hash(join(data, 'audit.jsonl'));
  configure('Prepare');
  const backups = readdirSync(join(data, 'backups'));
  assert.equal(backups.length, 1);
  assert.equal(hash(join(data, 'backups', backups[0], 'vault.json')), beforeVault);
  assert.equal(hash(join(data, 'backups', backups[0], 'audit.jsonl')), beforeAudit);
  configure('Configure');
  cookie = csrf = undefined;
  start();
  assert.equal((await fetch(url + '/api/status')).status, 401);
  await login(recoveryCodes[1]);
  const restartedIdentity = cookie;
  assert.equal((await request('/api/status')).unlocked, false);
  assert.equal(hash(vaultPath), beforeVault, 'Startup must not modify an existing vault');
  csrf = (await request('/api/unlock', 'POST', { password })).csrf;
  cookie = restartedIdentity + '; ' + cookie;
  assert.deepEqual(await request('/api/tokens'), []);
  stop();
  if (elevated) {
    try {
      configure('Configure', data, 1);
      assert.equal((await fetch(url + '/identity/me')).status, 200);
      assert.equal((await fetch(url + '/api/status')).status, 401);
      const service = spawnSync('powershell.exe', ['-NoProfile', '-Command', `Get-CimInstance Win32_Service -Filter "Name='${serviceName}'" | Select-Object State,StartMode,StartName | ConvertTo-Json`], { encoding: 'utf8', windowsHide: true });
      const info = JSON.parse(service.stdout);
      assert.equal(info.State, 'Running');
      assert.equal(info.StartMode, 'Auto');
      assert.match(info.StartName, /LocalService/i);
      configure('Prepare');
      configure('Configure', data, 0);
      start(); stop();
      console.log('Elevated service smoke passed: LocalService, automatic startup, real HTTP response, stop and switch back to manual.');
    } finally { configure('Uninstall'); }
  } else {
    console.log('Service installation test skipped: this shell is not elevated. Elevated build runners exercise the real service lifecycle.');
  }
  const invalid = powershell(join(stage, 'configure.ps1'), ['-Action', 'Prepare', '-InstallDir', stage, '-DataDir', join(stage, 'data')], true);
  assert.notEqual(invalid.status, 0, 'Data inside the replaceable app directory must be rejected');
  // Reading service status parses the WinSW config without installing a Windows service.
  const status = spawnSync(join(stage, 'mcp-ssh-service.exe'), ['status'], { encoding: 'utf8', windowsHide: true });
  assert.match(status.stdout, /NonExistent|non-existent|not installed/i, status.stderr);
  assert.match(readFileSync(join(stage, 'mcp-ssh-service.xml'), 'utf8'), /<user>LocalService<\/user>/);
  console.log('Windows release smoke passed: packaged SSH, manual launch/stop, existing vault, original master password, MFA and individual identity, backup, locked restart and WinSW config.');
} finally {
  if (running) stop();
  for (const name of ['install.json', 'mcp-ssh-service.xml', 'mcp-ssh-service.wrapper.log']) rmSync(join(stage, name), { force: true });
  // Only this mkdtemp directory is removed; never touch the real application data.
  rmSync(temporary, { recursive: true, force: true });
}
