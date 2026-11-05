// Calls the running application's loopback endpoint; never edits SQLite or accepts secrets in argv.
import { createInterface } from 'node:readline/promises';
import { Writable } from 'node:stream';
if (!process.stdin.isTTY || !process.stdout.isTTY) throw new Error('Run in an interactive terminal (-it for Docker/kubectl)');
let muted = false;
const output = new Writable({ write(chunk, _encoding, callback) { if (!muted) process.stdout.write(chunk); callback(); } });
const rl = createInterface({ input: process.stdin, output, terminal: true });
try {
  const name = await rl.question('Administrator name: ');
  process.stdout.write('Master password (existing vault, or at least 12 characters for a new vault): ');
  muted = true;
  const master = await rl.question('');
  muted = false; process.stdout.write('\n');
  const response = await fetch(`http://127.0.0.1:${process.env.ADMIN_PORT ?? 7777}/identity/bootstrap`, {
    method: 'POST', redirect: 'manual', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ name, master }), signal: AbortSignal.timeout(30_000),
  });
  const location = response.headers.get('location');
  if (response.status !== 302 || !location?.startsWith('/identity/activate?token=')) throw new Error('Bootstrap rejected. Check password and whether an administrator already exists.');
  const origin = process.env.AUTH_URL ?? `http://127.0.0.1:${process.env.ADMIN_PORT ?? 7777}`;
  console.log('Open this single-use invitation in your browser, set the account password and enable MFA:');
  console.log(new URL(location, origin).href);
} finally { muted = false; rl.close(); }
