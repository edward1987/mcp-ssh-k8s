import { chmodSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
/** Fail closed if credentials cannot be restricted to the running OS identity. */
export function protectCredentials(path: string, directory = false) {
  if (process.platform !== 'win32') { chmodSync(path, directory ? 0o700 : 0o600); return; }
  const sid = execFileSync('whoami.exe', ['/user', '/fo', 'csv', '/nh'], { encoding: 'utf8', windowsHide: true }).match(/S-1-5-[\d-]+/)?.[0];
  if (!sid) throw new Error('Cannot determine credential owner');
  const inheritance = directory ? '(OI)(CI)' : '';
  execFileSync('icacls.exe', [path, '/inheritance:r', '/grant:r', `*${sid}:${inheritance}F`, `*S-1-5-18:${inheritance}F`, `*S-1-5-32-544:${inheritance}F`], { windowsHide: true, stdio: 'pipe' });
}
