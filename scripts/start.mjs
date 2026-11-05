import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { verifyIntegrity, incidentPath, recordIntegrityIncident, INTEGRITY_EXIT_CODE } from './integrity.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
let valid = false;
try { valid = !existsSync(incidentPath(root)) && verifyIntegrity(root); } catch {}
if (!valid) {
  console.error('Application integrity verification failed. Reinstall from a trusted build. Do not enter passwords.');
  try { recordIntegrityIncident(root, 'startup-verification-failed-or-previous-incident'); } catch { console.error('Could not persist integrity incident. Startup is still blocked.'); }
  // No application modules or HTTP listeners are started on an integrity failure.
  process.exit(INTEGRITY_EXIT_CODE);
} else {
  await import('../dist/index.js');
}
