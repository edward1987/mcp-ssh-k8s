import { beforeEach, expect, it, vi } from 'vitest';
import { runHostSecurityAudit } from '../src/security.js';
import { runSsh } from '../src/ssh/exec.js';
import type { Ctx } from '../src/service.js';
vi.mock('../src/ssh/exec.js', () => ({ runSsh: vi.fn() }));
beforeEach(() => vi.clearAllMocks());
const context = (): Ctx => ({ vault: { d: { hosts: [{ id: 'host', name: 'host', mode: 'read-only' }], checklist: [{ hostId: 'host' }] }, touch() {}, save() {} } as any, audit: { log: vi.fn() } as any, approvals: {} as any });
it('persists a warning when every SSH check fails instead of reporting OK', async () => {
  const ctx = context();
  vi.mocked(runSsh).mockRejectedValue(new Error('connection refused'));
  const result = await runHostSecurityAudit(ctx, 'test', 'host');
  expect(result.status).toBe('warning'); expect(result.complete).toBe(false);
  expect(result.checks.every(c => !c.ok)).toBe(true);
  expect(result.summary).toContain('incomplete');
  expect(ctx.vault.d.checklist[0].lastStatus).toBe('warning');
  expect(result.report).not.toContain('Toate verificările de bază au trecut');
});
it('does not treat nonzero exits, permission-limited logs, timeouts or truncated output as successful checks', async () => {
  for (const overrides of [{ exitCode: 127 }, { stderr: 'Permission denied' }, { stderr: 'You are currently not seeing messages from other users' }, { timedOut: true }, { truncated: true }]) {
    vi.mocked(runSsh).mockResolvedValue({ stdout: '', stderr: '', exitCode: 0, truncated: false, timedOut: false, ...overrides });
    const result = await runHostSecurityAudit(context(), 'test', 'host', 'system');
    expect(result.complete).toBe(false); expect(result.status).toBe('warning');
  }
});
it('reports completed checks and ordinary grep no-match results without a false failure', async () => {
  vi.mocked(runSsh).mockImplementation(async (_vault, _host, command) => ({ stdout: command.startsWith('journalctl') ? '-- No entries --' : '', stderr: '', exitCode: command.startsWith('grep') ? 1 : 0, truncated: false, timedOut: false }));
  const result = await runHostSecurityAudit(context(), 'test', 'host', 'auth');
  expect(result.complete).toBe(true); expect(result.status).toBe('ok');
  expect(result.checks.at(-1)).toMatchObject({ exitCode: 1, ok: true });
});
