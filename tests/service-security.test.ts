import { beforeEach, expect, it, vi } from 'vitest';
import { Approvals } from '../src/policy/policy.js';
import { runCommand, runKube, type Ctx } from '../src/service.js';
import { runSsh } from '../src/ssh/exec.js';
import { runKubectl } from '../src/k8s/kubectl.js';
vi.mock('../src/ssh/exec.js', () => ({ runSsh: vi.fn() }));
vi.mock('../src/k8s/kubectl.js', async original => ({ ...await original<typeof import('../src/k8s/kubectl.js')>(), runKubectl: vi.fn() }));
beforeEach(() => vi.clearAllMocks());
const context = (): Ctx => ({
  vault: { d: {
    hosts: [{ id: 'host', name: 'host', hostname: 'example.test', user: 'test', port: 22, auth: 'password', mode: 'approval', allowlist: [] }],
    clusters: [{ id: 'cluster', name: 'cluster', kubeconfig: 'original', mode: 'approval' }],
    settings: { approvalTimeoutSec: 5 },
  }, touch() {} } as any,
  audit: { log() {} } as any, approvals: new Approvals(),
});
it('does not execute stale SSH approvals after resource credentials or policy change', async () => {
  const ctx = context(), promise = runCommand(ctx, 'test', 'host', 'reboot');
  ctx.vault.d.hosts[0].mode = 'read-only';
  ctx.approvals.decide(ctx.approvals.list()[0].id, 'approved');
  await expect(promise).rejects.toThrow('configuration changed');
  expect(runSsh).not.toHaveBeenCalled();
});
it('does not execute stale Kubernetes approvals against a changed target', async () => {
  const ctx = context(), promise = runKube(ctx, 'test', 'cluster', 'delete pod test');
  ctx.vault.d.clusters[0].kubeconfig = 'replacement';
  ctx.approvals.decide(ctx.approvals.list()[0].id, 'approved');
  await expect(promise).rejects.toThrow('configuration changed');
  expect(runKubectl).not.toHaveBeenCalled();
});
it('rejects manifests with hidden documents beyond the approval limit before queuing or executing', async () => {
  const ctx = context();
  const manifest = 'kind: ConfigMap\n#' + ' '.repeat(20000) + '\n---\nkind: ClusterRoleBinding\n';
  await expect(runKube(ctx, 'test', 'cluster', 'apply -f -', manifest)).rejects.toThrow('approval limit');
  expect(ctx.approvals.list()).toEqual([]);
  expect(runKubectl).not.toHaveBeenCalled();
});
it('shows the exact complete manifest that is executed after approval', async () => {
  const ctx = context(), manifest = 'kind: ConfigMap\n#' + ' '.repeat(19900) + '\n# end';
  vi.mocked(runKubectl).mockResolvedValue({ stdout: '', stderr: '', exitCode: 0, truncated: false, timedOut: false });
  const promise = runKube(ctx, 'test', 'cluster', 'apply -f -', manifest);
  const pending = ctx.approvals.list()[0];
  expect(pending.command).toBe('kubectl apply -f -\n--- manifest (stdin) ---\n' + manifest);
  ctx.approvals.decide(pending.id, 'approved');
  await promise;
  expect(runKubectl).toHaveBeenCalledWith('original', expect.any(Array), expect.objectContaining({ stdin: manifest }));
});
