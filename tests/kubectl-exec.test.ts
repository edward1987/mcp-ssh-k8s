import { existsSync, readdirSync } from 'node:fs';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { expect, it, vi } from 'vitest';
import { runKubectl, stopKubectlExecutions } from '../src/k8s/kubectl.js';
vi.mock('node:child_process', async original => ({ ...await original<typeof import('node:child_process')>(), spawn: vi.fn(() => { throw new Error('process creation rejected'); }) }));
it('removes temporary plaintext credentials even when process creation throws synchronously', async () => {
  const config = 'clusters: [{name: c, cluster: {server: "https://cluster.example"}}]\ncontexts: [{name: c, context: {cluster: c, user: u}}]\nusers: [{name: u, user: {token: synthetic-test-token}}]';
  const snapshot = () => readdirSync(tmpdir()).filter(name => name.startsWith('mcp-k8s-')).sort();
  const before = snapshot();
  await expect(runKubectl(config, ['get', 'pods'], { timeoutSec: 1, maxBytes: 1024 })).rejects.toThrow('process creation rejected');
  expect(snapshot()).toEqual(before);
});
it('kills active kubectl processes and removes their temporary credentials during an integrity incident', async () => {
  const config = 'clusters: [{name: c, cluster: {server: "https://cluster.example"}}]\ncontexts: [{name: c, context: {cluster: c, user: u}}]\nusers: [{name: u, user: {token: synthetic-test-token}}]';
  const child = Object.assign(new EventEmitter(), { stdout: new PassThrough(), stderr: new PassThrough(), kill: vi.fn(() => { queueMicrotask(() => child.emit('close', null)); return true; }) });
  let path = '';
  vi.mocked(spawn).mockImplementationOnce(((_exe: unknown, _args: unknown, options: any) => { path = options.env.KUBECONFIG; return child; }) as any);
  const pending = runKubectl(config, ['get', 'pods'], { timeoutSec: 10, maxBytes: 1024 });
  expect(existsSync(path)).toBe(true);
  stopKubectlExecutions();
  expect(child.kill).toHaveBeenCalledWith('SIGKILL'); expect(existsSync(path)).toBe(false);
  await pending;
});
