import { spawnSync } from 'node:child_process';
import { mkdtempSync, existsSync, unlinkSync, rmdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';

const cluster = 'mcp-ssh-test-' + randomUUID().slice(0, 8), node = cluster + '-control-plane';
const temp = mkdtempSync(join(tmpdir(), 'mcp-ssh-kind-')), kubeconfig = join(temp, 'config');
const image = process.env.TEST_IMAGE ?? 'mcp-ssh-k8s:local';
const run = (program, args, input, timeout = 120_000) => {
  const result = spawnSync(program, args, { encoding: 'utf8', input, timeout, windowsHide: true, maxBuffer: 4 * 1024 * 1024 });
  if (result.status !== 0) throw new Error(`${program} ${args[0]} failed: ${result.stderr || result.error?.message || result.stdout}`);
  return result.stdout.trim();
};
const docker = (...args) => run('docker', args);
const kubectl = (...args) => docker('exec', node, 'kubectl', '-n', 'mcp-ssh', ...args);
const exec = code => kubectl('exec', 'deployment/mcp-ssh', '--', 'node', '--input-type=module', '-e', code);
const fingerprint = () => exec(`import{readFileSync}from'node:fs';import{createHash}from'node:crypto';console.log(createHash('sha256').update(readFileSync('/var/lib/mcp-ssh/identity/identity.key')).digest('hex'));`);
try {
  console.log('Creating isolated kind cluster ' + cluster);
  run(process.env.KIND_PATH ?? 'kind', ['create', 'cluster', '--name', cluster, '--kubeconfig', kubeconfig, '--wait', '60s']);
  run(process.env.KIND_PATH ?? 'kind', ['load', 'docker-image', image, '--name', cluster]);
  const manifests = docker('run', '--rm', '--entrypoint', 'kubectl', '--mount', `type=bind,source=${resolve('deploy/k8s')},target=/manifests,readonly`, image, 'kustomize', '/manifests');
  run('docker', ['exec', '-i', node, 'kubectl', 'apply', '-f', '-'], manifests);
  const imageConfig = JSON.parse(docker('image', 'inspect', image))[0];
  const publicKey = imageConfig.Config.Env.find(entry => entry.startsWith('MCP_SSH_INTEGRITY_PUBLIC_KEY='))?.split('=').slice(1).join('=');
  assert(publicKey, 'A signed test image is required');
  kubectl('patch', 'configmap', 'mcp-ssh-integrity', '--type=merge', '-p', JSON.stringify({ data: { 'public-key': publicKey } }));
  kubectl('set', 'image', 'deployment/mcp-ssh', `app=${image}`);
  kubectl('rollout', 'status', 'deployment/mcp-ssh', '--timeout=90s');
  const pod = JSON.parse(kubectl('get', 'pods', '-l', 'app=mcp-ssh', '-o', 'json')).items[0];
  assert.equal(pod.spec.automountServiceAccountToken, false);
  assert.equal(pod.spec.securityContext.runAsNonRoot, true);
  assert.equal(pod.spec.containers[0].securityContext.readOnlyRootFilesystem, true);
  assert.equal(JSON.parse(kubectl('get', 'pvc', 'mcp-ssh-data', '-o', 'json')).status.phase, 'Bound');
  kubectl('exec', 'deployment/mcp-ssh', '--', 'node', 'scripts/healthcheck.mjs');
  kubectl('exec', 'deployment/mcp-ssh', '--', 'node', 'scripts/integrity.mjs', 'verify', '/app');
  // The example denies real destinations. Permit only this disposable API server for the test.
  const policy = JSON.parse(kubectl('get', 'networkpolicy', 'mcp-ssh', '-o', 'json'));
  const nodeInfo = JSON.parse(docker('exec', node, 'kubectl', 'get', 'node', node, '-o', 'json'));
  const nodeIp = nodeInfo.status.addresses.find(address => address.type === 'InternalIP').address;
  const apiIp = JSON.parse(docker('exec', node, 'kubectl', 'get', 'service', 'kubernetes', '-o', 'json')).spec.clusterIP;
  policy.spec.egress.push({ to: [nodeIp, apiIp].map(ip => ({ ipBlock: { cidr: ip + '/32' } })), ports: [{ protocol: 'TCP', port: 443 }, { protocol: 'TCP', port: 6443 }] });
  kubectl('patch', 'networkpolicy', 'mcp-ssh', '--type=merge', '-p', JSON.stringify({ spec: { egress: policy.spec.egress } }));
  // Credentials belong only to this temporary cluster and travel through stdin, never argv/logs.
  const config = docker('exec', node, 'kubectl', 'config', 'view', '--kubeconfig=/etc/kubernetes/admin.conf', '--raw', '--flatten');
  run('docker', ['exec', '-i', node, 'kubectl', '-n', 'mcp-ssh', 'exec', '-i', 'deployment/mcp-ssh', '--', 'node', '--input-type=module', '-e', `import{readFileSync,readdirSync}from'node:fs';import{parse,stringify}from'yaml';import{runKubectl}from'./dist/k8s/kubectl.js';const cfg=parse(readFileSync(0,'utf8'));cfg.clusters[0].cluster.server='https://kubernetes.default.svc';const before=readdirSync('/tmp').filter(n=>n.startsWith('mcp-k8s-'));const r=await runKubectl(stringify(cfg),['get','namespace','mcp-ssh','-o','jsonpath={.metadata.name}','--request-timeout=5s'],{timeoutSec:10,maxBytes:4096});if(r.exitCode!==0||r.stdout!=='mcp-ssh')throw Error('Temporary-cluster kubectl API test failed: '+r.stderr.slice(0,2000));if(JSON.stringify(before)!==JSON.stringify(readdirSync('/tmp').filter(n=>n.startsWith('mcp-k8s-'))))throw Error('Temporary kubeconfig not removed');`], config);
  exec(`const r=await fetch('http://127.0.0.1:7777/identity/bootstrap',{method:'POST',redirect:'manual',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({name:'kind-test',master:'isolated-kind-test-password'})});if(r.status!==302)throw Error('bootstrap failed');`);
  const before = fingerprint();
  kubectl('rollout', 'restart', 'deployment/mcp-ssh');
  kubectl('rollout', 'status', 'deployment/mcp-ssh', '--timeout=90s');
  assert.equal(fingerprint(), before);
  kubectl('exec', 'deployment/mcp-ssh', '--', 'node', 'scripts/healthcheck.mjs');
  exec(`import{writeFileSync}from'node:fs';writeFileSync('/var/lib/mcp-ssh/integrity-incident.json',JSON.stringify({reason:'synthetic-kind-incident',exitCode:78}),{mode:0o600});`);
  const oldUid = JSON.parse(kubectl('get', 'pods', '-l', 'app=mcp-ssh', '-o', 'json')).items[0].metadata.uid;
  kubectl('rollout', 'restart', 'deployment/mcp-ssh');
  let blocked = false;
  for (let i = 0; i < 60; i++) {
    const pods = JSON.parse(kubectl('get', 'pods', '-l', 'app=mcp-ssh', '-o', 'json')).items;
    blocked = pods.some(p => p.metadata.uid !== oldUid && p.status.containerStatuses?.some(s => !s.ready && (s.lastState?.terminated?.exitCode === 78 || s.state?.terminated?.exitCode === 78)));
    if (blocked) break;
    await delay(1000);
  }
  assert(blocked, 'A persistent integrity incident must refuse pod replacement with exit code 78');
  console.log('Kubernetes checks passed: signed image, restricted Pod Security, readiness, non-root/read-only, real kubectl API call and cleanup, PVC persistence and integrity lockout after pod replacement.');
  console.log('TLS ingress and enforcement of NetworkPolicy require tests with the deployment controller and CNI.');
} catch (error) {
  try { console.error(kubectl('get', 'pods')); console.error(kubectl('logs', 'deployment/mcp-ssh', '--tail=30')); } catch {}
  throw error;
} finally {
  // No user's kubeconfig/context is read or changed; remove only this unique cluster and its config.
  const result = spawnSync(process.env.KIND_PATH ?? 'kind', ['delete', 'cluster', '--name', cluster], { encoding: 'utf8', windowsHide: true, timeout: 60_000 });
  if (result.status !== 0) console.error('Could not delete test cluster ' + cluster);
  if (existsSync(kubeconfig)) unlinkSync(kubeconfig);
  rmdirSync(temp);
}
