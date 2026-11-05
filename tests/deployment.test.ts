import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { expect, it } from 'vitest';
import { parse, parseAllDocuments } from 'yaml';
import { renderDeployment } from '../scripts/render-deployment.mjs';
const key = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
const image = 'ghcr.io/example/mcp-ssh@sha256:' + 'a'.repeat(64);
it('renders Docker and Kubernetes with the same immutable image and trusted public key', () => {
  const bundle = renderDeployment(image, key, 'https://ssh.example.org');
  const compose = parse(bundle.compose), docs = parseAllDocuments(bundle.kubernetes).map(d => d.toJSON());
  expect(compose.services.app.image).toBe(image); expect(compose.services.app.build).toBeUndefined();
  expect(compose.services.app.environment.MCP_SSH_REQUIRE_SIGNED_INTEGRITY).toBe('1');
  expect(compose.services.app.environment.MCP_SSH_INTEGRITY_PUBLIC_KEY).toBe(key);
  expect(compose.services.app.read_only).toBe(true);
  const deployment = docs.find(d => d.kind === 'Deployment'), pod = deployment.spec.template.spec;
  expect(deployment.spec.replicas).toBe(1); expect(deployment.spec.strategy.type).toBe('Recreate');
  expect(pod.automountServiceAccountToken).toBe(false);
  expect(pod.containers[0].image).toBe(image);
  expect(pod.containers[0].securityContext).toMatchObject({ readOnlyRootFilesystem: true, allowPrivilegeEscalation: false });
  expect(pod.containers[0].env).toContainEqual({ name: 'AUTH_URL', value: 'https://ssh.example.org' });
  expect(docs.find(d => d.kind === 'ConfigMap').data['public-key']).toBe(key);
  expect(docs.find(d => d.kind === 'Ingress').spec.rules[0].host).toBe('ssh.example.org');
  expect(docs.filter(d => d.kind !== 'Namespace').every(d => d.metadata.namespace === 'mcp-ssh')).toBe(true);
});
it('refuses mutable tags, untrusted key types and insecure deployment origins', () => {
  for (const ref of ['app:latest', 'ghcr.io/example/app:0.2.0', 'app@sha256:bad']) expect(() => renderDeployment(ref, key)).toThrow('digest');
  expect(() => renderDeployment(image, 'invalid')).toThrow();
  expect(() => renderDeployment(image, key, 'http://example.org')).toThrow('HTTPS');
  expect(() => renderDeployment(image, key, 'https://example.org/path')).toThrow('HTTPS');
});
it('requires signatures for the default Docker distribution and keeps development explicitly separate', () => {
  const dockerfile = readFileSync('Dockerfile', 'utf8');
  expect(dockerfile).toContain('id=integrity_key,required=true');
  expect(dockerfile).toContain('AS runtime-dev');
  expect(dockerfile.slice(dockerfile.lastIndexOf('FROM '))).toContain('MCP_SSH_REQUIRE_SIGNED_INTEGRITY=1');
});
