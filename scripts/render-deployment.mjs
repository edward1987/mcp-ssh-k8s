import { createPublicKey } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse, parseAllDocuments, stringify } from 'yaml';

const root = fileURLToPath(new URL('../', import.meta.url));
export function renderDeployment(image, publicKey, origin = 'https://mcp.example.com') {
  if (!/^[a-z0-9][a-z0-9.:/_-]*@sha256:[a-f0-9]{64}$/.test(image)) throw new Error('Deployment requires an image pinned to a sha256 digest');
  const key = createPublicKey({ key: Buffer.from(publicKey.trim(), 'base64'), format: 'der', type: 'spki' });
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('An Ed25519 release public key is required');
  const url = new URL(origin);
  if (url.protocol !== 'https:' || url.pathname !== '/' || url.search || url.hash || url.username || url.password) throw new Error('An HTTPS origin is required');
  publicKey = key.export({ format: 'der', type: 'spki' }).toString('base64');
  const compose = parse(readFileSync(join(root, 'compose.yaml'), 'utf8'));
  compose.services.app.image = image;
  Object.assign(compose.services.app.environment, { AUTH_URL: url.origin, MCP_PUBLIC_URL: url.origin + '/mcp', MCP_SSH_INTEGRITY_PUBLIC_KEY: publicKey });
  const documents = ['namespace.yaml', 'workload.yaml', 'ingress.yaml', 'network-policy.yaml'].flatMap(file => parseAllDocuments(readFileSync(join(root, 'deploy/k8s', file), 'utf8')).map(doc => doc.toJSON()));
  documents.push({ apiVersion: 'v1', kind: 'ConfigMap', metadata: { name: 'mcp-ssh-integrity' }, data: { 'public-key': publicKey } });
  for (const doc of documents) {
    if (doc.kind !== 'Namespace') doc.metadata.namespace = 'mcp-ssh';
    if (doc.kind === 'Deployment') {
      const container = doc.spec.template.spec.containers[0]; container.image = image;
      for (const env of container.env) { if (env.name === 'AUTH_URL') env.value = url.origin; if (env.name === 'MCP_PUBLIC_URL') env.value = url.origin + '/mcp'; }
    }
    if (doc.kind === 'Ingress') { doc.spec.tls[0].hosts = [url.hostname]; doc.spec.rules[0].host = url.hostname; }
  }
  return { compose: stringify(compose), kubernetes: documents.map(doc => stringify(doc)).join('---\n'), publicKey, image };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2), value = name => args[args.indexOf(name) + 1];
  if (!args.includes('--image') || !args.includes('--build-metadata') || !args.includes('--output')) throw new Error('Use --image registry/image@sha256:digest --build-metadata build.json --output folder [--origin https://host]');
  const metadata = JSON.parse(readFileSync(value('--build-metadata'), 'utf8'));
  if (metadata.testKey) throw new Error('An ephemeral test key cannot be distributed as a release');
  const result = renderDeployment(value('--image'), metadata.publicKey, args.includes('--origin') ? value('--origin') : undefined);
  const output = resolve(value('--output')); mkdirSync(output, { recursive: true });
  writeFileSync(join(output, 'compose.yaml'), result.compose);
  writeFileSync(join(output, 'kubernetes.yaml'), result.kubernetes);
  writeFileSync(join(output, 'integrity.pub'), result.publicKey + '\n');
  writeFileSync(join(output, 'release.json'), JSON.stringify({ image: result.image, publicKey: result.publicKey, version: metadata.version, platform: metadata.platform, revision: metadata.revision }, null, 2) + '\n');
  console.log('Deployment bundle generated: ' + output);
}
