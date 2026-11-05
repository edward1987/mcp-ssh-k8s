import { CloudflareTls } from "./tls/cloudflare.js";
import { privateHttps } from "./tls/server.js";
import { VaultRegistry } from "./vault/registry.js";
import { ShareBroker } from "./vault/shares.js";
import { IdentityStore } from "./auth/store.js";
import { OAuthProvider } from "./auth/oauth.js";
import { canonicalUrl } from "./auth/web.js";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { startAdmin } from "./admin/server.js";
import { Audit } from "./audit.js";
import { resolveDataDir, runtimeConfig } from "./config.js";
import { startGateway } from "./gateway.js";
import { existsSync, mkdirSync } from "node:fs";
import { startMcp } from "./mcp/server.js";
import { Approvals } from "./policy/policy.js";
import { TunnelManager } from "./tunnel/manager.js";
import { WebTunnelManager } from "./tunnel/web.js";
import { Vault } from "./vault/store.js";
import { IntegrityMonitor } from './integrity.js';
import { INTEGRITY_EXIT_CODE, incidentPath, recordIntegrityIncident } from '../scripts/integrity.mjs';
import { stopKubectlExecutions } from './k8s/kubectl.js';

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
if (existsSync(incidentPath(root))) { console.error('An integrity incident is recorded. Startup blocked until operator recovery.'); process.exit(INTEGRITY_EXIT_CODE); }
process.umask(0o077);
const config = runtimeConfig();
const dataDir = resolveDataDir(root);
mkdirSync(dataDir, { recursive: true, mode: 0o700 });
console.log(`Data folder   ${dataDir}`);

const vault = new Vault(join(dataDir, "vault.json"));
const identities = new IdentityStore(dataDir);
const tls = new CloudflareTls(identities);
const registry = new VaultRegistry(dataDir, identities);
const ctx = {
  tls,
  registry,
  shares: new ShareBroker(identities, registry),
  identities,
  vault: registry.facade(),
  audit: new Audit(join(dataDir, "audit.jsonl"), true),
  approvals: new Approvals(),
  integrity: new IntegrityMonitor(root, () => {
    console.error('CRITICAL: application integrity changed. Stopping immediately (exit 78). Do not enter passwords.');
    try { recordIntegrityIncident(root, 'runtime-file-change-or-verification-failure'); } catch { console.error('Could not persist integrity incident.'); }
    try { stopKubectlExecutions(); registry.lockAll(); } finally { process.exit(INTEGRITY_EXIT_CODE); }
  }),

};
if (!ctx.integrity.check(true)) throw new Error('Application integrity verification failed');
ctx.integrity.start();

const { mcpPort, adminPort } = config;
const privateTls = tls.status();
const publicOrigin = identities.get<{ origin: string }>('runtime', 'web-tunnel')?.origin;
const authUrl = process.env.AUTH_URL ?? publicOrigin ?? privateTls.url ?? `http://127.0.0.1:${mcpPort}`;
const oauth = new OAuthProvider(ctx.identities, canonicalUrl(authUrl), canonicalUrl(process.env.MCP_PUBLIC_URL ?? (publicOrigin ? new URL('/mcp', authUrl).href : `http://127.0.0.1:${mcpPort}/mcp`)));
const tunnel = new TunnelManager(vault, dataDir, mcpPort, identities, oauth.issuer.origin);
const webTunnel = new WebTunnelManager(identities, dataDir, oauth.issuer.origin, mcpPort, oauth.resource.href, origin => oauth.setPublicOrigin(origin));

const admin = startAdmin(ctx, adminPort, join(root, "web"), tunnel, {
  dataDir, scriptsDir: join(root, "scripts"), mcpPort, bridgePath: join(root, "dist", "mcp", "stdio.js"), oauth, webTunnel,
});
const mcp = startMcp(ctx, mcpPort, "127.0.0.1", oauth, { adminPort });
let stopping = false;
const gateway = config.gatewayPort ? startGateway(oauth.issuer.origin, adminPort, mcpPort, config.gatewayPort, config.gatewayBind, () => !stopping && admin.listening && mcp.listening) : undefined;
tunnel.autoStart();
webTunnel.autoStart();
const closeHttps = privateHttps(tls, oauth.issuer.origin, adminPort, mcpPort);
const renewal = tls.startRenewal();

for (const sig of ["SIGINT", "SIGTERM"] as const)
  process.on(sig, () => {
    if (stopping) return;
    stopping = true;
    ctx.integrity.stop();
    clearInterval(renewal);
    ctx.approvals.denyAll();
    registry.lockAll();
    tunnel.stop();
    webTunnel.stop();
    closeHttps();
    const deadline = setTimeout(() => process.exit(0), 10_000);
    deadline.unref();
    const servers = [gateway, admin, mcp].filter(s => s !== undefined);
    let remaining = servers.length;
    for (const server of servers) server.close(() => { if (--remaining === 0) { identities.db.close(); process.exit(0); } });
  });
process.on("exit", () => { tunnel.stop(); webTunnel.stop(); });
