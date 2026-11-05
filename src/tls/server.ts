import { createServer, type Server } from 'node:https';
import { gatewayHandler } from '../gateway.js';
import type { CloudflareTls } from './cloudflare.js';

/** Bind only to the configured private address. VPN/firewall routing is managed externally. */
export function privateHttps(tls: CloudflareTls, authOrigin: string, adminPort: number, mcpPort: number) {
  let server: Server | undefined;
  const load = () => {
    const certificate = tls.certificate(), config = tls.config(); if (!certificate || !config) return;
    const origin = `https://${config.hostname}${config.port === 443 ? '' : ':' + config.port}`;
    if (origin !== authOrigin) { tls.lastError = 'Certificate ready. Restart application to activate the configured HTTPS origin.'; return; }
    if (server) { server.setSecureContext(certificate); return; }
    server = createServer(certificate, gatewayHandler(origin, adminPort, mcpPort));
    server.on('error', () => { tls.lastError = 'HTTPS listener failed. Check private interface and port permissions.'; server = undefined; });
    server.listen(config.port, config.privateIp);
  };
  tls.onCertificate = load; load(); return () => server?.close();
}
