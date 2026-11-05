import { createServer, request, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, expect, it } from 'vitest';
import { gatewayHandler } from '../src/gateway.js';

const servers: Server[] = [];
const listen = async (server: Server) => { servers.push(server); await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve)); return (server.address() as AddressInfo).port; };
afterEach(async () => { for (const server of servers.splice(0)) { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); } });
const call = (port: number, path: string, headers: Record<string, string> = {}) => new Promise<{ status: number; body: string }>((resolve, reject) => {
  const req = request({ hostname: '127.0.0.1', port, path, headers: { Host: 'mcp.example.com', ...headers } }, res => {
    let body = ''; res.on('data', chunk => body += chunk); res.on('end', () => resolve({ status: res.statusCode!, body }));
  }); req.on('error', reject); req.end();
});

it('routes UI/OAuth/MCP and strips spoofed proxy headers without losing Authorization or cookies', async () => {
  const upstream = (label: string) => createServer((req, res) => res.end(JSON.stringify({ label, headers: req.headers })));
  const admin = await listen(upstream('admin')), mcp = await listen(upstream('mcp'));
  const gateway = await listen(createServer(gatewayHandler('https://mcp.example.com', admin, mcp)));
  for (const [path, label] of [['/', 'admin'], ['/identity/login', 'admin'], ['/mcp', 'mcp'], ['/register', 'mcp'], ['/authorize/', 'mcp'], ['/token', 'mcp'], ['/.well-known/oauth-authorization-server', 'mcp']]) {
    const r = await call(gateway, path, { Origin: 'https://mcp.example.com', Authorization: 'Bearer test-only', Cookie: 'identity=test-only', Forwarded: 'for=evil', 'X-Forwarded-For': '8.8.8.8', 'X-Forwarded-Proto': 'http', 'X-Mcp-Private-Gateway': 'spoof' });
    expect(r.status).toBe(200);
    const response = JSON.parse(r.body); expect(response.label).toBe(label);
    expect(response.headers.authorization).toBe('Bearer test-only'); expect(response.headers.cookie).toBe('identity=test-only');
    expect(response.headers['x-mcp-private-gateway']).toBe('1');
    expect(response.headers.forwarded).toBeUndefined(); expect(response.headers['x-forwarded-for']).toBeUndefined(); expect(response.headers['x-forwarded-proto']).toBeUndefined();
  }
});
it('blocks rebinding, downgrade origins and bootstrap normalization/encoding bypasses before forwarding', async () => {
  let hits = 0;
  const admin = await listen(createServer((_req, res) => { hits++; res.end('unexpected'); }));
  const port = await listen(createServer(gatewayHandler('https://mcp.example.com', admin, admin)));
  expect((await call(port, '/', { Host: 'evil.example' })).status).toBe(403);
  expect((await call(port, '/', { Origin: 'http://mcp.example.com' })).status).toBe(403);
  expect((await call(port, '/', { Origin: 'https://evil.example' })).status).toBe(403);
  for (const path of ['/identity/bootstrap', '/identity/bootstrap/', '/IDENTITY/BOOTSTRAP', '/identity/bootstrap/extra']) expect((await call(port, path)).status, path).toBe(403);
  for (const path of ['/identity/%62ootstrap', '/identity%2fbootstrap', '//identity/bootstrap', '/a/../identity/bootstrap', '/identity\\bootstrap', '/%2e%2e/identity/bootstrap']) expect((await call(port, path)).status, path).toBe(400);
  expect(hits).toBe(0);
});
it('reports process health independently of vault lock and readiness during shutdown', async () => {
  let ready = true;
  const port = await listen(createServer(gatewayHandler('https://mcp.example.com', 1, 2, () => ready)));
  expect((await call(port, '/readyz', { Host: 'probe' })).status).toBe(200);
  ready = false;
  expect((await call(port, '/healthz')).status).toBe(200);
  expect((await call(port, '/readyz')).status).toBe(503);
  expect((await call(port, '/')).status).toBe(503);
});
