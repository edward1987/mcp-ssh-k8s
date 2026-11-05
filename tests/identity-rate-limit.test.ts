import { createServer, request, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import express from 'express';
import { afterEach, expect, it, vi } from 'vitest';
import { identityRouter } from '../src/auth/web.js';
import { gatewayHandler } from '../src/gateway.js';
const servers: Server[] = [];
afterEach(async () => { for (const server of servers.splice(0)) { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); } });
const listen = async (server: Server) => { servers.push(server); await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve)); return (server.address() as AddressInfo).port; };
it('isolates identity budgets by account and invitation through the same gateway without trusting forwarded IPs', async () => {
  const records = new Map<string, any>();
  const store = { get: (kind: string, id: string) => records.get(kind + id), put: (kind: string, id: string, value: any) => records.set(kind + id, value), login: vi.fn(async (name: string) => { if (name !== 'legitimate') throw new Error('invalid'); return { id: name }; }) };
  const app = express();
  app.use('/identity', identityRouter({ audit: { log() {} } } as any, { store, issuer: new URL('https://mcp.example.com') } as any));
  const backend = await listen(createServer(app));
  const gateway = await listen(createServer(gatewayHandler('https://mcp.example.com', backend, backend)));
  const login = (name: string) => new Promise<{ status: number; cookie: string }>((resolve, reject) => {
    const req = request({ hostname: '127.0.0.1', port: gateway, path: '/identity/login', method: 'POST', headers: { Host: 'mcp.example.com', 'Content-Type': 'application/x-www-form-urlencoded', 'X-Forwarded-For': 'spoof' } }, res => {
      res.resume(); res.on('end', () => resolve({ status: res.statusCode!, cookie: String(res.headers['set-cookie'] ?? '') }));
    });
    req.on('error', reject); req.end(new URLSearchParams({ name, password: 'test', otp: 'test' }).toString());
  });
  for (let i = 0; i < 15; i++) expect((await login('attacker')).status).toBe(400);
  expect((await login('attacker')).status).toBe(429);
  const legitimate = await login('legitimate');
  expect(legitimate.status).toBe(302);
  expect(legitimate.cookie).toContain('identity=');
  expect((await login('different-account')).status).toBe(400);
});
