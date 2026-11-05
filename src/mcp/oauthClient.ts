import { protectCredentials } from "../auth/files.js";
import { createServer, type Server } from 'node:http';
import { mkdirSync, readFileSync, writeFileSync, existsSync, renameSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { randomBytes, createHash } from 'node:crypto';
import type { OAuthClientProvider } from '@modelcontextprotocol/sdk/client/auth.js';
import type { OAuthClientInformationMixed, OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js';

/** Per-OS-user credentials, never embedded in project configuration or stdout. */
export class BridgeOAuth implements OAuthClientProvider {
  private data: { client?: OAuthClientInformationMixed; tokens?: OAuthTokens } = {};
  private verifier = '';
  private nonce = '';
  private callback?: Server;
  private redirect = '';
  private code?: Promise<string>;
  private path: string;
  constructor(endpoint: string) {
    const dir = join(homedir(), '.mcp-ssh', 'oauth'); mkdirSync(dir, { recursive: true, mode: 0o700 }); protectCredentials(dir, true);
    this.path = join(dir, createHash('sha256').update(endpoint).digest('hex') + '.json');
    if (existsSync(this.path)) this.data = JSON.parse(readFileSync(this.path, 'utf8'));
  }
  get redirectUrl() { return this.redirect; }
  get clientMetadata() { return { client_name: 'MCP SSH stdio bridge', redirect_uris: [this.redirect], token_endpoint_auth_method: 'none' as const, grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], scope: 'mcp:use' }; }
  clientInformation() { return this.data.client; }
  saveClientInformation(client: OAuthClientInformationMixed) { this.data.client = client; this.save(); }
  tokens() { return this.data.tokens; }
  saveTokens(tokens: OAuthTokens) { this.data.tokens = tokens; this.save(); }
  saveCodeVerifier(verifier: string) { this.verifier = verifier; }
  codeVerifier() { return this.verifier; }
  state() { this.nonce = randomBytes(32).toString('base64url'); return this.nonce; }
  invalidateCredentials(scope: string) { if (scope === 'all' || scope === 'client') delete this.data.client; if (scope === 'all' || scope === 'tokens') delete this.data.tokens; this.save(); }
  private save() { const tmp = this.path + '.' + process.pid + '.tmp'; writeFileSync(tmp, JSON.stringify(this.data), { mode: 0o600 }); renameSync(tmp, this.path); }
  async prepare() {
    let accept!: (code: string) => void;
    this.code = new Promise(resolve => { accept = resolve; });
    this.callback = createServer((req, res) => {
      const u = new URL(req.url ?? '/', 'http://127.0.0.1');
      if (u.pathname !== '/callback' || !this.nonce || u.searchParams.get('state') !== this.nonce || !u.searchParams.get('code')) { res.writeHead(400).end('Invalid OAuth callback'); return; }
      res.setHeader('Content-Type', 'text/plain; charset=utf-8'); res.end('Authenticated. You can close this page.');
      accept(u.searchParams.get('code')!); this.nonce = '';
    });
    await new Promise<void>(resolve => this.callback!.listen(0, '127.0.0.1', resolve));
    this.redirect = `http://127.0.0.1:${(this.callback.address() as { port: number }).port}/callback`;
  }
  redirectToAuthorization(url: URL) { console.error('Open this URL in your browser to sign in:\n' + url.href); }
  async authorizationCode() {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try { return await Promise.race([this.code!, new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('OAuth timed out')), 300000); })]); }
    finally { clearTimeout(timer); }
  }
  close() { this.callback?.close(); }
}
