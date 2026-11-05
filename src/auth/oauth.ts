import type { Response } from 'express';
import type { OAuthServerProvider, AuthorizationParams } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import { InvalidGrantError, InvalidRequestError, InvalidTokenError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { sha256 } from '../vault/store.js';
import { IdentityStore, randomToken } from './store.js';

export class OAuthProvider implements OAuthServerProvider {
  // PKCE is checked here atomically with code consumption, rather than in the SDK handler.
  readonly skipLocalPkceValidation = true;
  constructor(readonly store: IdentityStore, readonly issuer: URL, readonly resource: URL) {}
  setPublicOrigin(origin: string) {
    const url = new URL(origin);
    if (url.protocol !== 'https:' || url.pathname !== '/' || url.username || url.password || url.search || url.hash) throw new Error('HTTPS origin required');
    this.issuer.href = url.href;
    this.resource.href = new URL('/mcp', url).href;
  }
  clientsStore = {
    getClient: (id: string) => this.store.get<OAuthClientInformationFull>('client', id),
    registerClient: (input: Omit<OAuthClientInformationFull, 'client_id' | 'client_id_issued_at'>) => {
      if (this.store.all('client').length >= 1000) throw new InvalidRequestError('Client limit reached');
      for (const uri of input.redirect_uris) { const u = new URL(uri); if (u.hash || u.username || u.password || (u.protocol !== 'https:' && !(u.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(u.hostname)))) throw new InvalidRequestError('Unsafe redirect URI'); }
      if (input.token_endpoint_auth_method && input.token_endpoint_auth_method !== 'none') throw new InvalidRequestError('Use public clients with PKCE');
      const client = { ...input, token_endpoint_auth_method: 'none' as const, client_id: randomToken(), client_id_issued_at: Math.floor(Date.now() / 1000) };
      this.store.put('client', client.client_id, client); return client;
    },
  };
  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response) {
    this.validateResource(params.resource);
    if (params.scopes?.some(s => s !== 'mcp:use')) throw new InvalidRequestError('Unsupported scope');
    const id = randomToken();
    this.store.put('pending', id, { id, clientId: client.client_id, ...params, resource: this.resource.href, expires: Date.now() + 300000 });
    res.redirect(new URL('/identity/consent?request=' + id, this.issuer).href);
  }
  validateResource(resource?: URL) { if (resource?.href !== this.resource.href) throw new InvalidRequestError('Invalid resource'); }
  consent(id: string, userId: string, allow: boolean) {
    this.store.user(userId);
    const p = this.store.get<any>('pending', id);
    if (!p || p.expires < Date.now()) throw new InvalidRequestError('Expired authorization');
    this.store.del('pending', id);
    const redirect = new URL(p.redirectUri);
    if (p.state) redirect.searchParams.set('state', p.state);
    if (allow) { const code = randomToken(); this.store.put('code', sha256(code), { ...p, id: sha256(code), userId }); redirect.searchParams.set('code', code); }
    else redirect.searchParams.set('error', 'access_denied');
    return redirect.href;
  }
  async challengeForAuthorizationCode(client: OAuthClientInformationFull, code: string) { return this.code(client, code).codeChallenge; }
  private code(client: OAuthClientInformationFull, code: string) {
    const c = this.store.get<any>('code', sha256(code));
    if (!c || c.clientId !== client.client_id || c.expires < Date.now()) throw new InvalidGrantError('Invalid code');
    this.store.user(c.userId); return c;
  }
  async exchangeAuthorizationCode(client: OAuthClientInformationFull, code: string, verifier?: string, redirectUri?: string, resource?: URL) {
    const c = this.code(client, code); this.validateResource(resource);
    if (redirectUri !== c.redirectUri || !verifier || Buffer.from(sha256(verifier), 'hex').toString('base64url') !== c.codeChallenge) throw new InvalidGrantError('Invalid code binding');
    this.store.del('code', sha256(code)); return this.issue(c);
  }
  private issue(c: any) {
    const access = randomToken(), refresh = randomToken();
    const base = { userId: c.userId, clientId: c.clientId, resource: this.resource.href, scopes: c.scopes?.length ? c.scopes : ['mcp:use'], family: c.family ?? randomToken(), familyExpires: c.familyExpires ?? Date.now() + 30 * 86400000 };
    this.store.put('access', sha256(access), { ...base, id: sha256(access), expires: Date.now() + 600000 });
    this.store.put('refresh', sha256(refresh), { ...base, id: sha256(refresh), expires: base.familyExpires, used: false });
    return { access_token: access, token_type: 'Bearer', expires_in: 600, refresh_token: refresh, scope: base.scopes.join(' ') };
  }
  async exchangeRefreshToken(client: OAuthClientInformationFull, token: string, scopes?: string[], resource?: URL) {
    this.validateResource(resource);
    const r = this.store.get<any>('refresh', sha256(token));
    if (!r || r.clientId !== client.client_id) throw new InvalidGrantError('Invalid refresh token');
    if (r.used) { this.revokeFamily(r.family); throw new InvalidGrantError('Refresh token reused'); }
    if (r.expires < Date.now() || scopes?.some(s => !r.scopes.includes(s))) throw new InvalidGrantError('Expired token or invalid scopes');
    this.store.user(r.userId); this.store.put('refresh', r.id, { ...r, used: true }); return this.issue({ ...r, scopes: scopes ?? r.scopes });
  }
  async verifyAccessToken(token: string) {
    const t = this.store.get<any>('access', sha256(token));
    if (!t || t.expires < Date.now() || t.resource !== this.resource.href || !t.scopes.includes('mcp:use')) throw new InvalidTokenError('Invalid token');
    try { this.store.user(t.userId); } catch { throw new InvalidTokenError('Invalid user'); }
    return { token, clientId: t.clientId, scopes: t.scopes, expiresAt: Math.floor(t.expires / 1000), resource: this.resource, extra: { userId: t.userId } };
  }
  revokeFamily(family: string) { for (const kind of ['access', 'refresh']) for (const r of this.store.all<any>(kind)) if (r.family === family) this.store.del(kind, r.id); }
  async revokeToken(client: OAuthClientInformationFull, request: { token: string }) { for (const kind of ['access', 'refresh']) { const r = this.store.get<any>(kind, sha256(request.token)); if (r?.clientId === client.client_id) this.revokeFamily(r.family); } }
}
