import { sha256 as awaitHash } from "../vault/store.js";
import { AsyncLocalStorage } from 'node:async_hooks';
import type { Ctx } from '../service.js';
import type { Grant, Principal } from './store.js';
export const identityContext = new AsyncLocalStorage<Principal>();
export function canAccess(ctx: Ctx, type: Grant['type'], id: string) {
  if (!ctx.identities) return true; // Isolated service tests; production always supplies an identity store.
  const p = identityContext.getStore();
  if (ctx.registry) {
    if (!p) return false;
    try {
      if (p.sessionId) { const s = ctx.identities.get<any>("session", p.sessionId); if (!s || s.expires <= Date.now() || s.idle <= Date.now()) return false; }
      const v = ctx.registry.get(p.userId);
      if (!v.unlocked) return false;
      if (p.token) { const t = ctx.identities.get<any>("access", (awaitHash(p.token))); if (!t || t.expires < Date.now() || t.userId !== p.userId) return false; }
      return (type === "host" ? v.d.hosts : v.d.clusters).some(r => r.id === id);
    } catch { return false; }
  }
  return !!p && ctx.identities.can(p, type, id);
}
export function requireAccess(ctx: Ctx, type: Grant['type'], id: string) { if (!canAccess(ctx, type, id)) throw new Error('Resource unavailable'); }
