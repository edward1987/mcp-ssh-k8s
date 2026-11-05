import type express from 'express';
import type { IdentityStore } from './store.js';
import { sha256 } from '../vault/store.js';

export function session(store: IdentityStore, req: express.Request, touch = false) {
  const raw = /(?:^|;\s*)identity=([\w-]+)/.exec(req.headers.cookie ?? '')?.[1];
  const s = raw ? store.get<any>('session', sha256(raw)) : undefined;
  if (!s || s.expires < Date.now() || s.idle < Date.now()) return undefined;
  try { const user = store.user(s.userId); if (touch) { s.idle = Date.now() + 1800000; store.put('session', s.id, s); } return { ...s, user }; } catch { return undefined; }
}
