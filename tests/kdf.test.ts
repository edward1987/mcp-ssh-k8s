import { expect, it } from 'vitest';
import { deriveKey } from '../src/vault/crypto.js';
it('bounds password work and refuses excessive or attacker-selected KDF costs', async () => {
  const salt = Buffer.alloc(16), operations = Array.from({ length: 10 }, () => deriveKey('test password', salt));
  await expect(deriveKey('overflow', salt)).rejects.toThrow('Too many password operations');
  const keys = await Promise.all(operations);
  expect(keys.every(key => key.equals(keys[0]))).toBe(true);
  keys.forEach(key => key.fill(0));
  await expect(deriveKey('test', salt, { N: 1 << 24, r: 8, p: 1 })).rejects.toThrow('Unsupported');
}, 15000);
