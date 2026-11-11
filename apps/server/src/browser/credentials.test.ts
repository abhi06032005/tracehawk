import { afterEach, expect, it, vi } from 'vitest';
const { create } = vi.hoisted(() => ({ create: vi.fn(async () => ({})) }));
vi.mock('../db.js', () => ({ prisma: { browserEvent: { create } } }));
import { captureToken, forgetTokens, revealToken, tokenMetadata } from './credentials.js';
import { tokenSecurityMetadata } from '../ai/tools.js';
afterEach(() => { forgetTokens('one'); forgetTokens('two'); create.mockClear(); vi.useRealTimers(); });
it('keeps raw values out of persisted observations and isolates reveals by session', async () => {
  await captureToken('one', 'private-test-token', 'Authorization header', 'http://localhost');
  const row = create.mock.calls[0] as any;
  const id = row[0].data.metadata.tokenId;
  expect(JSON.stringify(row)).not.toContain('private-test-token');
  expect(revealToken('one', id)).toBe('private-test-token');
  expect(revealToken('two', id)).toBeNull();
  forgetTokens('one');
  expect(revealToken('one', id)).toBeNull();
});
it('expires raw values and deduplicates repeated observations', async () => {
  vi.useFakeTimers();
  await captureToken('one', 'temporary-secret', 'JSON response', 'http://localhost');
  await captureToken('one', 'temporary-secret', 'JSON response', 'http://localhost');
  expect(create).toHaveBeenCalledTimes(1);
  const id = (create.mock.calls[0] as any)[0].data.metadata.tokenId;
  vi.setSystemTime(Date.now() + 31 * 60 * 1000);
  expect(revealToken('one', id)).toBeNull();
});
it('decodes JWT facts without retaining identity claims', () => {
  const token = [ { alg: 'none' }, { sub: 'private-person', exp: 123 } ].map(x => Buffer.from(JSON.stringify(x)).toString('base64url')).join('.') + '.';
  const metadata = tokenMetadata(token);
  expect(metadata).toMatchObject({ format: 'JWT', algorithm: 'none', hasSubject: true, signaturePresent: false });
  expect(JSON.stringify(metadata)).not.toContain('private-person');
});
it('drops arbitrary database text and malformed token facts at the model boundary', () => {
  expect(tokenSecurityMetadata({ format: 'JWT', algorithm: 'secret', raw: 'secret', origin: 'secret', length: 'secret', secure: true, hasSubject: 'secret', expiresAt: Infinity })).toEqual({ format: 'JWT', secure: true });
  expect(tokenSecurityMetadata(null)).toEqual({});
});
