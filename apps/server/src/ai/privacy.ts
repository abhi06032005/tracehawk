import { createHash } from 'node:crypto';

export function scrubText(input: string): string {
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(input)) return input;
  if (/^https?:\/\/[^/?#]+\/\[endpoint-[0-9a-f]{12}\]$/.test(input)) return input;
  let value = input.replace(/\b(?:Bearer|Basic)\s+[^\s"',;]+/gi, '[REDACTED_AUTH]')
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, '[REDACTED_TOKEN]')
    .replace(/\bhf_[A-Za-z0-9_]{20,}\b/g, '[REDACTED_TOKEN]')
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[REDACTED_EMAIL]')
    .replace(/((?:password|passwd|secret|token|cookie|api[_-]?key|sessionid)\s*[=:]\s*)[^\s&;,"}]+/gi, '$1[REDACTED]')
    .replace(/\b(?:\+?\d[ ()-]?){9,16}\b/g, '[REDACTED_NUMBER]');
  for (const name of ['AI_API_KEY', 'ZAP_API_KEY', 'HF_TOKEN']) {
    const secret = process.env[name];
    if (secret) value = value.split(secret).join('[REDACTED]');
  }
  return value;
}
export function clean<T>(input: T): T {
  if (typeof input === 'string') return scrubText(input) as T;
  if (Array.isArray(input)) return input.map(clean) as T;
  if (input && typeof input === 'object') return Object.fromEntries(Object.entries(input).map(([k,v]) => [k, /^(password|token|authorization|cookie|apiKey|secret)$/i.test(k) ? '[REDACTED]' : clean(v)])) as T;
  return input;
}
export const opaque = (value: string) => createHash('sha256').update(value).digest('hex').slice(0, 12);

// An endpoint reference contains no captured path/query values. The actual URL is
// resolved server-side from the exchange ID; the model cannot supply credentials.
export function endpointRef(url: string): string {
  try { const u = new URL(url); return `${u.origin}/[endpoint-${opaque(u.pathname + u.search)}]`; }
  catch { return `[endpoint-${opaque(url)}]`; }
}
export function bodyShape(body: string | null | undefined): unknown {
  if (!body) return null;
  const visit = (v: unknown, depth: number): unknown => {
    if (depth > 5) return '[DEPTH_LIMIT]';
    if (Array.isArray(v)) return { type: 'array', count: v.length, sample: v.slice(0, 2).map(x => visit(x, depth + 1)) };
    if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).slice(0, 40).map(([k,val]) => [
      /^(id|status|error|message|data|results|user|users|role|password|token|email|phone|name|success|address)$/i.test(k) ? k : `field_${opaque(k)}`,
      visit(val, depth + 1),
    ]));
    return v === null ? null : `[${typeof v} value omitted]`;
  };
  try { return visit(JSON.parse(body), 0); }
  catch { return { type: 'non-json', bytes: Buffer.byteLength(body), content: '[OMITTED_FOR_PRIVACY]' }; }
}
export function headerFacts(headers: unknown) {
  const h = Object.fromEntries(Object.entries((headers || {}) as Record<string, unknown>).map(([k,v]) => [k.toLowerCase(), String(v)]));
  return { cspPresent: Boolean(h['content-security-policy']), hstsPresent: Boolean(h['strict-transport-security']),
    nosniff: h['x-content-type-options']?.toLowerCase() === 'nosniff',
    frameProtectionPresent: Boolean(h['x-frame-options']) || /frame-ancestors/i.test(h['content-security-policy'] || ''),
    corsWildcard: h['access-control-allow-origin'] === '*', corsCredentials: h['access-control-allow-credentials'] === 'true',
    authenticationHeaderPresent: Boolean(h.authorization), cookieHeaderPresent: Boolean(h.cookie || h['set-cookie']),
    serverDisclosed: Boolean(h.server), poweredByDisclosed: Boolean(h['x-powered-by']) };
}
