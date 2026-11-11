import { z } from 'zod';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { prisma } from '../db.js';
import { bodyShape, clean, endpointRef, headerFacts, opaque } from './privacy.js';
import { boundedText } from './provider.js';
import { Evidence, ToolName, ToolResult } from './contracts.js';
import { runZap } from './zap.js';
import { SecurityPolicyGateway, ToolRiskTier, ToolSecurityMetadata } from '../security/policy.js';
export type { ToolName } from './contracts.js';
export type { ToolRiskTier, ToolSecurityMetadata } from '../security/policy.js';

const empty = z.object({}).strict();
// Database rows may contain legacy or malformed fields. Only typed security facts leave this boundary.
export function tokenSecurityMetadata(value: unknown) {
  const input = value && typeof value === 'object' ? value as Record<string, unknown> : {};
  const output: Record<string, unknown> = {};
  for (const key of ['hasIssuer', 'hasAudience', 'hasSubject', 'signaturePresent', 'httpOnly', 'secure']) {
    if (typeof input[key] === 'boolean') output[key] = input[key];
  }
  for (const key of ['length', 'expiresAt', 'issuedAt', 'notBefore']) {
    if (typeof input[key] === 'number' && Number.isFinite(input[key])) output[key] = input[key];
  }
  const enums: Record<string, string[]> = {
    format: ['opaque', 'JWT'],
    algorithm: ['none', 'HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512', 'EdDSA', 'unrecognized'],
    sameSite: ['strict', 'lax', 'none', 'unspecified'],
    location: ['Authorization header', 'Cookie request', 'Set-Cookie response', 'JSON response', 'localStorage', 'sessionStorage'],
  };
  for (const [key, allowed] of Object.entries(enums)) {
    if (typeof input[key] === 'string' && allowed.includes(input[key])) output[key] = input[key];
  }
  return output;
}
const exchange = z.object({ exchangeId: z.string().uuid() }).strict();
export const toolSchemas = {
  get_session_evidence: empty,
  inspect_http_exchange: exchange,
  inspect_browser_storage: z.object({ storageType: z.enum(['COOKIE','LOCAL_STORAGE','SESSION_STORAGE','INDEXED_DB','ALL']).default('ALL') }).strict(),
  analyze_security_headers: exchange,
  run_zap_passive_analysis: empty,
  compare_test_account_access: z.object({ scenarioId: z.string().min(1).max(80) }).strict(),
  check_rate_limit_with_budget: z.object({ exchangeId: z.string().uuid(), method: z.enum(['GET','POST','PUT','PATCH','DELETE']).default('GET'), budget: z.number().int().min(1).max(5).default(3) }).strict(),
  inspect_console_errors: empty,
};
export const TOOL_DEFINITIONS = [
  { name: 'get_session_evidence', description: 'Read complete endpoint inventory and privacy-projected session context.', parameters: {} },
  { name: 'inspect_http_exchange', description: 'Inspect a recorded exchange, using its exchangeId. All values are privacy projected.', parameters: { exchangeId: 'UUID from evidence' } },
  { name: 'inspect_browser_storage', description: 'Inspect storage metadata; values are never returned.', parameters: { storageType: 'COOKIE|LOCAL_STORAGE|SESSION_STORAGE|INDEXED_DB|ALL' } },
  { name: 'analyze_security_headers', description: 'Verify specific missing CSP/HSTS configuration on an exchange.', parameters: { exchangeId: 'UUID from evidence' } },
  { name: 'run_zap_passive_analysis', description: 'Import privacy-projected recorded HAR into dedicated ZAP and await passive analysis. Never replays traffic.', parameters: {} },
  { name: 'compare_test_account_access', description: 'Compare two configured test accounts against an operator-defined resource ownership scenario.', parameters: { scenarioId: 'ID from availableScenarios' } },
  { name: 'check_rate_limit_with_budget', description: 'Bounded requests; absence of 429 is inconclusive. Mutating methods require a separate human approval.', parameters: { exchangeId: 'UUID from evidence', method: 'GET|POST|PUT|PATCH|DELETE', budget: 'integer 1..5' } },
  { name: 'inspect_console_errors', description: 'Inspect error categories and WebSocket metadata without private message text.', parameters: {} },
];
const AccountSchema = z.object({ id: z.string(), origin: z.string().url(), headers: z.record(z.string()) }).strict();
const ScenarioSchema = z.object({ id: z.string(), endpoint: z.string().url(), ownerAccountId: z.string(), otherAccountId: z.string(), resourcePointer: z.string().startsWith('/'), expectedResourceValue: z.union([z.string(), z.number()]), otherMustBeDenied: z.literal(true) }).strict();
function accounts() { return z.array(AccountSchema).parse(JSON.parse(process.env.AI_TEST_ACCOUNTS || '[]')); }
function scenarios() { return z.array(ScenarioSchema).parse(JSON.parse(process.env.AI_ACCESS_SCENARIOS || '[]')); }
export function availableScenarios() { return scenarios().map(s => ({ id: s.id, endpoint: endpointRef(s.endpoint), expectedPolicy: 'Only the owner account may access this resource' })); }
export interface ToolContext {
  sessionId: string; investigationId: string; allowedOrigins: string[];
  authorized: boolean; activeTests: boolean; signal: AbortSignal;
  remainingRequests: number; reserveRequest: () => Promise<void>;
  approve: (description: Record<string, unknown>) => Promise<boolean>;
}
export function isAllowed(url: string, origins: string[]): boolean {
  try {
    const u = new URL(url);
    return ['http:','https:'].includes(u.protocol) && !u.username && !u.password && !u.hash && origins.includes(u.origin);
  } catch { return false; }
}
function fact(kind: string, endpoint: string, sourceIds: string[], observations: Record<string, unknown>, supports: Evidence['supports'] = [], refutes: Evidence['refutes'] = []): Evidence {
  return { id: randomUUID(), kind, endpoint, sourceIds, observations, supports, refutes };
}
function result(evidence: Evidence[], summary: string, data?: unknown): ToolResult { return clean({ status: 'ok', evidence, summary, ...(data === undefined ? {} : { data }) }); }
function denied(summary: string): ToolResult { return { status: 'denied', evidence: [], summary }; }
function httpEvidence(e: any): Evidence {
  return fact('http_exchange', endpointRef(e.url), [e.id], { exchangeId: e.id, method: e.method, statusCode: e.statusCode,
    requestHeaders: headerFacts(e.requestHeaders), responseHeaders: headerFacts(e.responseHeaders),
    requestExample: bodyShape(e.sanitizedRequestBody), responseExample: bodyShape(e.sanitizedResponseBody),
    resourceType: ['document','fetch','xhr','script','stylesheet','image','font','websocket','other'].includes(e.resourceType) ? e.resourceType : 'other', failed: Boolean(e.failureReason) });
}
async function getExchange(ctx: ToolContext, id: string) {
  const e = await prisma.httpExchange.findFirst({ where: { id, sessionId: ctx.sessionId } });
  if (!e || !isAllowed(e.url, ctx.allowedOrigins)) throw new Error('Exchange missing or outside authorized scope');
  return e;
}
async function request(ctx: ToolContext, url: string, method: string, headers: Record<string,string> = {}) {
  ctx.signal.throwIfAborted();
  if (!ctx.authorized || !ctx.activeTests || !isAllowed(url, ctx.allowedOrigins)) throw new Error('Active request not authorized');
  if (/\[REDACTED|%5BREDACTED/i.test(url)) throw new Error('Cannot replay a redacted URL');
  if (ctx.remainingRequests <= 0) throw new Error('Investigation request budget exhausted');
  ctx.remainingRequests--; await ctx.reserveRequest(); ctx.signal.throwIfAborted();
  const response = await fetch(url, { method, headers: { Accept: 'application/json', 'User-Agent': 'TraceHawk-Audit/2.0', ...headers }, redirect: 'manual',
    signal: AbortSignal.any([ctx.signal, AbortSignal.timeout(5000)]) });
  const body = await boundedText(response, 256 * 1024);
  return { status: response.status, body, rateHeader: ['retry-after','x-ratelimit-limit','ratelimit-limit','ratelimit-remaining'].some(k => response.headers.has(k)) };
}
export const TOOL_METADATA_REGISTRY: Record<ToolName, ToolSecurityMetadata> = {
  get_session_evidence: {
    name: 'get_session_evidence',
    version: '1.0.0',
    description: 'Read complete endpoint inventory and privacy-projected session context.',
    risk: 'READ_ONLY',
    timeoutMs: 15000,
    requiredPermissions: ['read:session'],
    enabled: true,
  },
  inspect_http_exchange: {
    name: 'inspect_http_exchange',
    version: '1.0.0',
    description: 'Inspect a recorded exchange, using its exchangeId. All values are privacy projected.',
    risk: 'READ_ONLY',
    timeoutMs: 10000,
    requiredPermissions: ['read:exchanges'],
    enabled: true,
  },
  inspect_browser_storage: {
    name: 'inspect_browser_storage',
    version: '1.0.0',
    description: 'Inspect storage metadata; values are never returned.',
    risk: 'READ_ONLY',
    timeoutMs: 10000,
    requiredPermissions: ['read:storage'],
    enabled: true,
  },
  analyze_security_headers: {
    name: 'analyze_security_headers',
    version: '1.0.0',
    description: 'Verify specific missing CSP/HSTS configuration on an exchange.',
    risk: 'PASSIVE',
    timeoutMs: 10000,
    requiredPermissions: ['read:exchanges'],
    enabled: true,
  },
  run_zap_passive_analysis: {
    name: 'run_zap_passive_analysis',
    version: '1.0.0',
    description: 'Import privacy-projected recorded HAR into dedicated ZAP and await passive analysis. Never replays traffic.',
    risk: 'PASSIVE',
    timeoutMs: 45000,
    requiredPermissions: ['exec:zap_passive'],
    enabled: true,
  },
  compare_test_account_access: {
    name: 'compare_test_account_access',
    version: '1.0.0',
    description: 'Compare two configured test accounts against an operator-defined resource ownership scenario.',
    risk: 'ACTIVE_SAFE',
    timeoutMs: 20000,
    requiredPermissions: ['exec:active_test'],
    enabled: true,
  },
  check_rate_limit_with_budget: {
    name: 'check_rate_limit_with_budget',
    version: '1.0.0',
    description: 'Bounded requests; absence of 429 is inconclusive. Mutating methods require a separate human approval.',
    risk: 'ACTIVE_SAFE',
    timeoutMs: 30000,
    requiredPermissions: ['exec:active_test'],
    enabled: true,
  },
  inspect_console_errors: {
    name: 'inspect_console_errors',
    version: '1.0.0',
    description: 'Inspect error categories and WebSocket metadata without private message text.',
    risk: 'READ_ONLY',
    timeoutMs: 10000,
    requiredPermissions: ['read:events'],
    enabled: true,
  },
};

export class ToolRegistry {
  static getMetadata(name: ToolName): ToolSecurityMetadata {
    return { ...TOOL_METADATA_REGISTRY[name] };
  }

  static listTools(): ToolSecurityMetadata[] {
    return Object.values(TOOL_METADATA_REGISTRY).map((m) => ({ ...m }));
  }

  static setToolEnabled(name: ToolName, enabled: boolean): void {
    if (TOOL_METADATA_REGISTRY[name]) {
      TOOL_METADATA_REGISTRY[name].enabled = enabled;
    }
  }

  static async execute(name: ToolName, rawArgs: unknown, ctx: ToolContext): Promise<ToolResult> {
    ctx.signal.throwIfAborted();
    if (!ctx.authorized) return denied('Explicit target authorization is required');

    const meta = TOOL_METADATA_REGISTRY[name];
    if (meta && !meta.enabled) {
      return denied(`Tool '${name}' is currently disabled`);
    }

    const args = toolSchemas[name].parse(rawArgs) as any;
    switch (name) {
      case 'get_session_evidence': {
        const [all, storage, events, findings] = await Promise.all([
          prisma.httpExchange.findMany({ where: { sessionId: ctx.sessionId }, orderBy: { timestamp: 'asc' } }),
          prisma.storageObservation.findMany({ where: { sessionId: ctx.sessionId } }),
          prisma.browserEvent.findMany({ where: { sessionId: ctx.sessionId }, orderBy: { timestamp: 'asc' } }),
          prisma.finding.findMany({ where: { sessionId: ctx.sessionId } }),
        ]);
        const exchanges = all.filter(e => isAllowed(e.url, ctx.allowedOrigins));
        const inventory = new Map<string, { endpoint: string; method: string; statuses: (number|null)[]; exchangeIds: string[]; count: number }>();
        for (const e of exchanges) {
          const endpoint = endpointRef(e.url), key = `${e.method} ${endpoint}`;
          const row = inventory.get(key) || { endpoint, method: e.method, statuses: [], exchangeIds: [], count: 0 };
          if (!row.statuses.includes(e.statusCode)) row.statuses.push(e.statusCode);
          if (row.exchangeIds.length < 3) row.exchangeIds.push(e.id); row.count++; inventory.set(key,row);
        }
        return result(exchanges.slice(0,30).map(httpEvidence), 'Recorded context; arbitrary payload values, paths and console text withheld for privacy. Additional exchanges can be inspected by ID.', {
          endpointInventory: [...inventory.values()], totalExchanges: exchanges.length, exampleLimit: 30,
          authenticationObservations: { withAuthHeaders: exchanges.filter(e => headerFacts(e.requestHeaders).authenticationHeaderPresent).length, deniedResponses: exchanges.filter(e => e.statusCode === 401 || e.statusCode === 403).map(e => ({ exchangeId: e.id, endpoint: endpointRef(e.url), status: e.statusCode })) },
          storageObservations: storage.map(s => ({ sourceId: s.id, origin: new URL(s.origin).origin, storageType: s.storageType, credentialLikeKey: /token|auth|pass|secret|jwt/i.test(s.key), values: 'omitted', cookieFlags: cookieFlags(s.metadata) })),
          consoleErrors: events.filter(e => /CONSOLE_ERROR|CONSOLE_WARN|PAGE_CRASH|PAGE_ERROR/.test(e.type)).map(e => ({ sourceId: e.id, category: errorCategory(e.message), type: e.type })),
          webSockets: events.filter(e => e.type.startsWith('WEBSOCKET')).map(e => ({ sourceId: e.id, type: 'WEBSOCKET', metadata: wsMetadata(e.metadata) })),
          tokenSecurityObservations: events.filter(e => e.type === 'TOKEN_OBSERVATION').map(e => ({ sourceId: e.id, metadata: tokenSecurityMetadata(e.metadata) })),
          passiveFindings: findings.map(f => ({ sourceId: f.id, category: f.category, cweId: f.cweId, severity: f.severity, verificationStatus: f.verificationStatus })),
          availableScenarios: availableScenarios(),
        });
      }
      case 'inspect_http_exchange': return result([httpEvidence(await getExchange(ctx,args.exchangeId))], 'Recorded exchange with privacy-projected examples');
      case 'analyze_security_headers': {
        const e = await getExchange(ctx,args.exchangeId), h = headerFacts(e.responseHeaders);
        if (!e.statusCode || e.statusCode < 200 || e.statusCode >= 400 || e.resourceType !== 'document') return { status: 'unavailable', evidence: [], summary: 'Requires a successful document response' };
        const supports: Evidence['supports'] = [], refutes: Evidence['refutes'] = [];
        (h.cspPresent ? refutes : supports).push('missing_csp');
        if (new URL(e.url).protocol === 'https:') (h.hstsPresent ? refutes : supports).push('missing_hsts');
        return result([fact('security_headers',endpointRef(e.url),[e.id],h,supports,refutes)], 'Configuration evidence only; missing headers do not prove exploitability or XSS');
      }
      case 'inspect_browser_storage': {
        const items = await prisma.storageObservation.findMany({ where: { sessionId: ctx.sessionId, ...(args.storageType === 'ALL' ? {} : { storageType: args.storageType }) } });
        return result(items.map(s => fact('storage',endpointRef(s.origin),[s.id],{ storageType: s.storageType, keyReference: opaque(s.key), credentialLikeKey: /token|auth|pass|secret|jwt/i.test(s.key), value: '[OMITTED]', cookieFlags: cookieFlags(s.metadata), limitation: 'Key names alone do not prove credential storage' })), 'Storage observations contain no values');
      }
      case 'inspect_console_errors': {
        const events = await prisma.browserEvent.findMany({ where: { sessionId: ctx.sessionId }, orderBy: { timestamp: 'asc' } });
        return result(events.filter(e => /CONSOLE_|PAGE_|WEBSOCKET|TOKEN_OBSERVATION/.test(e.type)).map(e => fact('browser_event',endpointRef(e.pageUrl || ''),[e.id],{ category: errorCategory(e.message), type: /^WEBSOCKET/.test(e.type) ? 'WEBSOCKET' : e.type, metadata: e.type === 'TOKEN_OBSERVATION' ? tokenSecurityMetadata(e.metadata) : wsMetadata(e.metadata), message: '[PRIVATE_TEXT_OMITTED]' })), 'Browser error categories, token security observations and WebSocket metadata');
      }
      case 'run_zap_passive_analysis': {
        const exchanges = await prisma.httpExchange.findMany({ where: { sessionId: ctx.sessionId }, orderBy: { timestamp: 'asc' } });
        return runZap(exchanges.filter(e => isAllowed(e.url,ctx.allowedOrigins)),ctx.signal);
      }
      case 'check_rate_limit_with_budget': {
        if (!ctx.activeTests) return denied('Active tests were not authorized for this investigation');
        const e = await getExchange(ctx,args.exchangeId);
        if (args.budget > ctx.remainingRequests) return denied('Insufficient remaining request budget');
        if (args.method !== 'GET' && !await ctx.approve({ tool: name, exchangeId: e.id, endpoint: endpointRef(e.url), method: args.method, requests: args.budget, body: 'No request body or recorded credentials will be sent' })) return denied('State-changing test was not approved');
        const probes = [];
        for (let i=0;i<args.budget;i++) {
          const r = await request(ctx,e.url,args.method); probes.push({ status: r.status, rateHeader: r.rateHeader });
          if (r.status === 429 || r.status >= 300 && r.status < 400) break;
          await delay(150,undefined,{ signal: ctx.signal });
        }
        return result([fact('rate_probe',endpointRef(e.url),[e.id],{ probes, totalRequestsSent: probes.length, conclusion: 'Absence of throttling within this budget is inconclusive; redirects are never followed' })], 'Bounded rate-limit observations; no absence claim can be verified');
      }
      case 'compare_test_account_access': {
        if (!ctx.activeTests) return denied('Active tests were not authorized for this investigation');
        const scenario = scenarios().find(s => s.id === args.scenarioId);
        if (!scenario || !isAllowed(scenario.endpoint,ctx.allowedOrigins)) return denied('Scenario missing or outside authorized scope');
        const configured = accounts();
        const owner = configured.find(a => a.id === scenario.ownerAccountId), other = configured.find(a => a.id === scenario.otherAccountId);
        if (!owner || !other || owner.id === other.id || JSON.stringify(owner.headers) === JSON.stringify(other.headers)) return denied('Two distinct test-account credentials are required');
        if ([owner,other].some(a => a.origin !== new URL(scenario.endpoint).origin || Object.keys(a.headers).some(k => !['authorization','cookie'].includes(k.toLowerCase())))) return denied('Account origin/header configuration is invalid');
        if (ctx.remainingRequests < 2) return denied('Two requests are required');
        const a = await request(ctx,scenario.endpoint,'GET',owner.headers);
        const b = await request(ctx,scenario.endpoint,'GET',other.headers);
        const match = (r: typeof a) => {
          try { let value = JSON.parse(r.body); for (const part of scenario.resourcePointer.slice(1).split('/')) value = value[part.replace(/~1/g,'/').replace(/~0/g,'~')]; return value === scenario.expectedResourceValue; } catch { return false; }
        };
        const baseline = a.status === 200 && match(a), unauthorizedMatch = b.status === 200 && match(b);
        return result([fact('account_comparison',endpointRef(scenario.endpoint),[], { scenarioId: scenario.id, ownerStatus: a.status, otherStatus: b.status, ownerResourceMatched: baseline, otherResourceMatched: unauthorizedMatch, expectedPolicy: 'Non-owner must be denied' }, baseline && unauthorizedMatch ? ['cross_account_access'] : [], baseline && [401,403].includes(b.status) ? ['cross_account_access'] : [])], 'Compared configured owner and non-owner accounts; credential and response values withheld');
      }
    }
  }
}
function errorCategory(text: string) { return /TypeError/.test(text) ? 'TypeError' : /ReferenceError/.test(text) ? 'ReferenceError' : /CORS/i.test(text) ? 'CORS' : /Content.Security.Policy/i.test(text) ? 'CSP' : 'Browser error or warning'; }
function wsMetadata(input: unknown) {
  const m = input && typeof input === 'object' ? input as Record<string,unknown> : {};
  return { ...Object.fromEntries(['length','size','payloadSize','payloadLength','byteLength','code','wasClean'].filter(k => typeof m[k] === 'number' || typeof m[k] === 'boolean').map(k => [k,m[k]])), direction: ['sent','received'].includes(String(m.direction)) ? m.direction : undefined };
}
function cookieFlags(input: unknown) {
  const m = input && typeof input === 'object' ? input as Record<string,unknown> : {};
  return { httpOnly: typeof m.httpOnly === 'boolean' ? m.httpOnly : null, secure: typeof m.secure === 'boolean' ? m.secure : null, sameSite: ['Strict','Lax','None'].includes(String(m.sameSite)) ? m.sameSite : null, limitation: Object.keys(m).length ? undefined : 'Flags not available in legacy snapshot' };
}
