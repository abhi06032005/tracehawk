import { z } from 'zod';

export const toolNames = ['get_session_evidence', 'inspect_http_exchange', 'inspect_browser_storage', 'analyze_security_headers', 'run_zap_passive_analysis', 'compare_test_account_access', 'check_rate_limit_with_budget', 'inspect_console_errors'] as const;
export type ToolName = typeof toolNames[number];
export const claimTypes = ['missing_csp', 'missing_hsts', 'cross_account_access', 'missing_authentication', 'missing_rate_limiting', 'sensitive_storage', 'other'] as const;
export const HypothesisSchema = z.object({
  title: z.string().min(1).max(200), affectedEndpoint: z.string().max(1000),
  claimType: z.enum(claimTypes), cweCategory: z.string().max(30).optional(),
  attackMechanism: z.string().max(2000), prerequisites: z.string().max(2000),
  potentialImpact: z.string().max(2000), suggestedRemediation: z.string().max(2000),
  risk: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']),
  confidence: z.enum(['HIGH', 'MEDIUM', 'LOW']),
  verificationStatus: z.enum(['HYPOTHESIS', 'NEEDS_VERIFICATION', 'VERIFIED', 'REJECTED']),
  supportingEvidenceIds: z.array(z.string().max(150)).max(30),
  verificationNotes: z.string().max(2000).default(''),
}).strict();
export const AgentDecisionSchema = z.object({
  phase: z.enum(['ANALYZE', 'EVALUATE']),
  thought: z.string().min(1).max(3000),
  hypotheses: z.array(HypothesisSchema).max(20).default([]),
  toolCall: z.object({ name: z.enum(toolNames), args: z.record(z.unknown()) }).strict().nullable().default(null),
  isFinished: z.boolean(), riskSummary: z.string().max(3000).default(''),
}).strict();
export type AgentDecision = z.infer<typeof AgentDecisionSchema>;
export type Hypothesis = z.infer<typeof HypothesisSchema>;
export const StartAuditSchema = z.object({
  authorized: z.literal(true).default(true), activeTests: z.boolean().default(false),
  maxSteps: z.number().int().min(2).max(30).default(20),
  maxTimeSeconds: z.union([z.literal(0), z.number().int().min(10).max(600)]).default(0),
  requestBudget: z.number().int().min(0).max(50).default(0),
}).strict();
export type AuditOptions = z.infer<typeof StartAuditSchema>;
export interface Evidence {
  id: string; kind: string; endpoint: string; sourceIds: string[];
  observations: Record<string, unknown>;
  supports: Hypothesis['claimType'][]; refutes: Hypothesis['claimType'][];
}
export interface ToolResult {
  status: 'ok' | 'denied' | 'unavailable' | 'error';
  evidence: Evidence[]; summary: string; data?: unknown;
}

// Verification requires a backend-produced proof for this exact claim and endpoint.
// A model's confidence, a status code, or an arbitrary reference is never proof.
export function gateHypothesis(h: Hypothesis, evidence: Evidence[]): Hypothesis {
  const refs = evidence.filter(e => h.supportingEvidenceIds.includes(e.id) && e.endpoint === h.affectedEndpoint);
  let status = h.verificationStatus;
  if (status === 'VERIFIED' && !refs.some(e => e.supports.includes(h.claimType))) status = 'NEEDS_VERIFICATION';
  if (status === 'REJECTED' && !refs.some(e => e.refutes.includes(h.claimType))) status = 'NEEDS_VERIFICATION';
  return { ...h, verificationStatus: status, supportingEvidenceIds: refs.map(e => e.id),
    ...(status === 'VERIFIED' ? { title: ({ missing_csp: 'Missing Content-Security-Policy header', missing_hsts: 'Missing Strict-Transport-Security header on HTTPS', cross_account_access: 'Non-owner test account accessed the configured protected resource' } as Record<string,string>)[h.claimType] || h.title } : {}),
    verificationNotes: status !== h.verificationStatus
      ? 'Backend evidence gate: the requested conclusion is not supported by an exact claim and endpoint proof.' : h.verificationNotes };
}
