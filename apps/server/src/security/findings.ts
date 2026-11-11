import { z } from 'zod';
import { randomUUID } from 'node:crypto';
import type { Finding as PrismaFinding, AiHypothesis as PrismaAiHypothesis } from '@prisma/client';
import type { FindingDraft } from './rules.js';
import type { Evidence } from '../ai/contracts.js';

export const FindingSeveritySchema = z.enum(['critical', 'high', 'medium', 'low', 'informational']);
export type FindingSeverity = z.infer<typeof FindingSeveritySchema>;

export const FindingStatusSchema = z.enum([
  'discovered',
  'needs_verification',
  'verified',
  'false_positive',
  'inconclusive',
  'declined',
]);
export type FindingStatus = z.infer<typeof FindingStatusSchema>;

export const NormalizedFindingSchema = z.object({
  id: z.string().uuid(),
  title: z.string().min(1),
  severity: FindingSeveritySchema,
  status: FindingStatusSchema,
  target: z.string(),
  endpoint: z.string(),
  method: z.string().default('GET'),
  cwe: z.array(z.string()).default([]),
  owasp_category: z.string().default(''),
  description: z.string().default(''),
  evidence: z.array(z.any()).default([]),
  reproduction_steps: z.array(z.string()).default([]),
  impact: z.string().default(''),
  remediation: z.string().default(''),
  confidence: z.number().min(0).max(100).default(50),
  source_agent: z.string().default('passive_engine'),
  source_tool: z.string().default('deterministic_rules'),
  created_at: z.string(),
  verified_at: z.string().nullable().default(null),
  // Benchmark attribution fields (Feature #4)
  source_model: z.string().optional(),
  raw_confidence_text: z.string().optional(),
  verifier_result: z.any().optional(),
  prompt_variant_id: z.string().optional(),
});

export type NormalizedFinding = z.infer<typeof NormalizedFindingSchema>;

/**
 * Normalizes uppercase severity strings (from Prisma Finding / AiHypothesis) to standard lowercase.
 */
export function normalizeSeverity(rawSeverity: string): FindingSeverity {
  const upper = (rawSeverity || '').toUpperCase();
  switch (upper) {
    case 'CRITICAL':
      return 'critical';
    case 'HIGH':
      return 'high';
    case 'MEDIUM':
      return 'medium';
    case 'LOW':
      return 'low';
    case 'INFO':
    case 'INFORMATIONAL':
    default:
      return 'informational';
  }
}

/**
 * Maps verification status to the standard 5 statuses.
 */
export function normalizeStatus(rawStatus: string): FindingStatus {
  const upper = (rawStatus || '').toUpperCase();
  switch (upper) {
    case 'VERIFIED':
    case 'CONFIRMED_CONFIG':
      return 'verified';
    case 'REJECTED':
    case 'FALSE_POSITIVE':
      return 'false_positive';
    case 'NEEDS_VERIFICATION':
    case 'POTENTIAL_VULNERABILITY':
    case 'HYPOTHESIS':
      return 'needs_verification';
    case 'INCONCLUSIVE':
      return 'inconclusive';
    case 'DECLINED':
    case 'REFUSED':
    case 'HEDGED':
      return 'declined';
    case 'DISCOVERED':
    default:
      return 'discovered';
  }
}

/**
 * Converts a deterministic passive FindingDraft or Prisma Finding into a NormalizedFinding.
 */
export function normalizePassiveFinding(
  finding: FindingDraft | PrismaFinding,
  targetUrl: string,
  sessionId?: string
): NormalizedFinding {
  const isPrisma = 'id' in finding && typeof (finding as PrismaFinding).id === 'string';
  const cwe = finding.cweId ? [finding.cweId] : [];
  const status = normalizeStatus(finding.verificationStatus);

  return {
    id: isPrisma ? (finding as PrismaFinding).id : randomUUID(),
    title: finding.title,
    severity: normalizeSeverity(finding.severity),
    status,
    target: targetUrl,
    endpoint: ((finding.evidence as any)?.endpoint as string) || '/',
    method: ((finding.evidence as any)?.method as string) || 'GET',
    cwe,
    owasp_category: finding.category || 'GENERAL_SECURITY',
    description: finding.description,
    evidence: Array.isArray(finding.evidence) ? finding.evidence : [finding.evidence],
    reproduction_steps: [
      `1. Request ${((finding.evidence as any)?.endpoint as string) || targetUrl}`,
      `2. Observe response configuration in session ${sessionId || 'current'}`,
    ],
    impact: finding.impact,
    remediation: finding.remediation,
    confidence: finding.confidence === 'CERTAIN' ? 100 : finding.confidence === 'HIGH' ? 85 : 60,
    source_agent: 'Agent 2 — Web Security',
    source_tool: 'passive_engine',
    created_at: isPrisma ? (finding as PrismaFinding).createdAt.toISOString() : new Date().toISOString(),
    verified_at: status === 'verified' ? new Date().toISOString() : null,
  };
}

/**
 * Converts an AI hypothesis row into a NormalizedFinding.
 */
export function normalizeAiHypothesis(
  hypothesis: PrismaAiHypothesis,
  targetUrl: string,
  evidenceList: Evidence[] = []
): NormalizedFinding {
  const status = normalizeStatus(hypothesis.verificationStatus);
  const matchingEvidence = evidenceList.filter((e) => hypothesis.supportingEvidenceIds.includes(e.id));

  return {
    id: hypothesis.id,
    title: hypothesis.title,
    severity: normalizeSeverity(hypothesis.risk),
    status,
    target: targetUrl,
    endpoint: hypothesis.affectedEndpoint,
    method: 'GET',
    cwe: hypothesis.cweCategory ? [hypothesis.cweCategory] : [],
    owasp_category: hypothesis.claimType,
    description: hypothesis.attackMechanism || hypothesis.title,
    evidence: matchingEvidence.length > 0 ? matchingEvidence : hypothesis.supportingEvidenceIds.map((id) => ({ id })),
    reproduction_steps: hypothesis.verificationNotes ? [hypothesis.verificationNotes] : [],
    impact: hypothesis.potentialImpact || '',
    remediation: hypothesis.suggestedRemediation || '',
    confidence: hypothesis.confidence === 'HIGH' ? 85 : hypothesis.confidence === 'MEDIUM' ? 60 : 40,
    source_agent: 'DeepHat-V1-7B Investigation',
    source_tool: hypothesis.claimType,
    created_at: hypothesis.createdAt.toISOString(),
    verified_at: status === 'verified' ? new Date().toISOString() : null,
  };
}

/**
 * Deduplicates findings across passive scanners, AI hypotheses, and external tools.
 * Groups findings by (target + endpoint + normalized title/cwe).
 */
export function deduplicateFindings(findings: NormalizedFinding[]): NormalizedFinding[] {
  const map = new Map<string, NormalizedFinding>();

  for (const finding of findings) {
    const key = `${finding.target}::${finding.endpoint}::${finding.cwe.sort().join(',') || finding.title.toLowerCase().trim()}`;

    if (!map.has(key)) {
      map.set(key, { ...finding });
      continue;
    }

    const existing = map.get(key)!;

    // Severity promotion: choose higher severity
    const severityRank: Record<FindingSeverity, number> = {
      critical: 5,
      high: 4,
      medium: 3,
      low: 2,
      informational: 1,
    };
    if (severityRank[finding.severity] > severityRank[existing.severity]) {
      existing.severity = finding.severity;
    }

    // Status promotion: verified > needs_verification > discovered > false_positive
    const statusRank: Record<FindingStatus, number> = {
      verified: 4,
      needs_verification: 3,
      inconclusive: 2,
      discovered: 1,
      false_positive: 0,
      declined: 0,
    };
    if (statusRank[finding.status] > statusRank[existing.status]) {
      existing.status = finding.status;
      if (finding.verified_at) existing.verified_at = finding.verified_at;
    }

    // Confidence: take the highest
    if (finding.confidence > existing.confidence) {
      existing.confidence = finding.confidence;
    }

    // Merge evidence without duplicates
    const existingIds = new Set(existing.evidence.map((e) => (typeof e === 'object' && e?.id ? e.id : JSON.stringify(e))));
    for (const ev of finding.evidence) {
      const id = typeof ev === 'object' && ev?.id ? ev.id : JSON.stringify(ev);
      if (!existingIds.has(id)) {
        existing.evidence.push(ev);
        existingIds.add(id);
      }
    }

    // Merge reproduction steps
    for (const step of finding.reproduction_steps) {
      if (!existing.reproduction_steps.includes(step)) {
        existing.reproduction_steps.push(step);
      }
    }

    map.set(key, existing);
  }

  return [...map.values()];
}

