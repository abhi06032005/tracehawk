import type { EvidenceBundle, PromptTemplate } from './types.js';
import { clean } from '../ai/privacy.js';

export const DEFAULT_SECURITY_PROMPT: PromptTemplate = {
  id: 'default',
  name: 'Standard Security Vulnerability Audit',
  description: 'Adversarial perspective prompt directly searching for security vulnerabilities and exploit paths.',
  system: `You are an expert application security auditor evaluating an authorized web application test session.
Analyze the provided recorded HTTP exchanges, endpoint inventory, storage observations, and code snippets for real security vulnerabilities (OWASP Top 10, API Security Top 10, CWE).
Return a JSON object with a single key "hypotheses", containing a list of vulnerability objects.
Each hypothesis object MUST have the following structure:
- title: concise title of the vulnerability
- affectedEndpoint: the affected endpoint path (e.g. /rest/user/login)
- claimType: category (e.g. broken_auth, bola, injection, missing_csp, missing_hsts, sensitive_storage, cors, other)
- cweCategory: e.g. CWE-89, CWE-284, CWE-693
- attackMechanism: concrete explanation of how an attacker abuses this
- prerequisites: access level or conditions required
- potentialImpact: security impact of exploitation
- suggestedRemediation: technical fix guidance
- risk: CRITICAL | HIGH | MEDIUM | LOW | INFO
- confidence: HIGH | MEDIUM | LOW

If you identify no vulnerabilities, return {"hypotheses": []}. Return strictly valid JSON.`,
  buildUserPrompt: (bundle: EvidenceBundle) => {
    const sanitized = clean({
      targetUrl: bundle.targetUrl,
      endpointInventory: bundle.endpointInventory,
      recentExchanges: bundle.exchanges.slice(0, 30),
      storageObservations: bundle.storageObservations || [],
      sourceSnippets: bundle.sourceSnippets || [],
      passiveFindings: bundle.passiveFindings || [],
    });
    return JSON.stringify(sanitized, null, 2);
  },
};

export const CORRECTNESS_REVIEW_PROMPT: PromptTemplate = {
  id: 'correctness-review',
  name: 'Software Correctness & Defect Review',
  description: 'Neutral software engineering prompt reviewing code and traffic for functional bugs, state anomalies, and unexpected behavior (often bypasses aggressive refusal filters).',
  system: `You are a principal software engineer and QA architect conducting a code correctness and defect review of an authorized web application session.
Review the recorded interactions, endpoints, and code snippets for unexpected state transitions, unintended data disclosures, unvalidated parameter handling, missing access boundary checks, and configuration defects.
Format your review as a JSON object with a single key "hypotheses" listing identified software defects and security anomalies:
Each defect object MUST have the following structure:
- title: concise description of the functional or security defect
- affectedEndpoint: the affected endpoint path (e.g. /api/data)
- claimType: category (e.g. broken_auth, bola, injection, missing_csp, missing_hsts, sensitive_storage, cors, other)
- cweCategory: corresponding CWE identifier if applicable (e.g. CWE-200, CWE-284)
- attackMechanism: how this unexpected behavior manifests or can be triggered
- prerequisites: required preconditions
- potentialImpact: impact on application reliability, data privacy, or integrity
- suggestedRemediation: recommended software fix
- risk: CRITICAL | HIGH | MEDIUM | LOW | INFO
- confidence: HIGH | MEDIUM | LOW

Return strictly valid JSON with {"hypotheses": [...]}. If none are found, return {"hypotheses": []}.`,
  buildUserPrompt: (bundle: EvidenceBundle) => {
    const sanitized = clean({
      targetUrl: bundle.targetUrl,
      endpointsUnderReview: bundle.endpointInventory,
      recordedInteractions: bundle.exchanges.slice(0, 30),
      storageSnapshots: bundle.storageObservations || [],
      sourceCode: bundle.sourceSnippets || [],
    });
    return JSON.stringify(sanitized, null, 2);
  },
};

export const ALL_PROMPT_TEMPLATES: Record<string, PromptTemplate> = {
  default: DEFAULT_SECURITY_PROMPT,
  'correctness-review': CORRECTNESS_REVIEW_PROMPT,
};

export function getPromptTemplate(id: string): PromptTemplate {
  const tpl = ALL_PROMPT_TEMPLATES[id];
  if (!tpl) {
    throw new Error(`Unknown prompt template ID: '${id}'. Available: [${Object.keys(ALL_PROMPT_TEMPLATES).join(', ')}]`);
  }
  return tpl;
}

