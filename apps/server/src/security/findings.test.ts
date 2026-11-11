import { describe, expect, it } from 'vitest';
import {
  normalizeSeverity,
  normalizeStatus,
  normalizePassiveFinding,
  normalizeAiHypothesis,
  deduplicateFindings,
  NormalizedFinding,
} from './findings.js';

describe('Findings Normalization & Deduplication', () => {
  describe('normalizeSeverity and normalizeStatus', () => {
    it('normalizes various casing for severity', () => {
      expect(normalizeSeverity('CRITICAL')).toBe('critical');
      expect(normalizeSeverity('High')).toBe('high');
      expect(normalizeSeverity('medium')).toBe('medium');
      expect(normalizeSeverity('low')).toBe('low');
      expect(normalizeSeverity('INFO')).toBe('informational');
      expect(normalizeSeverity('UNKNOWN')).toBe('informational');
    });

    it('normalizes status lifecycle transitions', () => {
      expect(normalizeStatus('VERIFIED')).toBe('verified');
      expect(normalizeStatus('CONFIRMED_CONFIG')).toBe('verified');
      expect(normalizeStatus('REJECTED')).toBe('false_positive');
      expect(normalizeStatus('FALSE_POSITIVE')).toBe('false_positive');
      expect(normalizeStatus('NEEDS_VERIFICATION')).toBe('needs_verification');
      expect(normalizeStatus('HYPOTHESIS')).toBe('needs_verification');
      expect(normalizeStatus('POTENTIAL_VULNERABILITY')).toBe('needs_verification');
      expect(normalizeStatus('INCONCLUSIVE')).toBe('inconclusive');
      expect(normalizeStatus('DISCOVERED')).toBe('discovered');
    });
  });

  describe('normalizePassiveFinding', () => {
    it('converts a deterministic passive draft to a normalized finding', () => {
      const draft = {
        title: 'Missing Content Security Policy (CSP) Header',
        category: 'HEADERS' as const,
        cweId: 'CWE-693',
        severity: 'MEDIUM' as const,
        confidence: 'HIGH' as const,
        verificationStatus: 'CONFIRMED_CONFIG' as const,
        description: 'Missing CSP allows potential content injection.',
        evidence: { endpoint: '/index.html', method: 'GET', responseHeaders: {} },
        impact: 'Attacker could execute XSS if an injection exists.',
        remediation: 'Configure a restrictive CSP.',
      };

      const normalized = normalizePassiveFinding(draft, 'http://127.0.0.1:3000');
      expect(normalized.title).toBe(draft.title);
      expect(normalized.severity).toBe('medium');
      expect(normalized.status).toBe('verified');
      expect(normalized.target).toBe('http://127.0.0.1:3000');
      expect(normalized.endpoint).toBe('/index.html');
      expect(normalized.cwe).toEqual(['CWE-693']);
      expect(normalized.confidence).toBe(85);
      expect(normalized.verified_at).not.toBeNull();
    });
  });

  describe('normalizeAiHypothesis', () => {
    it('converts an AI hypothesis row to a normalized finding', () => {
      const hyp = {
        id: '22222222-2222-4222-8222-222222222222',
        investigationId: 'inv-1',
        title: 'BOLA in User Profile Endpoint',
        affectedEndpoint: '/rest/user/profile',
        cweCategory: 'CWE-284',
        claimType: 'cross_account_access',
        risk: 'HIGH',
        attackMechanism: 'Modifying userId parameter in request returns other users data.',
        prerequisites: 'Valid user account session.',
        potentialImpact: 'Exposure of private user profile and order history.',
        suggestedRemediation: 'Validate session owner matches requested userId.',
        confidence: 'HIGH',
        verificationStatus: 'HYPOTHESIS',
        supportingEvidenceIds: ['ev-1', 'ev-2'],
        verificationNotes: 'Test with second test account.',
        createdAt: new Date('2026-10-28T12:00:00Z'),
      };

      const normalized = normalizeAiHypothesis(hyp as any, 'http://127.0.0.1:3000', [
        { id: 'ev-1', kind: 'http_exchange', endpoint: '/rest/user/profile', sourceIds: [], observations: {}, supports: [], refutes: [] },
      ]);

      expect(normalized.title).toBe(hyp.title);
      expect(normalized.severity).toBe('high');
      expect(normalized.status).toBe('needs_verification');
      expect(normalized.cwe).toEqual(['CWE-284']);
      expect(normalized.evidence).toHaveLength(1);
      expect(normalized.reproduction_steps).toEqual([hyp.verificationNotes]);
      expect(normalized.verified_at).toBeNull();
    });
  });

  describe('deduplicateFindings', () => {
    it('merges duplicate findings on the same endpoint and promotes verified status & highest severity', () => {
      const f1: NormalizedFinding = {
        id: '11111111-1111-4111-8111-111111111111',
        title: 'Missing CSP',
        severity: 'low',
        status: 'discovered',
        target: 'http://localhost:3000',
        endpoint: '/app',
        method: 'GET',
        cwe: ['CWE-693'],
        owasp_category: 'HEADERS',
        description: 'First discovery',
        evidence: [{ id: 'e1' }],
        reproduction_steps: ['Step 1'],
        impact: 'Low',
        remediation: 'Fix CSP',
        confidence: 50,
        source_agent: 'passive',
        source_tool: 'rules',
        created_at: new Date().toISOString(),
        verified_at: null,
      };

      const f2: NormalizedFinding = {
        id: '22222222-2222-4222-8222-222222222222',
        title: 'Missing CSP',
        severity: 'medium',
        status: 'verified',
        target: 'http://localhost:3000',
        endpoint: '/app',
        method: 'GET',
        cwe: ['CWE-693'],
        owasp_category: 'HEADERS',
        description: 'Second discovery with proof',
        evidence: [{ id: 'e2' }],
        reproduction_steps: ['Step 2'],
        impact: 'Medium',
        remediation: 'Fix CSP',
        confidence: 90,
        source_agent: 'verification_agent',
        source_tool: 'header_check',
        created_at: new Date().toISOString(),
        verified_at: '2026-10-28T12:05:00Z',
      };

      const deduplicated = deduplicateFindings([f1, f2]);
      expect(deduplicated).toHaveLength(1);
      const merged = deduplicated[0];
      expect(merged.severity).toBe('medium'); // promoted from low -> medium
      expect(merged.status).toBe('verified');  // promoted from discovered -> verified
      expect(merged.confidence).toBe(90);
      expect(merged.evidence).toHaveLength(2); // merged e1 and e2
      expect(merged.reproduction_steps).toEqual(['Step 1', 'Step 2']);
      expect(merged.verified_at).toBe('2026-10-28T12:05:00Z');
    });
  });
});

