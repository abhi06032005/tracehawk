import { describe, expect, it, vi } from 'vitest';
import { VerificationEngine, VerificationContext } from './verifier.js';
import type { NormalizedFinding } from './findings.js';

describe('VerificationEngine', () => {
  const allowedOrigins = ['http://127.0.0.1:3000'];

  const makeCtx = (overrides: Partial<VerificationContext> = {}): VerificationContext => ({
    allowedOrigins,
    authorized: true,
    activeTests: true,
    signal: new AbortController().signal,
    remainingBudget: 5,
    reserveBudget: vi.fn(),
    ...overrides,
  });

  const baseFinding: NormalizedFinding = {
    id: '11111111-1111-4111-8111-111111111111',
    title: 'Missing Content Security Policy (CSP)',
    severity: 'medium',
    status: 'needs_verification',
    target: 'http://127.0.0.1:3000',
    endpoint: '/index.html',
    method: 'GET',
    cwe: ['CWE-693'],
    owasp_category: 'HEADERS',
    description: 'CSP missing',
    evidence: [{ responseHeaders: { 'content-type': 'text/html' } }],
    reproduction_steps: [],
    impact: 'Potential XSS',
    remediation: 'Add CSP',
    confidence: 60,
    source_agent: 'Agent 2',
    source_tool: 'rules',
    created_at: new Date().toISOString(),
    verified_at: null,
  };

  it('verifies missing CSP when responseHeaders in evidence omit CSP', async () => {
    const { updatedFinding, proof } = await VerificationEngine.verifyFinding(baseFinding, makeCtx());
    expect(updatedFinding.status).toBe('verified');
    expect(updatedFinding.confidence).toBe(95);
    expect(proof.status).toBe('verified');
    expect(proof.observations.result).toContain('missing or ineffective');
  });

  it('refutes finding as false_positive when CSP is actually present in evidence', async () => {
    const findingWithCsp: NormalizedFinding = {
      ...baseFinding,
      evidence: [{ responseHeaders: { 'content-security-policy': "default-src 'self'" } }],
    };

    const { updatedFinding, proof } = await VerificationEngine.verifyFinding(findingWithCsp, makeCtx());
    expect(updatedFinding.status).toBe('false_positive');
    expect(updatedFinding.confidence).toBe(10);
    expect(proof.status).toBe('false_positive');
  });

  it('verifies CORS vulnerability when arbitrary origin reflected with credentials: true', async () => {
    const corsFinding: NormalizedFinding = {
      ...baseFinding,
      title: 'Permissive CORS Misconfiguration',
      endpoint: '/api/user/data',
      owasp_category: 'CORS',
      cwe: ['CWE-942'],
      evidence: [],
    };

    const mockFetch = vi.fn().mockResolvedValue({
      status: 200,
      headers: new Headers({
        'access-control-allow-origin': 'https://security-verify.invalid',
        'access-control-allow-credentials': 'true',
      }),
    });

    const { updatedFinding, proof } = await VerificationEngine.verifyFinding(
      corsFinding,
      makeCtx({ fetchTarget: mockFetch })
    );

    expect(updatedFinding.status).toBe('verified');
    expect(updatedFinding.confidence).toBe(95);
    expect(proof.status).toBe('verified');
    expect(proof.explanation).toContain('reflects arbitrary test Origin');
  });

  it('identifies CORS wildcard without credentials as false_positive', async () => {
    const corsFinding: NormalizedFinding = {
      ...baseFinding,
      title: 'Permissive CORS Misconfiguration',
      endpoint: '/api/public/data',
      owasp_category: 'CORS',
      cwe: ['CWE-942'],
      evidence: [],
    };

    const mockFetch = vi.fn().mockResolvedValue({
      status: 200,
      headers: new Headers({
        'access-control-allow-origin': '*',
      }),
    });

    const { updatedFinding, proof } = await VerificationEngine.verifyFinding(
      corsFinding,
      makeCtx({ fetchTarget: mockFetch })
    );

    expect(updatedFinding.status).toBe('false_positive');
    expect(proof.status).toBe('false_positive');
    expect(proof.explanation).toContain('wildcard * without credentials');
  });

  it('identifies active rate-limiting as false_positive if 429 received', async () => {
    const rateFinding: NormalizedFinding = {
      ...baseFinding,
      title: 'Missing Rate Limiting on Login',
      endpoint: '/api/login',
      owasp_category: 'API',
      cwe: ['CWE-770'],
      evidence: [],
    };

    const mockFetch = vi.fn()
      .mockResolvedValueOnce({ status: 200 })
      .mockResolvedValueOnce({ status: 429 });

    const { updatedFinding, proof } = await VerificationEngine.verifyFinding(
      rateFinding,
      makeCtx({ fetchTarget: mockFetch })
    );

    expect(updatedFinding.status).toBe('false_positive');
    expect(proof.status).toBe('false_positive');
    expect(proof.explanation).toContain('HTTP 429 Too Many Requests');
  });
});

