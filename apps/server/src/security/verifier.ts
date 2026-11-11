import { randomUUID } from 'node:crypto';
import type { NormalizedFinding, FindingStatus } from './findings.js';
import { SecurityPolicyGateway } from './policy.js';

export interface VerificationContext {
  allowedOrigins: string[];
  authorized: boolean;
  activeTests: boolean;
  signal: AbortSignal;
  remainingBudget: number;
  reserveBudget: () => Promise<void>;
  fetchTarget?: (url: string, init?: RequestInit) => Promise<Response>;
}

export interface VerificationProof {
  id: string;
  findingId: string;
  status: FindingStatus;
  claim: string;
  endpoint: string;
  observations: Record<string, unknown>;
  reproductionCurl?: string;
  timestamp: string;
  explanation: string;
}

export class VerificationEngine {
  /**
   * Deterministically verifies a candidate finding against the target application.
   * Eliminates false positives and collects verifiable evidence proofs.
   */
  public static async verifyFinding(
    finding: NormalizedFinding,
    ctx: VerificationContext
  ): Promise<{ updatedFinding: NormalizedFinding; proof: VerificationProof }> {
    ctx.signal.throwIfAborted();

    // 1. Check if finding is already in a definitive state
    if (finding.status === 'declined') {
      return {
        updatedFinding: finding,
        proof: {
          id: randomUUID(),
          findingId: finding.id,
          status: 'declined',
          claim: finding.title,
          endpoint: finding.endpoint,
          observations: { note: 'Model refused or hedged; skipped verification.' },
          timestamp: new Date().toISOString(),
          explanation: 'Finding was marked as declined by the refusal classifier.',
        },
      };
    }

    if (finding.status === 'verified' && finding.evidence.length > 0) {
      return {
        updatedFinding: finding,
        proof: {
          id: randomUUID(),
          findingId: finding.id,
          status: 'verified',
          claim: finding.title,
          endpoint: finding.endpoint,
          observations: { note: 'Finding already verified by previous evidence.' },
          timestamp: new Date().toISOString(),
          explanation: 'Retaining established verification proof.',
        },
      };
    }

    // 2. Security header verification (deterministic, passive/offline evidence)
    if (finding.owasp_category === 'HEADERS' || finding.cwe.includes('CWE-693')) {
      return this.verifySecurityHeaders(finding);
    }

    // 3. CORS misconfiguration verification
    if (finding.owasp_category === 'CORS' || finding.cwe.includes('CWE-942')) {
      return this.verifyCorsConfiguration(finding, ctx);
    }

    // 4. Rate-limiting verification (requires active probing)
    if (finding.title.toLowerCase().includes('rate limit') || finding.cwe.includes('CWE-770')) {
      return this.verifyRateLimiting(finding, ctx);
    }

    // 5. Default fallback for unautomated or complex findings
    return {
      updatedFinding: {
        ...finding,
        status: 'needs_verification',
        confidence: Math.min(finding.confidence, 60),
      },
      proof: {
        id: randomUUID(),
        findingId: finding.id,
        status: 'needs_verification',
        claim: finding.title,
        endpoint: finding.endpoint,
        observations: { reason: 'Automated reproduction proof generator not registered for this claim type.' },
        timestamp: new Date().toISOString(),
        explanation: 'Requires manual verification or specialized test scenario.',
      },
    };
  }

  /**
   * Verifies missing security headers by inspecting recorded response evidence.
   */
  private static verifySecurityHeaders(
    finding: NormalizedFinding
  ): { updatedFinding: NormalizedFinding; proof: VerificationProof } {
    const rawHeaders = finding.evidence.find((e) => e.responseHeaders)?.responseHeaders || {};
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(rawHeaders)) {
      headers[k.toLowerCase()] = String(v);
    }

    const titleLower = finding.title.toLowerCase();
    let isConfirmed = false;
    let headerName = '';

    if (titleLower.includes('csp') || titleLower.includes('content security policy')) {
      headerName = 'content-security-policy';
      isConfirmed = !headers['content-security-policy'];
    } else if (titleLower.includes('hsts') || titleLower.includes('strict-transport')) {
      headerName = 'strict-transport-security';
      isConfirmed = !headers['strict-transport-security'];
    } else if (titleLower.includes('nosniff') || titleLower.includes('x-content-type')) {
      headerName = 'x-content-type-options';
      isConfirmed = headers['x-content-type-options'] !== 'nosniff';
    } else if (titleLower.includes('frame') || titleLower.includes('clickjacking')) {
      headerName = 'x-frame-options';
      isConfirmed = !headers['x-frame-options'] && !headers['content-security-policy']?.includes('frame-ancestors');
    }

    const status: FindingStatus = isConfirmed ? 'verified' : 'false_positive';
    const confidence = isConfirmed ? 95 : 10;

    const proof: VerificationProof = {
      id: randomUUID(),
      findingId: finding.id,
      status,
      claim: finding.title,
      endpoint: finding.endpoint,
      observations: {
        checkedHeader: headerName,
        headerObserved: headers[headerName] || null,
        result: isConfirmed ? 'Header is missing or ineffective' : 'Header is properly configured',
      },
      timestamp: new Date().toISOString(),
      explanation: isConfirmed
        ? `Deterministic verification confirmed missing ${headerName} header.`
        : `Verification refuted finding: ${headerName} is already configured.`,
    };

    return {
      updatedFinding: {
        ...finding,
        status,
        confidence,
        verified_at: isConfirmed ? new Date().toISOString() : null,
        evidence: [...finding.evidence, proof],
      },
      proof,
    };
  }

  /**
   * Verifies CORS policy by probing with an untrusted origin if active testing is enabled.
   */
  private static async verifyCorsConfiguration(
    finding: NormalizedFinding,
    ctx: VerificationContext
  ): Promise<{ updatedFinding: NormalizedFinding; proof: VerificationProof }> {
    const targetUrl = finding.endpoint.startsWith('http') ? finding.endpoint : `${finding.target}${finding.endpoint.startsWith('/') ? '' : '/'}${finding.endpoint}`;

    if (!ctx.activeTests || ctx.remainingBudget <= 0) {
      return {
        updatedFinding: { ...finding, status: 'needs_verification' },
        proof: {
          id: randomUUID(),
          findingId: finding.id,
          status: 'needs_verification',
          claim: finding.title,
          endpoint: finding.endpoint,
          observations: { limitation: 'Active probe skipped: active testing disabled or budget depleted.' },
          timestamp: new Date().toISOString(),
          explanation: 'CORS reflection probe requires active test authorization.',
        },
      };
    }

    const scopeCheck = SecurityPolicyGateway.isTargetInScope(targetUrl, ctx.allowedOrigins);
    if (!scopeCheck.allowed) {
      return {
        updatedFinding: { ...finding, status: 'inconclusive' },
        proof: {
          id: randomUUID(),
          findingId: finding.id,
          status: 'inconclusive',
          claim: finding.title,
          endpoint: finding.endpoint,
          observations: { reason: scopeCheck.reason },
          timestamp: new Date().toISOString(),
          explanation: 'Target endpoint out of scope for verification.',
        },
      };
    }

    try {
      ctx.remainingBudget--;
      await ctx.reserveBudget();

      const fetcher = ctx.fetchTarget || fetch;
      const testOrigin = 'https://security-verify.invalid';
      const res = await fetcher(targetUrl, {
        method: 'OPTIONS',
        headers: {
          Origin: testOrigin,
          'Access-Control-Request-Method': 'GET',
        },
        signal: AbortSignal.any([ctx.signal, AbortSignal.timeout(5000)]),
      });

      const allowOrigin = res.headers.get('access-control-allow-origin');
      const allowCreds = res.headers.get('access-control-allow-credentials');

      // Exploitable CORS: reflects arbitrary origin AND allows credentials
      const isExploitable = allowOrigin === testOrigin && allowCreds === 'true';
      const isWildcardWithoutCreds = allowOrigin === '*' && allowCreds !== 'true';

      let status: FindingStatus = 'inconclusive';
      let explanation = '';

      if (isExploitable) {
        status = 'verified';
        explanation = 'Target reflects arbitrary test Origin with Access-Control-Allow-Credentials: true.';
      } else if (isWildcardWithoutCreds) {
        status = 'false_positive';
        explanation = 'Origin allows wildcard * without credentials; non-sensitive public resource.';
      } else if (!allowOrigin) {
        status = 'false_positive';
        explanation = 'Target does not return Access-Control-Allow-Origin for untrusted origins.';
      }

      const proof: VerificationProof = {
        id: randomUUID(),
        findingId: finding.id,
        status,
        claim: finding.title,
        endpoint: targetUrl,
        observations: {
          testedOrigin: testOrigin,
          statusCode: res.status,
          allowOrigin,
          allowCredentials: allowCreds,
        },
        reproductionCurl: `curl -I -X OPTIONS "${targetUrl}" -H "Origin: ${testOrigin}"`,
        timestamp: new Date().toISOString(),
        explanation,
      };

      return {
        updatedFinding: {
          ...finding,
          status,
          confidence: status === 'verified' ? 95 : 15,
          verified_at: status === 'verified' ? new Date().toISOString() : null,
          evidence: [...finding.evidence, proof],
        },
        proof,
      };
    } catch (err: any) {
      return {
        updatedFinding: { ...finding, status: 'inconclusive' },
        proof: {
          id: randomUUID(),
          findingId: finding.id,
          status: 'inconclusive',
          claim: finding.title,
          endpoint: targetUrl,
          observations: { error: err.message },
          timestamp: new Date().toISOString(),
          explanation: 'Verification probe failed due to network or timeout error.',
        },
      };
    }
  }

  /**
   * Verifies rate-limiting by sending a bounded burst of requests.
   */
  private static async verifyRateLimiting(
    finding: NormalizedFinding,
    ctx: VerificationContext
  ): Promise<{ updatedFinding: NormalizedFinding; proof: VerificationProof }> {
    const targetUrl = finding.endpoint.startsWith('http') ? finding.endpoint : `${finding.target}${finding.endpoint.startsWith('/') ? '' : '/'}${finding.endpoint}`;

    if (!ctx.activeTests || ctx.remainingBudget < 3) {
      return {
        updatedFinding: { ...finding, status: 'needs_verification' },
        proof: {
          id: randomUUID(),
          findingId: finding.id,
          status: 'needs_verification',
          claim: finding.title,
          endpoint: finding.endpoint,
          observations: { limitation: 'Requires at least 3 available request units in budget.' },
          timestamp: new Date().toISOString(),
          explanation: 'Insufficient budget to verify rate-limiting.',
        },
      };
    }

    try {
      const fetcher = ctx.fetchTarget || fetch;
      const responses: number[] = [];

      for (let i = 0; i < 3; i++) {
        ctx.remainingBudget--;
        await ctx.reserveBudget();

        const res = await fetcher(targetUrl, {
          method: 'GET',
          headers: { 'User-Agent': 'TraceHawk-Verification/2.0' },
          signal: AbortSignal.any([ctx.signal, AbortSignal.timeout(3000)]),
        });
        responses.push(res.status);

        if (res.status === 429) {
          break;
        }
      }

      const throttled = responses.includes(429);
      // If throttled, finding of "Missing Rate Limiting" is disproved -> false_positive
      // If not throttled, 3 requests is too small to prove absence -> inconclusive
      const status: FindingStatus = throttled ? 'false_positive' : 'inconclusive';
      const explanation = throttled
        ? 'Application returned HTTP 429 Too Many Requests; rate-limiting is active.'
        : 'Burst of 3 requests did not trigger HTTP 429; inconclusive without larger volume.';

      const proof: VerificationProof = {
        id: randomUUID(),
        findingId: finding.id,
        status,
        claim: finding.title,
        endpoint: targetUrl,
        observations: {
          probeStatuses: responses,
          totalProbes: responses.length,
          throttled,
        },
        timestamp: new Date().toISOString(),
        explanation,
      };

      return {
        updatedFinding: {
          ...finding,
          status,
          confidence: throttled ? 10 : 50,
          evidence: [...finding.evidence, proof],
        },
        proof,
      };
    } catch (err: any) {
      return {
        updatedFinding: { ...finding, status: 'inconclusive' },
        proof: {
          id: randomUUID(),
          findingId: finding.id,
          status: 'inconclusive',
          claim: finding.title,
          endpoint: targetUrl,
          observations: { error: err.message },
          timestamp: new Date().toISOString(),
          explanation: 'Rate-limit probe encountered an error.',
        },
      };
    }
  }
}

