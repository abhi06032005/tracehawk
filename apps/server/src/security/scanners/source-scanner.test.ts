import { describe, expect, it, vi } from 'vitest';
import { SourceSecurityScanner } from './source-scanner.js';
import { SemgrepScannerAdapter } from './semgrep.js';
import { TrivyScannerAdapter } from './trivy.js';
import { GitleaksScannerAdapter } from './gitleaks.js';

describe('SourceSecurityScanner', () => {
  it('throws an error if target directory does not exist', async () => {
    await expect(
      SourceSecurityScanner.scanDirectory('d:/non-existent-directory-12345')
    ).rejects.toThrow(/not an accessible directory/);
  });

  it('runs enabled scanners gracefully even when tools are not installed', async () => {
    // Current host does not have semgrep/trivy/gitleaks in PATH,
    // so this tests the real graceful fallback path!
    const summary = await SourceSecurityScanner.scanDirectory('.', {
      enableSemgrep: true,
      enableTrivy: true,
      enableGitleaks: true,
      timeoutMs: 3000,
    });

    expect(summary.targetDir).toBeDefined();
    expect(summary.scannersExecuted.length).toBe(3);
    for (const s of summary.scannersExecuted) {
      expect(['semgrep', 'trivy', 'gitleaks']).toContain(s.name);
      // When not installed, available is false and error explains missing CLI
      if (!s.available) {
        expect(s.error).toMatch(/not installed/);
      }
    }
  });

  it('aggregates findings from mock adapters correctly', async () => {
    vi.spyOn(SemgrepScannerAdapter, 'scan').mockResolvedValue({
      available: true,
      findings: [
        {
          id: '11111111-1111-4111-8111-111111111111',
          title: 'javascript.express.security.audit.xss',
          severity: 'high',
          status: 'needs_verification',
          target: '.',
          endpoint: 'src/routes/api.ts:42',
          method: 'STATIC_SOURCE',
          cwe: ['CWE-79'],
          owasp_category: 'A03:2021-Injection',
          description: 'Reflected parameter in response',
          evidence: [],
          reproduction_steps: [],
          impact: 'XSS',
          remediation: 'Sanitize output',
          confidence: 80,
          source_agent: 'Agent 4',
          source_tool: 'semgrep',
          created_at: new Date().toISOString(),
          verified_at: null,
        },
      ],
    });

    vi.spyOn(TrivyScannerAdapter, 'scan').mockResolvedValue({
      available: true,
      findings: [
        {
          id: '22222222-2222-4222-8222-222222222222',
          title: 'CVE-2024-1234 in express (4.18.0)',
          severity: 'medium',
          status: 'needs_verification',
          target: '.',
          endpoint: 'package.json:express',
          method: 'DEPENDENCY_SCA',
          cwe: ['CWE-1395'],
          owasp_category: 'A06:2021-Vulnerable and Outdated Components',
          description: 'Known advisory',
          evidence: [],
          reproduction_steps: [],
          impact: 'Vulnerability in express',
          remediation: 'Upgrade express',
          confidence: 90,
          source_agent: 'Agent 4',
          source_tool: 'trivy',
          created_at: new Date().toISOString(),
          verified_at: null,
        },
      ],
    });

    vi.spyOn(GitleaksScannerAdapter, 'scan').mockResolvedValue({
      available: true,
      findings: [
        {
          id: '33333333-3333-4333-8333-333333333333',
          title: 'Exposed Credential: AWS Access Token',
          severity: 'critical',
          status: 'needs_verification',
          target: '.',
          endpoint: '.env:5',
          method: 'SECRET_SCAN',
          cwe: ['CWE-798'],
          owasp_category: 'A07:2021-Identification and Authentication Failures',
          description: 'Hardcoded key in .env',
          evidence: [],
          reproduction_steps: [],
          impact: 'Credential leak',
          remediation: 'Rotate key',
          confidence: 95,
          source_agent: 'Agent 4',
          source_tool: 'gitleaks',
          created_at: new Date().toISOString(),
          verified_at: null,
        },
      ],
    });

    const summary = await SourceSecurityScanner.scanDirectory('.', {
      enableSemgrep: true,
      enableTrivy: true,
      enableGitleaks: true,
    });

    expect(summary.totalFindings).toBe(3);
    const severities = summary.findings.map((f) => f.severity);
    expect(severities).toContain('high');
    expect(severities).toContain('medium');
    expect(severities).toContain('critical');
  });
});

