import { describe, expect, it } from 'vitest';
import { ReportGenerator, ReportMetadata } from './generator.js';
import type { NormalizedFinding } from '../security/findings.js';

describe('ReportGenerator', () => {
  const metadata: ReportMetadata = {
    reportId: 'rep-001',
    projectName: 'OWASP Juice Shop Audit',
    targetUrl: 'http://127.0.0.1:3000',
    scanDate: '2026-11-07T12:00:00Z',
    scannerVersion: '2.0.0',
    executiveSummary: 'Automated AI security audit identified several high-impact vulnerabilities.',
  };

  const sampleFindings: NormalizedFinding[] = [
    {
      id: '11111111-1111-4111-8111-111111111111',
      title: 'Broken Object-Level Authorization (BOLA)',
      severity: 'high',
      status: 'verified',
      target: 'http://127.0.0.1:3000',
      endpoint: '/rest/user/profile',
      method: 'GET',
      cwe: ['CWE-284'],
      owasp_category: 'API1:2023-Broken Object Level Authorization',
      description: 'Arbitrary user profiles can be retrieved by swapping the ID parameter.',
      evidence: [{ exchangeId: 'ex-123', status: 200 }],
      reproduction_steps: ['GET /rest/user/profile?id=2 with Account 1 token'],
      impact: 'Cross-tenant data exposure',
      remediation: 'Validate session owner against queried object ID.',
      confidence: 95,
      source_agent: 'Agent 3 — API Security',
      source_tool: 'compare_test_account_access',
      created_at: '2026-11-07T12:01:00Z',
      verified_at: '2026-11-07T12:02:00Z',
    },
    {
      id: '22222222-2222-4222-8222-222222222222',
      title: 'Missing Content Security Policy',
      severity: 'medium',
      status: 'verified',
      target: 'http://127.0.0.1:3000',
      endpoint: '/',
      method: 'GET',
      cwe: ['CWE-693'],
      owasp_category: 'HEADERS',
      description: 'CSP header missing on root document',
      evidence: [],
      reproduction_steps: ['curl -I http://127.0.0.1:3000/'],
      impact: 'Defense-in-depth reduction against XSS',
      remediation: 'Configure Content-Security-Policy header.',
      confidence: 95,
      source_agent: 'Agent 2 — Web Security',
      source_tool: 'passive_engine',
      created_at: '2026-11-07T12:01:00Z',
      verified_at: '2026-11-07T12:02:00Z',
    },
  ];

  it('generates valid JSON report with accurate counts', () => {
    const jsonStr = ReportGenerator.generateJson(metadata, sampleFindings);
    const parsed = JSON.parse(jsonStr);

    expect(parsed.metadata.reportId).toBe('rep-001');
    expect(parsed.metadata.generator).toContain('DeepHat-V1-7B');
    expect(parsed.summary.bySeverity.high).toBe(1);
    expect(parsed.summary.bySeverity.medium).toBe(1);
    expect(parsed.summary.byStatus.verified).toBe(2);
    expect(parsed.findings).toHaveLength(2);
  });

  it('generates Markdown report with executive summary table and findings', () => {
    const md = ReportGenerator.generateMarkdown(metadata, sampleFindings);

    expect(md).toContain('# DeepHat Security Assessment Report');
    expect(md).toContain('**Target Application:** `http://127.0.0.1:3000`');
    expect(md).toContain('| **High** | 1 | 1 | 0 | 0 |');
    expect(md).toContain('### 1. Broken Object-Level Authorization (BOLA)');
    expect(md).toContain('- **OWASP Category:** API1:2023-Broken Object Level Authorization');
    expect(md).toContain('GET /rest/user/profile?id=2 with Account 1 token');
  });

  it('generates self-contained HTML report with CSS styles and badges', () => {
    const html = ReportGenerator.generateHtml(metadata, sampleFindings);

    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('<title>DeepHat Security Report — OWASP Juice Shop Audit</title>');
    expect(html).toContain('badge badge-high');
    expect(html).toContain('badge badge-verified');
    expect(html).toContain('Broken Object-Level Authorization (BOLA)');
  });
});
