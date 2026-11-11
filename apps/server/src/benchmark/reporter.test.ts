import { describe, it, expect } from 'vitest';
import { BenchmarkReporter } from './reporter.js';
import type { BenchmarkResult } from './types.js';

describe('BenchmarkReporter', () => {
  const sampleResult: BenchmarkResult = {
    runId: 'test-run-123',
    timestamp: '2026-11-09T18:00:00.000Z',
    fixtureId: 'test-fixture',
    fixtureName: 'Test Benchmark Fixture',
    targetUrl: 'http://127.0.0.1:3000',
    modelsTested: ['groq', 'gemini'],
    promptVariantsTested: ['default'],
    repeats: 1,
    runs: [
      {
        runId: 'test-run-123',
        providerId: 'groq',
        modelName: 'qwen/qwen3.8-27b',
        promptVariantId: 'default',
        repeatIndex: 1,
        latencyMs: 1200,
        tokenUsage: { promptTokens: 500, completionTokens: 200, totalTokens: 700 },
        estimatedCostUsd: 0.001,
        isRefusal: false,
        findings: [
          {
            id: 'find-1',
            title: 'SQL Injection in Search',
            severity: 'critical',
            status: 'verified',
            target: 'http://127.0.0.1:3000',
            endpoint: '/rest/products/search',
            method: 'GET',
            cwe: ['CWE-89'],
            owasp_category: 'INJECTION',
            description: 'Unsanitized input passed directly to database query.',
            evidence: [],
            reproduction_steps: ['Send payload to q parameter'],
            impact: 'Data exfiltration',
            remediation: 'Use parameterized queries',
            confidence: 90,
            source_agent: 'Benchmark Model Provider',
            source_tool: 'groq',
            created_at: '2026-11-09T18:00:00.000Z',
            verified_at: '2026-11-09T18:00:01.000Z',
            source_model: 'qwen/qwen3.8-27b',
            raw_confidence_text: 'High confidence SQLi',
            prompt_variant_id: 'default',
            verifier_result: {
              status: 'VERIFIED',
              reason: 'Confirmed SQL error syntax response',
            },
          },
        ],
        truePositives: ['gt-sqli'],
        falsePositives: [],
        falseNegatives: [],
        declined: [],
        precision: 1.0,
        recall: 1.0,
        f1Score: 1.0,
        rawText: '{"findings": [{"title": "SQL Injection in Search"}]}',
      },
      {
        runId: 'test-run-123',
        providerId: 'gemini',
        modelName: 'gemini-flash-lite-latest',
        promptVariantId: 'default',
        repeatIndex: 1,
        latencyMs: 2500,
        tokenUsage: { promptTokens: 600, completionTokens: 150, totalTokens: 750 },
        estimatedCostUsd: 0.0005,
        isRefusal: false,
        findings: [
          {
            id: 'find-2',
            title: 'Missing Content Security Policy',
            severity: 'medium',
            status: 'verified',
            target: 'http://127.0.0.1:3000',
            endpoint: '/',
            method: 'GET',
            cwe: ['CWE-1021'],
            owasp_category: 'HEADERS',
            description: 'Missing CSP header allows unauthorized script injection.',
            evidence: [],
            reproduction_steps: ['Check response headers for Content-Security-Policy'],
            impact: 'XSS amplification',
            remediation: 'Add strict Content-Security-Policy header',
            confidence: 85,
            source_agent: 'Benchmark Model Provider',
            source_tool: 'gemini',
            created_at: '2026-11-09T18:00:00.000Z',
            verified_at: '2026-11-09T18:00:01.000Z',
            source_model: 'gemini-flash-lite-latest',
            raw_confidence_text: 'High confidence header finding',
            prompt_variant_id: 'default',
            verifier_result: {
              status: 'VERIFIED',
              reason: 'Header absent in response',
            },
          },
        ],
        truePositives: ['gt-csp'],
        falsePositives: [],
        falseNegatives: [],
        declined: [],
        precision: 1.0,
        recall: 1.0,
        f1Score: 1.0,
        rawText: '{"findings": [{"title": "Missing Content Security Policy"}]}',
      },
    ],
    comparisonTable: [
      {
        model: 'qwen/qwen3.8-27b',
        promptVariant: 'default',
        vulnerabilityClass: 'INJECTION',
        vulnerabilityTitle: 'SQL Injection in Product Search Query',
        status: 'confirmed',
        hitRate: '1/1 (100%)',
        avgLatencyMs: 1200,
        costPerRunUsd: 0.001,
      },
    ],
    aggregates: [
      {
        providerId: 'groq',
        modelName: 'qwen/qwen3.8-27b',
        promptVariantId: 'default',
        totalRuns: 1,
        refusalCount: 0,
        avgLatencyMs: 1200,
        avgPromptTokens: 500,
        avgCompletionTokens: 200,
        totalCostUsd: 0.001,
        avgPrecision: 1.0,
        avgRecall: 1.0,
        avgF1Score: 1.0,
        vulnerabilityHitRates: {},
      },
    ],
  };

  it('generates a comparison markdown report', () => {
    const md = BenchmarkReporter.generateMarkdown(sampleResult);
    expect(md).toContain('# TraceHawk Model Security Benchmark Comparison Report');
    expect(md).toContain('qwen/qwen3.8-27b');
    expect(md).toContain('100.0%');
  });

  it('generates individual reports for each model containing model-specific findings', () => {
    const individualReports = BenchmarkReporter.generateIndividualModelReports(sampleResult);

    expect(individualReports.size).toBe(2);
    expect(individualReports.has('qwen/qwen3.8-27b')).toBe(true);
    expect(individualReports.has('gemini-flash-lite-latest')).toBe(true);

    const groqReport = individualReports.get('qwen/qwen3.8-27b')!;
    expect(groqReport).toContain('# Security Audit & Finding Report: qwen/qwen3.8-27b');
    expect(groqReport).toContain('SQL Injection in Search');
    expect(groqReport).toContain('Unsanitized input passed directly to database query');
    expect(groqReport).toContain('Use parameterized queries');
    expect(groqReport).toContain('Confirmed SQL error syntax response');
    expect(groqReport).toContain('Raw Model Output Transcripts');

    const geminiReport = individualReports.get('gemini-flash-lite-latest')!;
    expect(geminiReport).toContain('# Security Audit & Finding Report: gemini-flash-lite-latest');
    expect(geminiReport).toContain('Missing Content Security Policy');
    expect(geminiReport).toContain('Add strict Content-Security-Policy header');
  });
});

