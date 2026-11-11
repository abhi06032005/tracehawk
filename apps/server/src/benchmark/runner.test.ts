import { describe, expect, it, vi, beforeEach } from 'vitest';
import { BenchmarkRunner } from './runner.js';
import { BenchmarkReporter } from './reporter.js';
import { ModelProviderRegistry } from './providers/registry.js';
import type { ModelProvider, GroundTruthFixture } from './types.js';

describe('BenchmarkRunner & BenchmarkReporter', () => {
  const sampleFixture: GroundTruthFixture = {
    id: 'test-fixture-01',
    name: 'Unit Test Fixture',
    targetUrl: 'http://127.0.0.1:3000',
    evidence: {
      targetUrl: 'http://127.0.0.1:3000',
      endpointInventory: [{ method: 'GET', url: 'http://127.0.0.1:3000/' }],
      exchanges: [],
    },
    groundTruthVulnerabilities: [
      {
        id: 'GT-01',
        title: 'Missing Content Security Policy (CSP)',
        endpoint: '/',
        cwe: 'CWE-693',
        category: 'HEADERS',
        expectedFound: true,
      },
      {
        id: 'GT-02',
        title: 'BOLA / IDOR in User Profile',
        endpoint: '/rest/user/profile',
        cwe: 'CWE-284',
        category: 'BOLA',
        expectedFound: true,
      },
    ],
  };

  const mockProvider: ModelProvider = {
    id: 'mock-model',
    name: 'Mock Test Model',
    defaultModel: 'mock-v1',
    analyze: vi.fn().mockImplementation(async (_bundle, promptTpl) => ({
      providerId: 'mock-model',
      modelName: 'mock-v1',
      promptVariantId: promptTpl.id,
      rawText: '{"hypotheses": [{"title": "Missing Content Security Policy", "affectedEndpoint": "/", "claimType": "missing_csp", "cweCategory": "CWE-693", "risk": "MEDIUM", "confidence": "HIGH"}]}',
      promptText: '...',
      latencyMs: 150,
      tokenUsage: { promptTokens: 100, completionTokens: 40, totalTokens: 140 },
      estimatedCostUsd: 0.0001,
      timestamp: new Date().toISOString(),
      isRefusal: false,
      parsedHypotheses: [
        {
          title: 'Missing Content Security Policy',
          affectedEndpoint: '/',
          claimType: 'missing_csp',
          cweCategory: 'CWE-693',
          risk: 'MEDIUM',
          confidence: 'HIGH',
          rawConfidenceText: 'HIGH',
        },
      ],
    })),
  };

  beforeEach(() => {
    ModelProviderRegistry.registerProvider('mock-model', () => mockProvider);
  });

  it('runs complete benchmark across prompt variants and repeats with attribution', async () => {
    const result = await BenchmarkRunner.run({
      fixture: sampleFixture,
      models: ['mock-model'],
      promptVariants: ['default', 'correctness-review'],
      repeats: 2,
    });

    expect(result.fixtureId).toBe('test-fixture-01');
    expect(result.modelsTested).toEqual(['mock-model']);
    expect(result.promptVariantsTested).toEqual(['default', 'correctness-review']);
    expect(result.repeats).toBe(2);

    // Total runs = 1 model * 2 variants * 2 repeats = 4 runs
    expect(result.runs).toHaveLength(4);

    // Verify per-finding model attribution
    for (const run of result.runs) {
      expect(run.findings.length).toBeGreaterThan(0);
      const finding = run.findings[0];
      expect(finding.source_model).toBe('mock-v1');
      expect(finding.prompt_variant_id).toBeDefined();
      expect(finding.raw_confidence_text).toBe('HIGH');
    }

    // Verify aggregates
    expect(result.aggregates).toHaveLength(2); // 1 model * 2 variants
    for (const agg of result.aggregates) {
      expect(agg.totalRuns).toBe(2);
      expect(agg.vulnerabilityHitRates['GT-01'].hitRatePercent).toBe(100);
      expect(agg.vulnerabilityHitRates['GT-02'].hitRatePercent).toBe(0);
    }

    // Verify comparison table
    expect(result.comparisonTable.length).toBe(4); // 2 variants * 2 GT items
  });

  it('generates Markdown and JSON comparison reports correctly', async () => {
    const result = await BenchmarkRunner.run({
      fixture: sampleFixture,
      models: ['mock-model'],
      promptVariants: ['default'],
      repeats: 1,
    });

    const md = BenchmarkReporter.generateMarkdown(result);
    expect(md).toContain('# TraceHawk Model Security Benchmark Comparison Report');
    expect(md).toContain('mock-v1');
    expect(md).toContain('Overall Model Performance Summary');
    expect(md).toContain('Granular Vulnerability Detection Matrix');
    expect(md).toContain('`CONFIRMED`');

    const json = BenchmarkReporter.generateJson(result);
    const parsed = JSON.parse(json);
    expect(parsed.fixtureId).toBe('test-fixture-01');
    expect(parsed.runs).toHaveLength(1);
    expect(parsed.comparisonTable).toBeDefined();
  });
});
