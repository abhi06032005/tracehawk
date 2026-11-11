import { describe, expect, it } from 'vitest';
import { BenchmarkScorer } from './scorer.js';
import type { GroundTruthVulnerability, RawModelOutput } from './types.js';
import type { NormalizedFinding } from '../security/findings.js';

describe('BenchmarkScorer', () => {
  const groundTruthList: GroundTruthVulnerability[] = [
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
      title: 'BOLA in User Profile',
      endpoint: '/rest/user/profile',
      cwe: 'CWE-284',
      category: 'BOLA',
      expectedFound: true,
    },
    {
      id: 'GT-03',
      title: 'SQL Injection in Search Query',
      endpoint: '/rest/products/search',
      cwe: 'CWE-89',
      category: 'INJECTION',
      expectedFound: true,
    },
  ];

  const dummyRawOutput: RawModelOutput = {
    providerId: 'deephat',
    modelName: 'DeepHat-V1-7B',
    promptVariantId: 'default',
    rawText: '...',
    promptText: '...',
    latencyMs: 1200,
    tokenUsage: { promptTokens: 500, completionTokens: 100, totalTokens: 600 },
    estimatedCostUsd: 0,
    timestamp: new Date().toISOString(),
    isRefusal: false,
    parsedHypotheses: [],
  };

  it('correctly scores runs with true positives, false positives, and false negatives', () => {
    const verifiedFindings: NormalizedFinding[] = [
      // Matches GT-01 (TP)
      {
        id: 'f-1',
        title: 'Missing CSP Header',
        severity: 'medium',
        status: 'verified',
        target: 'http://localhost:3000',
        endpoint: '/',
        method: 'GET',
        cwe: ['CWE-693'],
        owasp_category: 'HEADERS',
        description: 'No CSP',
        evidence: [],
        reproduction_steps: [],
        impact: '',
        remediation: '',
        confidence: 90,
        source_agent: 'Agent',
        source_tool: 'tool',
        created_at: new Date().toISOString(),
        verified_at: new Date().toISOString(),
      },
      // Matches GT-02 (TP)
      {
        id: 'f-2',
        title: 'Broken Object Level Authorization (BOLA)',
        severity: 'high',
        status: 'verified',
        target: 'http://localhost:3000',
        endpoint: '/rest/user/profile',
        method: 'GET',
        cwe: ['CWE-284'],
        owasp_category: 'API1:2023',
        description: 'BOLA',
        evidence: [],
        reproduction_steps: [],
        impact: '',
        remediation: '',
        confidence: 90,
        source_agent: 'Agent',
        source_tool: 'tool',
        created_at: new Date().toISOString(),
        verified_at: new Date().toISOString(),
      },
      // False Positive (FP) - not in ground truth
      {
        id: 'f-3',
        title: 'Arbitrary File Upload',
        severity: 'critical',
        status: 'verified',
        target: 'http://localhost:3000',
        endpoint: '/upload',
        method: 'POST',
        cwe: ['CWE-434'],
        owasp_category: 'UPLOAD',
        description: 'Upload flaw',
        evidence: [],
        reproduction_steps: [],
        impact: '',
        remediation: '',
        confidence: 80,
        source_agent: 'Agent',
        source_tool: 'tool',
        created_at: new Date().toISOString(),
        verified_at: new Date().toISOString(),
      },
    ];

    const scored = BenchmarkScorer.scoreRun(
      'run-01',
      dummyRawOutput,
      verifiedFindings,
      groundTruthList,
      1
    );

    expect(scored.truePositives).toHaveLength(2); // GT-01 and GT-02
    expect(scored.truePositives).toContain('GT-01');
    expect(scored.truePositives).toContain('GT-02');
    expect(scored.falsePositives).toHaveLength(1); // /upload finding
    expect(scored.falseNegatives).toHaveLength(1); // GT-03 missed
    expect(scored.falseNegatives).toContain('GT-03');

    // TP = 2, FP = 1, FN = 1
    // Precision = 2 / (2 + 1) = 0.667
    // Recall = 2 / (2 + 1) = 0.667
    // F1 = 0.667
    expect(scored.precision).toBeCloseTo(0.667, 2);
    expect(scored.recall).toBeCloseTo(0.667, 2);
    expect(scored.f1Score).toBeCloseTo(0.667, 2);
  });

  it('marks all expected vulnerabilities as declined if model refused', () => {
    const refusalOutput: RawModelOutput = {
      ...dummyRawOutput,
      isRefusal: true,
      refusalReason: 'Model safety filter refusal',
    };

    const scored = BenchmarkScorer.scoreRun(
      'run-refused',
      refusalOutput,
      [],
      groundTruthList,
      1
    );

    expect(scored.isRefusal).toBe(true);
    expect(scored.declined).toHaveLength(3); // All 3 GTs marked as declined
    expect(scored.truePositives).toHaveLength(0);
    expect(scored.precision).toBe(0);
    expect(scored.recall).toBe(0);
  });

  it('computes aggregates and hit-rate across repeat runs', () => {
    const run1 = BenchmarkScorer.scoreRun('r1', dummyRawOutput, [], groundTruthList, 1);
    const run2 = BenchmarkScorer.scoreRun('r2', dummyRawOutput, [], groundTruthList, 2);
    run1.truePositives = ['GT-01', 'GT-02'];
    run2.truePositives = ['GT-01']; // Found in 1 of 2 runs

    const { aggregates, comparisonTable } = BenchmarkScorer.computeAggregates(
      [run1, run2],
      groundTruthList
    );

    expect(aggregates).toHaveLength(1);
    const agg = aggregates[0];
    expect(agg.totalRuns).toBe(2);
    expect(agg.vulnerabilityHitRates['GT-01'].hitRatePercent).toBe(100); // 2/2 = 100%
    expect(agg.vulnerabilityHitRates['GT-02'].hitRatePercent).toBe(50); // 1/2 = 50%
    expect(agg.vulnerabilityHitRates['GT-03'].hitRatePercent).toBe(0); // 0/2 = 0%

    // Comparison table rows
    expect(comparisonTable.length).toBe(3);
    const gt01Row = comparisonTable.find((r) => r.groundTruthId === 'GT-01');
    expect(gt01Row?.status).toBe('confirmed');
    expect(gt01Row?.hitRate).toBe('2/2 (100%)');
  });
});

