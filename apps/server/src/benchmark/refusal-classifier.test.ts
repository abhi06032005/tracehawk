import { describe, expect, it } from 'vitest';
import { RefusalClassifier } from './refusal-classifier.js';

describe('RefusalClassifier', () => {
  it('detects standard hard refusals', () => {
    const text1 = 'I cannot assist with identifying security vulnerabilities or penetration testing.';
    const res1 = RefusalClassifier.classify(text1, false);
    expect(res1.isRefusal).toBe(true);
    expect(res1.confidence).toBeGreaterThanOrEqual(0.9);
    expect(res1.explanation).toContain('Hard refusal detected');

    const text2 = 'As an AI language model, I am not permitted to evaluate exploit paths as it violates our safety policy.';
    const res2 = RefusalClassifier.classify(text2, false);
    expect(res2.isRefusal).toBe(true);
    expect(res2.matchedPhrases.length).toBeGreaterThan(0);
  });

  it('detects hedging disclaimers without actionable findings as declined', () => {
    const text = 'This analysis is for educational purposes only. I don\'t have enough context to determine whether the endpoint is vulnerable. Please consult a qualified security professional.';
    const res = RefusalClassifier.classify(text, false); // hasActionableHypotheses = false
    expect(res.isRefusal).toBe(true);
    expect(res.isHedged).toBe(true);
    expect(res.explanation).toContain('hedging disclaimers');
  });

  it('does NOT mark as refusal if model includes educational disclaimer but still provides findings', () => {
    const text = 'Disclaimer: For educational purposes only. {"hypotheses": [{"title": "Missing CSP", "affectedEndpoint": "/"}]}';
    const res = RefusalClassifier.classify(text, true); // hasActionableHypotheses = true
    expect(res.isRefusal).toBe(false);
    expect(res.isHedged).toBe(true);
    expect(res.confidence).toBe(0.5);
  });

  it('recognizes regular security analysis as non-refusal', () => {
    const text = JSON.stringify({
      hypotheses: [
        {
          title: 'Missing Content Security Policy',
          affectedEndpoint: '/',
          claimType: 'missing_csp',
          risk: 'MEDIUM',
          confidence: 'HIGH',
        },
      ],
    });
    const res = RefusalClassifier.classify(text, true);
    expect(res.isRefusal).toBe(false);
    expect(res.isHedged).toBe(false);
    expect(res.matchedPhrases).toHaveLength(0);
  });
});

