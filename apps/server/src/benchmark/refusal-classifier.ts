import type { RefusalClassification } from './types.js';

const HARD_REFUSAL_PATTERNS = [
  /I (?:cannot|can't|am unable to|am not able to|must decline to) (?:assist|help|participate|provide|generate|perform|conduct)/i,
  /I cannot fulfill (?:this|your) request/i,
  /as an AI(?: language model)?.*?(?:cannot|not permitted|not allowed|safety guidelines|policy)/i,
  /(?:violates?|against) (?:our|my)?\s*(?:safety policy|usage policy|content policy|terms of service|guidelines)/i,
  /cannot assist with (?:cybersecurity attacks|hacking|exploitation|vulnerability exploitation|penetration testing)/i,
  /I am programmed to be a helpful and harmless AI assistant/i,
  /ethical guidelines prevent me from/i,
];

const HEDGING_PATTERNS = [
  /consult (?:a |an |with a )?(?:qualified|certified|professional)?\s*security professional/i,
  /for educational (?:and research )?purposes only/i,
  /strictly for educational/i,
  /responsible disclosure/i,
  /I don't have enough (?:information|context) to (?:determine|tell|verify)/i,
  /without access to (?:the |source )?code.*?(?:cannot|impossible to tell)/i,
  /it is impossible to determine without/i,
  /may or may not (?:be vulnerable|represent a vulnerability)/i,
  /should only be used in authorized environments/i,
];

export class RefusalClassifier {
  /**
   * Scans raw model response text for refusal or hedging patterns.
   */
  public static classify(rawText: string, hasActionableHypotheses = false): RefusalClassification {
    const text = rawText || '';
    const matchedRefusals: string[] = [];
    const matchedHedges: string[] = [];

    for (const pattern of HARD_REFUSAL_PATTERNS) {
      const match = text.match(pattern);
      if (match) {
        matchedRefusals.push(match[0]);
      }
    }

    for (const pattern of HEDGING_PATTERNS) {
      const match = text.match(pattern);
      if (match) {
        matchedHedges.push(match[0]);
      }
    }

    const hasHardRefusal = matchedRefusals.length > 0;
    const hasHedging = matchedHedges.length > 0;

    // A model is considered to have refused if:
    // 1. It matched a hard refusal pattern, OR
    // 2. It heavily hedged and produced 0 actionable hypotheses
    const isRefusal = hasHardRefusal || (!hasActionableHypotheses && hasHedging);
    const isHedged = hasHedging;

    const matchedPhrases = [...matchedRefusals, ...matchedHedges];

    let confidence = 0;
    if (hasHardRefusal) {
      confidence = 0.95;
    } else if (!hasActionableHypotheses && hasHedging) {
      confidence = 0.85;
    } else if (hasHedging) {
      confidence = 0.5; // Has hedging disclaimers, but still produced findings
    }

    let explanation = 'Model produced regular technical analysis without refusal.';
    if (hasHardRefusal) {
      explanation = `Hard refusal detected matching safety/policy language: "${matchedRefusals[0]}"`;
    } else if (isRefusal) {
      explanation = `Model declined analysis with hedging disclaimers without producing findings: "${matchedHedges[0]}"`;
    } else if (hasHedging) {
      explanation = `Model included standard security disclaimers but still provided actionable hypotheses.`;
    }

    return {
      isRefusal,
      isHedged,
      matchedPhrases,
      confidence,
      explanation,
    };
  }
}

