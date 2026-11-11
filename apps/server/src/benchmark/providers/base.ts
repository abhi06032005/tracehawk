import type { RawHypothesisDraft } from '../types.js';

export function parseHypothesesFromJson(rawText: string): RawHypothesisDraft[] {
  try {
    const trimmed = rawText.trim();
    const jsonMatch = trimmed.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/i);
    const cleanedJson = jsonMatch ? jsonMatch[1].trim() : trimmed;
    const parsed = JSON.parse(cleanedJson);

    let items: any[] = [];
    if (Array.isArray(parsed)) {
      items = parsed;
    } else if (Array.isArray(parsed.hypotheses)) {
      items = parsed.hypotheses;
    } else if (Array.isArray(parsed.findings)) {
      items = parsed.findings;
    } else if (Array.isArray(parsed.vulnerabilities)) {
      items = parsed.vulnerabilities;
    }

    return items.map((item) => ({
      title: String(item.title || item.name || 'Untitled Hypothesis'),
      affectedEndpoint: String(item.affectedEndpoint || item.endpoint || item.path || '/'),
      claimType: String(item.claimType || item.category || 'other'),
      cweCategory: item.cweCategory || item.cwe || undefined,
      attackMechanism: item.attackMechanism || item.description || '',
      prerequisites: item.prerequisites || '',
      potentialImpact: item.potentialImpact || item.impact || '',
      suggestedRemediation: item.suggestedRemediation || item.remediation || '',
      risk: (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(String(item.risk).toUpperCase())
        ? String(item.risk).toUpperCase()
        : 'MEDIUM') as any,
      confidence: (['HIGH', 'MEDIUM', 'LOW'].includes(String(item.confidence).toUpperCase())
        ? String(item.confidence).toUpperCase()
        : 'MEDIUM') as any,
      rawConfidenceText: item.confidence ? String(item.confidence) : undefined,
    }));
  } catch {
    return [];
  }
}

/**
 * Estimates API costs based on standard per-million-tokens pricing.
 */
export function estimateCostUsd(
  model: string,
  promptTokens: number,
  completionTokens: number
): number {
  const m = (model || '').toLowerCase();

  // Pricing per 1M tokens: [input, output]
  let rates: [number, number] = [0, 0];

  if (m.includes('gpt-4o-mini')) {
    rates = [0.15, 0.60];
  } else if (m.includes('gpt-4o')) {
    rates = [2.50, 10.00];
  } else if (m.includes('gpt-4-turbo') || m.includes('gpt-4')) {
    rates = [10.00, 30.00];
  } else if (m.includes('gemini-2.0-flash')) {
    rates = [0.10, 0.40];
  } else if (m.includes('gemini-1.5-flash')) {
    rates = [0.075, 0.30];
  } else if (m.includes('gemini-1.5-pro')) {
    rates = [1.25, 5.00];
  } else if (m.includes('llama-3.3-70b') || m.includes('llama3-70b')) {
    rates = [0.59, 0.79];
  } else if (m.includes('llama-3.1-8b') || m.includes('llama3-8b')) {
    rates = [0.05, 0.08];
  } else {
    // Local / self-hosted models (DeepHat, WhiteRabbitNeo) have zero incremental API cost
    rates = [0, 0];
  }

  const cost = (promptTokens / 1_000_000) * rates[0] + (completionTokens / 1_000_000) * rates[1];
  return Math.round(cost * 1_000_000) / 1_000_000; // 6 decimal places
}

