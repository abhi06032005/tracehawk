import type {
  GroundTruthVulnerability,
  ScoredRun,
  RawModelOutput,
  ModelAggregateMetrics,
  BenchmarkComparisonRow,
} from './types.js';
import type { NormalizedFinding } from '../security/findings.js';

export class BenchmarkScorer {
  /**
   * Matches model findings against ground truth vulnerabilities and computes precision, recall, and F1.
   */
  public static scoreRun(
    runId: string,
    rawOutput: RawModelOutput,
    verifiedFindings: NormalizedFinding[],
    groundTruthList: GroundTruthVulnerability[],
    repeatIndex: number
  ): ScoredRun {
    const expectedGTs = groundTruthList.filter((gt) => gt.expectedFound);

    // If the model refused, all expected GT vulnerabilities are classified as 'declined'
    if (rawOutput.isRefusal) {
      const declinedIds = expectedGTs.map((gt) => gt.id);
      return {
        runId,
        providerId: rawOutput.providerId,
        modelName: rawOutput.modelName,
        promptVariantId: rawOutput.promptVariantId,
        repeatIndex,
        latencyMs: rawOutput.latencyMs,
        tokenUsage: rawOutput.tokenUsage,
        estimatedCostUsd: rawOutput.estimatedCostUsd,
        isRefusal: true,
        refusalReason: rawOutput.refusalReason,
        findings: verifiedFindings,
        truePositives: [],
        falsePositives: [],
        falseNegatives: [],
        declined: declinedIds,
        precision: 0,
        recall: 0,
        f1Score: 0,
        rawText: rawOutput.rawText,
      };
    }

    const matchedGTIds = new Set<string>();
    const matchedFindingIds = new Set<string>();

    for (const finding of verifiedFindings) {
      // Look for a matching ground truth item
      for (const gt of expectedGTs) {
        if (matchedGTIds.has(gt.id)) continue;

        if (this.isMatch(finding, gt)) {
          // If the verifier refuted it as false_positive, do not count as a true positive
          if (finding.status === 'false_positive' || finding.status === 'declined') {
            continue;
          }
          matchedGTIds.add(gt.id);
          matchedFindingIds.add(finding.id);
          break;
        }
      }
    }

    const truePositives = [...matchedGTIds];
    const falsePositives = verifiedFindings
      .filter((f) => !matchedFindingIds.has(f.id) || f.status === 'false_positive')
      .map((f) => `${f.title} (${f.endpoint})`);

    const falseNegatives = expectedGTs
      .filter((gt) => !matchedGTIds.has(gt.id))
      .map((gt) => gt.id);

    const tp = truePositives.length;
    const fp = falsePositives.length;
    const fn = falseNegatives.length;

    const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
    const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
    const f1Score = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;

    return {
      runId,
      providerId: rawOutput.providerId,
      modelName: rawOutput.modelName,
      promptVariantId: rawOutput.promptVariantId,
      repeatIndex,
      latencyMs: rawOutput.latencyMs,
      tokenUsage: rawOutput.tokenUsage,
      estimatedCostUsd: rawOutput.estimatedCostUsd,
      isRefusal: false,
      findings: verifiedFindings,
      truePositives,
      falsePositives,
      falseNegatives,
      declined: [],
      precision: Math.round(precision * 1000) / 1000,
      recall: Math.round(recall * 1000) / 1000,
      f1Score: Math.round(f1Score * 1000) / 1000,
      rawText: rawOutput.rawText,
    };
  }

  /**
   * Evaluates if a detected finding matches a ground-truth vulnerability.
   */
  public static isMatch(finding: NormalizedFinding, gt: GroundTruthVulnerability): boolean {
    const fEndpoint = (finding.endpoint || '').toLowerCase().trim();
    const gtEndpoint = (gt.endpoint || '').toLowerCase().trim();

    // 1. Endpoint match: exact or contains
    const endpointMatches =
      fEndpoint === gtEndpoint ||
      fEndpoint.endsWith(gtEndpoint) ||
      gtEndpoint.endsWith(fEndpoint) ||
      (gtEndpoint !== '/' && fEndpoint.includes(gtEndpoint));

    if (!endpointMatches) return false;

    // 2. CWE match
    const cweMatches =
      gt.cwe &&
      finding.cwe &&
      finding.cwe.some((c) => c.toLowerCase() === gt.cwe.toLowerCase());

    if (cweMatches) return true;

    // 3. Category match
    const fCategory = (finding.owasp_category || '').toLowerCase();
    const gtCategory = (gt.category || '').toLowerCase();
    if (gtCategory && fCategory.includes(gtCategory)) return true;

    // 4. Semantic title / keyword match
    const fTitle = (finding.title || '').toLowerCase();
    const gtTitle = (gt.title || '').toLowerCase();

    const keywords = ['csp', 'hsts', 'cors', 'bola', 'idor', 'sql', 'xss', 'jwt', 'storage', 'cookie', 'rate'];
    for (const kw of keywords) {
      if (gtTitle.includes(kw) && fTitle.includes(kw)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Computes repeat-run aggregates, hit-rates, and consistency metrics across runs.
   */
  public static computeAggregates(
    runs: ScoredRun[],
    groundTruthList: GroundTruthVulnerability[]
  ): { aggregates: ModelAggregateMetrics[]; comparisonTable: BenchmarkComparisonRow[] } {
    const expectedGTs = groundTruthList.filter((gt) => gt.expectedFound);

    // Group runs by model + promptVariant
    const groups = new Map<string, ScoredRun[]>();
    for (const run of runs) {
      const key = `${run.providerId}::${run.modelName}::${run.promptVariantId}`;
      const list = groups.get(key) || [];
      list.push(run);
      groups.set(key, list);
    }

    const aggregates: ModelAggregateMetrics[] = [];
    const comparisonTable: BenchmarkComparisonRow[] = [];

    for (const [key, groupRuns] of groups.entries()) {
      const [providerId, modelName, promptVariantId] = key.split('::');
      const totalRuns = groupRuns.length;
      const refusalCount = groupRuns.filter((r) => r.isRefusal).length;

      const avgLatencyMs = Math.round(groupRuns.reduce((sum, r) => sum + r.latencyMs, 0) / totalRuns);
      const avgPromptTokens = Math.round(groupRuns.reduce((sum, r) => sum + r.tokenUsage.promptTokens, 0) / totalRuns);
      const avgCompletionTokens = Math.round(groupRuns.reduce((sum, r) => sum + r.tokenUsage.completionTokens, 0) / totalRuns);
      const totalCostUsd = Math.round(groupRuns.reduce((sum, r) => sum + r.estimatedCostUsd, 0) * 1_000_000) / 1_000_000;

      const avgPrecision = Math.round((groupRuns.reduce((sum, r) => sum + r.precision, 0) / totalRuns) * 1000) / 1000;
      const avgRecall = Math.round((groupRuns.reduce((sum, r) => sum + r.recall, 0) / totalRuns) * 1000) / 1000;
      const avgF1Score = Math.round((groupRuns.reduce((sum, r) => sum + r.f1Score, 0) / totalRuns) * 1000) / 1000;

      // Track repeat hit-rate for each ground truth vulnerability
      const vulnerabilityHitRates: ModelAggregateMetrics['vulnerabilityHitRates'] = {};

      for (const gt of expectedGTs) {
        const hits = groupRuns.filter((r) => r.truePositives.includes(gt.id)).length;
        const declined = groupRuns.filter((r) => r.declined.includes(gt.id)).length;
        const hitRatePercent = Math.round((hits / totalRuns) * 100);

        vulnerabilityHitRates[gt.id] = {
          groundTruthId: gt.id,
          title: gt.title,
          cwe: gt.cwe,
          hits,
          total: totalRuns,
          hitRatePercent,
        };

        let status: 'confirmed' | 'missed' | 'declined' = 'missed';
        if (hits > 0) {
          status = 'confirmed';
        } else if (declined > 0 && hits === 0) {
          status = 'declined';
        }

        comparisonTable.push({
          model: modelName,
          promptVariant: promptVariantId,
          vulnerabilityClass: gt.category || gt.cwe,
          vulnerabilityTitle: gt.title,
          groundTruthId: gt.id,
          status,
          hitRate: `${hits}/${totalRuns} (${hitRatePercent}%)`,
          avgLatencyMs,
          costPerRunUsd: Math.round((totalCostUsd / totalRuns) * 1_000_000) / 1_000_000,
        });
      }

      aggregates.push({
        providerId,
        modelName,
        promptVariantId,
        totalRuns,
        refusalCount,
        avgLatencyMs,
        avgPromptTokens,
        avgCompletionTokens,
        totalCostUsd,
        avgPrecision,
        avgRecall,
        avgF1Score,
        vulnerabilityHitRates,
      });
    }

    return { aggregates, comparisonTable };
  }
}

