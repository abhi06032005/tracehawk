import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type {
  BenchmarkResult,
  GroundTruthFixture,
  ScoredRun,
  ModelProvider,
} from './types.js';
import { ModelProviderRegistry } from './providers/registry.js';
import { getPromptTemplate } from './prompts.js';
import { BenchmarkScorer } from './scorer.js';
import { VerificationEngine, type VerificationContext } from '../security/verifier.js';
import type { NormalizedFinding, FindingStatus } from '../security/findings.js';

export interface BenchmarkRunOptions {
  fixture: string | GroundTruthFixture;
  models?: string[]; // IDs: deephat, gpt, gemini, groq, whiterabbitneo
  promptVariants?: string[]; // IDs: default, correctness-review
  repeats?: number;
  enableVerification?: boolean;
  signal?: AbortSignal;
  onProgress?: (info: {
    model: string;
    variant: string;
    repeat: number;
    currentStep: number;
    totalSteps: number;
    status: string;
  }) => void;
}

export class BenchmarkRunner {
  /**
   * Executes a complete multi-model research benchmark against a ground-truth fixture.
   */
  public static async run(options: BenchmarkRunOptions): Promise<BenchmarkResult> {
    const runId = randomUUID();
    const startTime = new Date().toISOString();

    // 1. Load Fixture
    let fixture: GroundTruthFixture;
    if (typeof options.fixture === 'string') {
      const filePath = resolve(options.fixture);
      const raw = await readFile(filePath, 'utf8');
      fixture = JSON.parse(raw);
    } else {
      fixture = options.fixture;
    }

    const models = (options.models && options.models.length > 0)
      ? options.models
      : ['deephat', 'gpt', 'gemini', 'groq', 'whiterabbitneo'];

    const promptVariants = (options.promptVariants && options.promptVariants.length > 0)
      ? options.promptVariants
      : ['default', 'correctness-review'];

    const repeats = Math.max(1, options.repeats ?? 3);
    const enableVerification = options.enableVerification ?? true;
    const signal = options.signal;

    const totalSteps = models.length * promptVariants.length * repeats;
    let currentStep = 0;

    const runs: ScoredRun[] = [];

    // Verification context using safe in-memory mock/passive checking
    const verifierCtx: VerificationContext = {
      allowedOrigins: [new URL(fixture.targetUrl).origin],
      authorized: true,
      activeTests: false, // passive verification by default
      signal: signal || new AbortController().signal,
      remainingBudget: 10,
      reserveBudget: async () => {},
    };

    // 2. Execute Matrix: Models x Variants x Repeats
    for (const modelId of models) {
      signal?.throwIfAborted();
      let provider: ModelProvider;
      try {
        provider = ModelProviderRegistry.getProvider(modelId);
      } catch (err: any) {
        console.warn(`[Benchmark] Skipping unavailable provider '${modelId}': ${err.message}`);
        continue;
      }

      for (const variantId of promptVariants) {
        signal?.throwIfAborted();
        const promptTemplate = getPromptTemplate(variantId);

        for (let repeat = 1; repeat <= repeats; repeat++) {
          signal?.throwIfAborted();
          currentStep++;

          if (options.onProgress) {
            options.onProgress({
              model: provider.defaultModel,
              variant: variantId,
              repeat,
              currentStep,
              totalSteps,
              status: `Querying ${provider.name} (run ${repeat}/${repeats})`,
            });
          }

          // A. Call model provider
          let rawOutput;
          try {
            rawOutput = await provider.analyze(fixture.evidence, promptTemplate, signal);
          } catch (err: any) {
            // Record failure as a refusal / execution error rather than crashing the whole benchmark run
            rawOutput = {
              providerId: provider.id,
              modelName: provider.defaultModel,
              promptVariantId: variantId,
              rawText: `Execution Error: ${err.message}`,
              promptText: '',
              latencyMs: 0,
              tokenUsage: { promptTokens: 0, completionTokens: 0, totalTokens: 0 },
              estimatedCostUsd: 0,
              timestamp: new Date().toISOString(),
              isRefusal: true,
              refusalReason: `API Execution Error: ${err.message}`,
              parsedHypotheses: [],
            };
          }

          // B. Convert hypotheses into NormalizedFindings with attribution
          const candidateFindings: NormalizedFinding[] = rawOutput.parsedHypotheses.map((hyp) => {
            const status: FindingStatus = rawOutput.isRefusal
              ? 'declined'
              : 'needs_verification';

            return {
              id: randomUUID(),
              title: hyp.title,
              severity: (['critical', 'high', 'medium', 'low', 'informational'].includes(
                hyp.risk.toLowerCase()
              )
                ? hyp.risk.toLowerCase()
                : 'medium') as any,
              status,
              target: fixture.targetUrl,
              endpoint: hyp.affectedEndpoint,
              method: 'GET',
              cwe: hyp.cweCategory ? [hyp.cweCategory] : [],
              owasp_category: hyp.claimType,
              description: hyp.attackMechanism || hyp.title,
              evidence: [],
              reproduction_steps: hyp.prerequisites ? [hyp.prerequisites] : [],
              impact: hyp.potentialImpact || '',
              remediation: hyp.suggestedRemediation || '',
              confidence: hyp.confidence === 'HIGH' ? 85 : hyp.confidence === 'MEDIUM' ? 60 : 40,
              source_agent: 'Benchmark Model Provider',
              source_tool: provider.id,
              created_at: new Date().toISOString(),
              verified_at: null,
              source_model: provider.defaultModel,
              raw_confidence_text: hyp.rawConfidenceText,
              prompt_variant_id: variantId,
            };
          });

          // C. Route through Agent 5 Verifier (reused as-is!)
          const verifiedFindings: NormalizedFinding[] = [];
          for (const finding of candidateFindings) {
            if (enableVerification && finding.status !== 'declined') {
              try {
                const { updatedFinding, proof } = await VerificationEngine.verifyFinding(
                  finding,
                  verifierCtx
                );
                verifiedFindings.push({
                  ...updatedFinding,
                  verifier_result: proof,
                });
              } catch {
                verifiedFindings.push(finding);
              }
            } else {
              verifiedFindings.push(finding);
            }
          }

          // D. Score run against ground truth
          const scoredRun = BenchmarkScorer.scoreRun(
            runId,
            rawOutput,
            verifiedFindings,
            fixture.groundTruthVulnerabilities,
            repeat
          );

          runs.push(scoredRun);
        }
      }
    }

    // 3. Compute Aggregates & Repeat Hit Rates
    const { aggregates, comparisonTable } = BenchmarkScorer.computeAggregates(
      runs,
      fixture.groundTruthVulnerabilities
    );

    return {
      runId,
      timestamp: startTime,
      fixtureId: fixture.id,
      fixtureName: fixture.name,
      targetUrl: fixture.targetUrl,
      modelsTested: models,
      promptVariantsTested: promptVariants,
      repeats,
      runs,
      aggregates,
      comparisonTable,
    };
  }
}

