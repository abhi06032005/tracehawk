import type { NormalizedFinding } from '../security/findings.js';

export interface EvidenceBundle {
  targetUrl: string;
  endpointInventory: Array<{
    method: string;
    url: string;
    statuses?: (number | null)[];
    parameters?: string[];
  }>;
  exchanges: Array<{
    id: string;
    method: string;
    url: string;
    statusCode: number | null;
    requestHeaders?: Record<string, unknown> | null;
    responseHeaders?: Record<string, unknown> | null;
    sanitizedRequestBody?: string | null;
    sanitizedResponseBody?: string | null;
    resourceType?: string | null;
  }>;
  storageObservations?: Array<{
    storageType: string;
    origin: string;
    key: string;
    sanitizedValue?: string | null;
    metadata?: Record<string, unknown> | null;
  }>;
  sourceSnippets?: Array<{
    file: string;
    startLine?: number;
    endLine?: number;
    codeSnippet: string;
  }>;
  passiveFindings?: Array<{
    title: string;
    category: string;
    cweId?: string;
    severity: string;
  }>;
}

export interface PromptTemplate {
  id: string; // e.g. 'default', 'correctness-review'
  name: string;
  description: string;
  system: string;
  buildUserPrompt: (bundle: EvidenceBundle) => string;
}

export interface RawHypothesisDraft {
  title: string;
  affectedEndpoint: string;
  claimType: string;
  cweCategory?: string;
  attackMechanism?: string;
  prerequisites?: string;
  potentialImpact?: string;
  suggestedRemediation?: string;
  risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  rawConfidenceText?: string;
}

export interface RawModelOutput {
  providerId: string; // e.g. 'deephat', 'gpt', 'gemini', 'groq', 'whiterabbitneo'
  modelName: string;
  promptVariantId: string;
  rawText: string;
  promptText: string;
  latencyMs: number;
  tokenUsage: {
    promptTokens: number;
    completionTokens: number;
    totalTokens: number;
  };
  estimatedCostUsd: number;
  timestamp: string;
  isRefusal: boolean;
  refusalReason?: string;
  parsedHypotheses: RawHypothesisDraft[];
}

export interface ModelProvider {
  id: string;
  name: string;
  defaultModel: string;
  analyze(
    evidenceBundle: EvidenceBundle,
    promptTemplate: PromptTemplate,
    signal?: AbortSignal
  ): Promise<RawModelOutput>;
}

export interface RefusalClassification {
  isRefusal: boolean;
  isHedged: boolean;
  matchedPhrases: string[];
  confidence: number;
  explanation: string;
}

export interface GroundTruthVulnerability {
  id: string;
  title: string;
  endpoint: string;
  cwe: string;
  category: string;
  expectedFound: boolean;
  description?: string;
}

export interface GroundTruthFixture {
  id: string;
  name: string;
  targetUrl: string;
  evidence: EvidenceBundle;
  groundTruthVulnerabilities: GroundTruthVulnerability[];
}

export interface ScoredRun {
  runId: string;
  providerId: string;
  modelName: string;
  promptVariantId: string;
  repeatIndex: number;
  latencyMs: number;
  tokenUsage: {
    promptTokens: number;
    completionTokens: number;
    totalTokens: number;
  };
  estimatedCostUsd: number;
  isRefusal: boolean;
  refusalReason?: string;
  findings: NormalizedFinding[];
  truePositives: string[]; // Ground-truth IDs matched
  falsePositives: string[]; // Finding titles or IDs that didn't match ground truth
  falseNegatives: string[]; // Ground-truth IDs expected but missed
  declined: string[]; // Ground-truth IDs declined due to refusal
  precision: number;
  recall: number;
  f1Score: number;
  rawText?: string;
}

export interface ModelAggregateMetrics {
  providerId: string;
  modelName: string;
  promptVariantId: string;
  totalRuns: number;
  refusalCount: number;
  avgLatencyMs: number;
  avgPromptTokens: number;
  avgCompletionTokens: number;
  totalCostUsd: number;
  avgPrecision: number;
  avgRecall: number;
  avgF1Score: number;
  vulnerabilityHitRates: Record<
    string,
    {
      groundTruthId: string;
      title: string;
      cwe: string;
      hits: number;
      total: number;
      hitRatePercent: number;
    }
  >;
}

export interface BenchmarkComparisonRow {
  model: string;
  promptVariant: string;
  vulnerabilityClass: string;
  vulnerabilityTitle: string;
  groundTruthId: string;
  status: 'confirmed' | 'missed' | 'declined';
  hitRate: string;
  avgLatencyMs: number;
  costPerRunUsd: number;
}

export interface BenchmarkResult {
  runId: string;
  timestamp: string;
  fixtureId: string;
  fixtureName: string;
  targetUrl: string;
  modelsTested: string[];
  promptVariantsTested: string[];
  repeats: number;
  runs: ScoredRun[];
  aggregates: ModelAggregateMetrics[];
  comparisonTable: BenchmarkComparisonRow[];
}

