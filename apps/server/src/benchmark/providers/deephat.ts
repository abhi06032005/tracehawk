import type { ModelProvider, EvidenceBundle, PromptTemplate, RawModelOutput } from '../types.js';
import { parseHypothesesFromJson, estimateCostUsd } from './base.js';
import { RefusalClassifier } from '../refusal-classifier.js';

export class DeepHatModelProvider implements ModelProvider {
  public readonly id = 'deephat';
  public readonly name = 'DeepHat-V1-7B (Local/vLLM)';
  public readonly defaultModel = process.env.AI_MODEL || 'DeepHat/DeepHat-V1-7B';

  private baseUrl = process.env.AI_BASE_URL || 'http://127.0.0.1:18001/v1';
  private apiKey = process.env.AI_API_KEY || 'dummy';

  constructor(options?: { baseUrl?: string; apiKey?: string; model?: string }) {
    if (options?.baseUrl) this.baseUrl = options.baseUrl;
    if (options?.apiKey) this.apiKey = options.apiKey;
    if (options?.model) this.defaultModel = options.model;
  }

  public async analyze(
    evidenceBundle: EvidenceBundle,
    promptTemplate: PromptTemplate,
    signal?: AbortSignal
  ): Promise<RawModelOutput> {
    const startTime = Date.now();
    const promptText = promptTemplate.buildUserPrompt(evidenceBundle);

    let endpoint = this.baseUrl.replace(/\/+$/, '');
    if (!endpoint.endsWith('/chat/completions')) {
      endpoint += endpoint.endsWith('/v1') ? '/chat/completions' : '/v1/chat/completions';
    }

    const res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify({
        model: this.defaultModel,
        temperature: 0.1,
        max_tokens: 2048,
        messages: [
          { role: 'system', content: promptTemplate.system },
          { role: 'user', content: promptText },
        ],
      }),
      signal,
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      throw new Error(`DeepHat vLLM request failed (HTTP ${res.status}): ${errText.slice(0, 300)}`);
    }

    const data: any = await res.json();
    const rawText = data.choices?.[0]?.message?.content || '';
    const latencyMs = Date.now() - startTime;

    const promptTokens = data.usage?.prompt_tokens ?? Math.ceil(promptText.length / 4);
    const completionTokens = data.usage?.completion_tokens ?? Math.ceil(rawText.length / 4);
    const totalTokens = data.usage?.total_tokens ?? (promptTokens + completionTokens);

    const hypotheses = parseHypothesesFromJson(rawText);
    const refusal = RefusalClassifier.classify(rawText, hypotheses.length > 0);

    return {
      providerId: this.id,
      modelName: this.defaultModel,
      promptVariantId: promptTemplate.id,
      rawText,
      promptText,
      latencyMs,
      tokenUsage: {
        promptTokens,
        completionTokens,
        totalTokens,
      },
      estimatedCostUsd: estimateCostUsd(this.defaultModel, promptTokens, completionTokens),
      timestamp: new Date().toISOString(),
      isRefusal: refusal.isRefusal,
      refusalReason: refusal.isRefusal ? refusal.explanation : undefined,
      parsedHypotheses: hypotheses,
    };
  }
}

