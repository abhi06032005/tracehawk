import type { ModelProvider, EvidenceBundle, PromptTemplate, RawModelOutput } from '../types.js';
import { parseHypothesesFromJson, estimateCostUsd } from './base.js';
import { RefusalClassifier } from '../refusal-classifier.js';

export class OpenAIModelProvider implements ModelProvider {
  public readonly id = 'gpt';
  public readonly name = 'OpenAI API (GPT)';
  public readonly defaultModel = process.env.OPENAI_MODEL || 'gpt-4o';

  private apiKey = process.env.OPENAI_API_KEY || '';
  private baseUrl = process.env.OPENAI_BASE_URL || 'https://api.openai.com/v1';

  constructor(options?: { apiKey?: string; model?: string; baseUrl?: string }) {
    if (options?.apiKey) this.apiKey = options.apiKey;
    if (options?.model) this.defaultModel = options.model;
    if (options?.baseUrl) this.baseUrl = options.baseUrl;
  }

  public async analyze(
    evidenceBundle: EvidenceBundle,
    promptTemplate: PromptTemplate,
    signal?: AbortSignal
  ): Promise<RawModelOutput> {
    const apiKey = this.apiKey || process.env.OPENAI_API_KEY;
    if (!apiKey) {
      throw new Error('OPENAI_API_KEY is not configured in environment or benchmark configuration.');
    }

    const startTime = Date.now();
    const promptText = promptTemplate.buildUserPrompt(evidenceBundle);
    const endpoint = `${this.baseUrl.replace(/\/+$/, '')}/chat/completions`;

    const res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: this.defaultModel,
        temperature: 0.1,
        response_format: { type: 'json_object' },
        messages: [
          { role: 'system', content: promptTemplate.system },
          { role: 'user', content: promptText },
        ],
      }),
      signal,
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      throw new Error(`OpenAI API request failed (HTTP ${res.status}): ${errText.slice(0, 300)}`);
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

