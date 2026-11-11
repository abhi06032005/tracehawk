import type { ModelProvider, EvidenceBundle, PromptTemplate, RawModelOutput } from '../types.js';
import { parseHypothesesFromJson, estimateCostUsd } from './base.js';
import { RefusalClassifier } from '../refusal-classifier.js';

export class GroqModelProvider implements ModelProvider {
  public readonly id = 'groq';
  public readonly name = 'Groq Hosted LLM API';
  public readonly defaultModel = process.env.GROQ_MODEL || 'qwen/qwen3.8-27b';
  public readonly maxRetries = parseInt(process.env.GROQ_MAX_RETRIES || '4', 10);

  private apiKey = process.env.GROQ_API_KEY || '';
  private baseUrl = process.env.GROQ_BASE_URL || 'https://api.groq.com/openai/v1';

  constructor(options?: { apiKey?: string; model?: string; baseUrl?: string; maxRetries?: number }) {
    if (options?.apiKey) this.apiKey = options.apiKey;
    if (options?.model) this.defaultModel = options.model;
    if (options?.baseUrl) this.baseUrl = options.baseUrl;
    if (options?.maxRetries !== undefined) this.maxRetries = options.maxRetries;
  }

  public async analyze(
    evidenceBundle: EvidenceBundle,
    promptTemplate: PromptTemplate,
    signal?: AbortSignal
  ): Promise<RawModelOutput> {
    const apiKey = this.apiKey || process.env.GROQ_API_KEY;
    if (!apiKey) {
      throw new Error('GROQ_API_KEY is not configured in environment or benchmark configuration.');
    }

    const startTime = Date.now();
    const promptText = promptTemplate.buildUserPrompt(evidenceBundle);
    const endpoint = `${this.baseUrl.replace(/\/+$/, '')}/chat/completions`;

    let attempt = 0;
    let lastError: Error | null = null;

    while (attempt <= this.maxRetries) {
      signal?.throwIfAborted();
      attempt++;

      try {
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

        if (res.status === 429 || res.status === 503) {
          const errText = await res.text().catch(() => '');
          const retryHeader = res.headers.get('retry-after');
          let backoffMs: number;

          if (retryHeader) {
            const parsedSeconds = parseInt(retryHeader, 10);
            backoffMs = !isNaN(parsedSeconds) ? parsedSeconds * 1000 : 5000;
          } else {
            backoffMs = Math.min(2500 * Math.pow(2, attempt - 1) + Math.random() * 1000, 25000);
          }

          if (attempt <= this.maxRetries) {
            console.warn(
              `[Groq Rate Limit] Received HTTP ${res.status}. Backing off for ${(backoffMs / 1000).toFixed(1)}s (retry attempt ${attempt}/${this.maxRetries})...`
            );
            await new Promise((resolve) => setTimeout(resolve, backoffMs));
            continue;
          } else {
            throw new Error(
              `Groq API rate limit exceeded (HTTP ${res.status}) after ${this.maxRetries} retries: ${errText.slice(0, 300)}`
            );
          }
        }

        if (!res.ok) {
          const errText = await res.text().catch(() => '');
          throw new Error(`Groq API request failed (HTTP ${res.status}): ${errText.slice(0, 300)}`);
        }

        const data: any = await res.json();
        const rawText = data.choices?.[0]?.message?.content || '';
        const latencyMs = Date.now() - startTime;

        const promptTokens = data.usage?.prompt_tokens ?? Math.ceil(promptText.length / 4);
        const completionTokens = data.usage?.completion_tokens ?? Math.ceil(rawText.length / 4);
        const totalTokens = data.usage?.total_tokens ?? promptTokens + completionTokens;

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
      } catch (err: any) {
        lastError = err;
        if (
          attempt <= this.maxRetries &&
          (err.name === 'FetchError' || /fetch failed|ECONNRESET|ETIMEDOUT/i.test(err.message))
        ) {
          const waitMs = 2000 * attempt;
          console.warn(`[Groq Connection Error] ${err.message}. Retrying in ${(waitMs / 1000).toFixed(1)}s...`);
          await new Promise((resolve) => setTimeout(resolve, waitMs));
          continue;
        }
        throw err;
      }
    }

    throw lastError || new Error(`Groq API call failed after ${this.maxRetries} attempts.`);
  }
}
