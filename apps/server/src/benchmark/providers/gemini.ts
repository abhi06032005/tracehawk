import type { ModelProvider, EvidenceBundle, PromptTemplate, RawModelOutput } from '../types.js';
import { parseHypothesesFromJson, estimateCostUsd } from './base.js';
import { RefusalClassifier } from '../refusal-classifier.js';

export class GeminiModelProvider implements ModelProvider {
  public readonly id = 'gemini';
  public readonly name = 'Google Gemini API';
  public readonly defaultModel = process.env.GEMINI_MODEL || 'gemini-flash-lite-latest';

  // Gemini Flash-Lite window limits (1,048,576 tokens input, 65,536 tokens output)
  public readonly inputTokenLimit = 1048576;
  public readonly maxOutputTokens = parseInt(process.env.GEMINI_MAX_OUTPUT_TOKENS || '8192', 10);
  public readonly minRequestIntervalMs = parseInt(
    process.env.GEMINI_MIN_REQUEST_INTERVAL_MS || '2000',
    10
  );
  public readonly maxRetries = parseInt(process.env.GEMINI_MAX_RETRIES || '4', 10);

  private apiKey = process.env.GEMINI_API_KEY || '';
  private static lastRequestTimestamp = 0;

  constructor(options?: {
    apiKey?: string;
    model?: string;
    maxOutputTokens?: number;
    minRequestIntervalMs?: number;
    maxRetries?: number;
  }) {
    if (options?.apiKey) this.apiKey = options.apiKey;
    if (options?.model) this.defaultModel = options.model;
    if (options?.maxOutputTokens) this.maxOutputTokens = options.maxOutputTokens;
    if (options?.minRequestIntervalMs !== undefined)
      this.minRequestIntervalMs = options.minRequestIntervalMs;
    if (options?.maxRetries !== undefined) this.maxRetries = options.maxRetries;
  }

  /**
   * Enforces client-side rate limit spacing between consecutive Gemini API calls
   * to prevent exceeding standard RPM limits (15 RPM on free tier).
   */
  private static async enforcePacing(intervalMs: number, signal?: AbortSignal): Promise<void> {
    if (intervalMs <= 0) return;
    const now = Date.now();
    const elapsed = now - GeminiModelProvider.lastRequestTimestamp;
    const waitNeeded = intervalMs - elapsed;

    if (waitNeeded > 0) {
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(resolve, waitNeeded);
        signal?.addEventListener(
          'abort',
          () => {
            clearTimeout(timer);
            reject(new Error('Operation aborted during rate limit pacing delay'));
          },
          { once: true }
        );
      });
    }

    GeminiModelProvider.lastRequestTimestamp = Date.now();
  }

  public async analyze(
    evidenceBundle: EvidenceBundle,
    promptTemplate: PromptTemplate,
    signal?: AbortSignal
  ): Promise<RawModelOutput> {
    const apiKey = this.apiKey || process.env.GEMINI_API_KEY;
    if (!apiKey) {
      throw new Error('GEMINI_API_KEY is not configured in environment or benchmark configuration.');
    }

    const startTime = Date.now();
    let promptText = promptTemplate.buildUserPrompt(evidenceBundle);

    // Context Window Guard: Prevent exceeding input token limit (~4 chars per token rule of thumb)
    const estimatedInputTokens = Math.ceil(promptText.length / 4);
    if (estimatedInputTokens > this.inputTokenLimit) {
      const maxCharBudget = this.inputTokenLimit * 4 * 0.9;
      console.warn(
        `[Gemini Window Guard] Evidence bundle exceeds input token limit (~${estimatedInputTokens} > ${this.inputTokenLimit}). Budgeting prompt to ${maxCharBudget} characters.`
      );
      promptText = promptText.slice(0, maxCharBudget) + '\n\n[TRUNCATED TO FIT MODEL CONTEXT WINDOW]';
    }

    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(
      this.defaultModel
    )}:generateContent?key=${encodeURIComponent(apiKey)}`;

    let attempt = 0;
    let lastError: Error | null = null;

    while (attempt <= this.maxRetries) {
      signal?.throwIfAborted();
      attempt++;

      // Enforce rate limit interval between consecutive requests
      await GeminiModelProvider.enforcePacing(this.minRequestIntervalMs, signal);

      try {
        const res = await fetch(endpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-goog-api-key': apiKey,
          },
          body: JSON.stringify({
            systemInstruction: {
              parts: [{ text: promptTemplate.system }],
            },
            contents: [
              {
                role: 'user',
                parts: [{ text: promptText }],
              },
            ],
            generationConfig: {
              temperature: 0.1,
              responseMimeType: 'application/json',
              maxOutputTokens: this.maxOutputTokens,
            },
          }),
          signal,
        });

        // Handle Rate Limit (HTTP 429) and Service Unavailable (HTTP 503) with exponential backoff
        if (res.status === 429 || res.status === 503) {
          const errText = await res.text().catch(() => '');
          const retryHeader = res.headers.get('retry-after');
          let backoffMs: number;

          if (retryHeader) {
            const parsedSeconds = parseInt(retryHeader, 10);
            backoffMs = !isNaN(parsedSeconds) ? parsedSeconds * 1000 : 5000;
          } else {
            // Exponential backoff: 3s, 6s, 12s, 24s + jitter
            backoffMs = Math.min(3000 * Math.pow(2, attempt - 1) + Math.random() * 1500, 30000);
          }

          if (attempt <= this.maxRetries) {
            console.warn(
              `[Gemini Rate Limit] Received HTTP ${res.status} (${
                res.status === 429 ? 'Quota / Rate Limit' : 'Model Overload'
              }). Backing off for ${(backoffMs / 1000).toFixed(1)}s (retry attempt ${attempt}/${this.maxRetries})...`
            );
            await new Promise((resolve) => setTimeout(resolve, backoffMs));
            continue;
          } else {
            throw new Error(
              `Gemini API rate limit exceeded (HTTP ${res.status}) after ${this.maxRetries} retries: ${errText.slice(0, 300)}`
            );
          }
        }

        if (!res.ok) {
          const errText = await res.text().catch(() => '');
          throw new Error(`Gemini API request failed (HTTP ${res.status}): ${errText.slice(0, 300)}`);
        }

        const data: any = await res.json();
        const rawText = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
        const latencyMs = Date.now() - startTime;

        const promptTokens = data.usageMetadata?.promptTokenCount ?? Math.ceil(promptText.length / 4);
        const completionTokens =
          data.usageMetadata?.candidatesTokenCount ?? Math.ceil(rawText.length / 4);
        const totalTokens = data.usageMetadata?.totalTokenCount ?? promptTokens + completionTokens;

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
          const waitMs = 2500 * attempt;
          console.warn(`[Gemini Connection Error] ${err.message}. Retrying in ${(waitMs / 1000).toFixed(1)}s...`);
          await new Promise((resolve) => setTimeout(resolve, waitMs));
          continue;
        }
        throw err;
      }
    }

    throw lastError || new Error(`Gemini API call failed after ${this.maxRetries} attempts.`);
  }
}
