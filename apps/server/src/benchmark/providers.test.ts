import { describe, expect, it, vi, beforeEach } from 'vitest';
import { DeepHatModelProvider } from './providers/deephat.js';
import { OpenAIModelProvider } from './providers/openai.js';
import { GeminiModelProvider } from './providers/gemini.js';
import { GroqModelProvider } from './providers/groq.js';
import { WhiteRabbitNeoModelProvider } from './providers/whiterabbitneo.js';
import { ModelProviderRegistry } from './providers/registry.js';
import { estimateCostUsd, parseHypothesesFromJson } from './providers/base.js';
import { DEFAULT_SECURITY_PROMPT } from './prompts.js';
import type { EvidenceBundle } from './types.js';

describe('Model Providers & Registry', () => {
  const dummyBundle: EvidenceBundle = {
    targetUrl: 'http://127.0.0.1:3000',
    endpointInventory: [{ method: 'GET', url: 'http://127.0.0.1:3000/' }],
    exchanges: [],
  };

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  describe('estimateCostUsd', () => {
    it('calculates GPT-4o costs accurately', () => {
      // 100,000 prompt tokens ($2.50/M) + 1,000 completion tokens ($10.00/M)
      // 0.25 + 0.01 = 0.26
      const cost = estimateCostUsd('gpt-4o', 100_000, 1_000);
      expect(cost).toBe(0.26);
    });

    it('estimates zero cost for self-hosted models (DeepHat, WhiteRabbitNeo)', () => {
      expect(estimateCostUsd('DeepHat/DeepHat-V1-7B', 50_000, 2_000)).toBe(0);
      expect(estimateCostUsd('WhiteRabbitNeo-33B', 50_000, 2_000)).toBe(0);
    });
  });

  describe('parseHypothesesFromJson', () => {
    it('parses markdown code-fenced JSON responses', () => {
      const raw = '```json\n{"hypotheses": [{"title": "SQL Injection", "affectedEndpoint": "/search", "risk": "HIGH", "confidence": "HIGH"}]}\n```';
      const parsed = parseHypothesesFromJson(raw);
      expect(parsed).toHaveLength(1);
      expect(parsed[0].title).toBe('SQL Injection');
      expect(parsed[0].affectedEndpoint).toBe('/search');
      expect(parsed[0].risk).toBe('HIGH');
    });

    it('gracefully returns empty array on invalid JSON', () => {
      expect(parseHypothesesFromJson('Not valid json at all')).toEqual([]);
    });
  });

  describe('ModelProviderRegistry', () => {
    it('instantiates all 5 supported provider types', () => {
      expect(ModelProviderRegistry.getProvider('deephat')).toBeInstanceOf(DeepHatModelProvider);
      expect(ModelProviderRegistry.getProvider('gpt')).toBeInstanceOf(OpenAIModelProvider);
      expect(ModelProviderRegistry.getProvider('gemini')).toBeInstanceOf(GeminiModelProvider);
      expect(ModelProviderRegistry.getProvider('groq')).toBeInstanceOf(GroqModelProvider);
      expect(ModelProviderRegistry.getProvider('whiterabbitneo')).toBeInstanceOf(WhiteRabbitNeoModelProvider);
    });

    it('throws when requesting an unknown provider', () => {
      expect(() => ModelProviderRegistry.getProvider('unknown-model')).toThrow(/Unknown model provider/);
    });
  });

  describe('DeepHatModelProvider', () => {
    it('sends OpenAI-compatible completions request and parses output', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          choices: [
            {
              message: {
                content: JSON.stringify({
                  hypotheses: [
                    { title: 'Missing CSP', affectedEndpoint: '/', risk: 'MEDIUM', confidence: 'HIGH' },
                  ],
                }),
              },
            },
          ],
          usage: { prompt_tokens: 150, completion_tokens: 45, total_tokens: 195 },
        }),
      });
      globalThis.fetch = mockFetch as any;

      const provider = new DeepHatModelProvider({ baseUrl: 'http://127.0.0.1:18001/v1' });
      const output = await provider.analyze(dummyBundle, DEFAULT_SECURITY_PROMPT);

      expect(output.providerId).toBe('deephat');
      expect(output.parsedHypotheses).toHaveLength(1);
      expect(output.parsedHypotheses[0].title).toBe('Missing CSP');
      expect(output.isRefusal).toBe(false);
      expect(output.tokenUsage.totalTokens).toBe(195);
    });
  });

  describe('OpenAIModelProvider', () => {
    it('throws if API key is not provided', async () => {
      const provider = new OpenAIModelProvider({ apiKey: '' });
      await expect(provider.analyze(dummyBundle, DEFAULT_SECURITY_PROMPT)).rejects.toThrow(
        /OPENAI_API_KEY is not configured/
      );
    });

    it('successfully calls OpenAI endpoint with Bearer auth', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          choices: [
            {
              message: {
                content: '{"hypotheses": [{"title": "BOLA in /user", "affectedEndpoint": "/user", "risk": "HIGH", "confidence": "HIGH"}]}',
              },
            },
          ],
          usage: { prompt_tokens: 200, completion_tokens: 50, total_tokens: 250 },
        }),
      });
      globalThis.fetch = mockFetch as any;

      const provider = new OpenAIModelProvider({ apiKey: 'sk-test-mock' });
      const output = await provider.analyze(dummyBundle, DEFAULT_SECURITY_PROMPT);

      expect(output.providerId).toBe('gpt');
      expect(output.parsedHypotheses).toHaveLength(1);
      expect(output.tokenUsage.totalTokens).toBe(250);
      expect(output.estimatedCostUsd).toBeGreaterThan(0);
    });
  });

  describe('GeminiModelProvider', () => {
    it('throws if GEMINI_API_KEY is missing', async () => {
      const provider = new GeminiModelProvider({ apiKey: '' });
      await expect(provider.analyze(dummyBundle, DEFAULT_SECURITY_PROMPT)).rejects.toThrow(
        /GEMINI_API_KEY is not configured/
      );
    });

    it('calls Gemini generateContent REST endpoint', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          candidates: [
            {
              content: {
                parts: [
                  {
                    text: '{"hypotheses": [{"title": "CORS Wildcard", "affectedEndpoint": "/api", "risk": "LOW", "confidence": "HIGH"}]}',
                  },
                ],
              },
            },
          ],
          usageMetadata: { promptTokenCount: 180, candidatesTokenCount: 30, totalTokenCount: 210 },
        }),
      });
      globalThis.fetch = mockFetch as any;

      const provider = new GeminiModelProvider({ apiKey: 'ai-gemini-mock' });
      const output = await provider.analyze(dummyBundle, DEFAULT_SECURITY_PROMPT);

      expect(output.providerId).toBe('gemini');
      expect(output.parsedHypotheses).toHaveLength(1);
      expect(output.parsedHypotheses[0].title).toBe('CORS Wildcard');
      expect(output.tokenUsage.totalTokens).toBe(210);
    });
  });

  describe('GroqModelProvider', () => {
    it('throws if GROQ_API_KEY is missing', async () => {
      const provider = new GroqModelProvider({ apiKey: '' });
      await expect(provider.analyze(dummyBundle, DEFAULT_SECURITY_PROMPT)).rejects.toThrow(
        /GROQ_API_KEY is not configured/
      );
    });

    it('calls Groq OpenAI-compatible API', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          choices: [
            {
              message: {
                content: '{"hypotheses": [{"title": "SQLi", "affectedEndpoint": "/search", "risk": "CRITICAL", "confidence": "HIGH"}]}',
              },
            },
          ],
          usage: { prompt_tokens: 300, completion_tokens: 60, total_tokens: 360 },
        }),
      });
      globalThis.fetch = mockFetch as any;

      const provider = new GroqModelProvider({ apiKey: 'gsk-test-mock' });
      const output = await provider.analyze(dummyBundle, DEFAULT_SECURITY_PROMPT);

      expect(output.providerId).toBe('groq');
      expect(output.parsedHypotheses[0].title).toBe('SQLi');
    });
  });
});

