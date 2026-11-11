import type { ModelProvider } from '../types.js';
import { DeepHatModelProvider } from './deephat.js';
import { OpenAIModelProvider } from './openai.js';
import { GeminiModelProvider } from './gemini.js';
import { GroqModelProvider } from './groq.js';
import { WhiteRabbitNeoModelProvider } from './whiterabbitneo.js';

export class ModelProviderRegistry {
  private static providers = new Map<string, () => ModelProvider>([
    ['deephat', () => new DeepHatModelProvider()],
    ['gpt', () => new OpenAIModelProvider()],
    ['openai', () => new OpenAIModelProvider()],
    ['gemini', () => new GeminiModelProvider()],
    ['groq', () => new GroqModelProvider()],
    ['whiterabbitneo', () => new WhiteRabbitNeoModelProvider()],
  ]);

  /**
   * Instantiates a model provider by its identifier.
   */
  public static getProvider(id: string): ModelProvider {
    const factory = this.providers.get(id.toLowerCase());
    if (!factory) {
      throw new Error(
        `Unknown model provider ID '${id}'. Supported providers: [${[
          'deephat',
          'gpt',
          'gemini',
          'groq',
          'whiterabbitneo',
        ].join(', ')}]`
      );
    }
    return factory();
  }

  /**
   * Registers a custom or mock provider instance (useful for testing or extensions).
   */
  public static registerProvider(id: string, factory: () => ModelProvider): void {
    this.providers.set(id.toLowerCase(), factory);
  }

  /**
   * Lists available provider metadata and configuration readiness.
   */
  public static listProviders(): Array<{
    id: string;
    name: string;
    defaultModel: string;
    isConfigured: boolean;
  }> {
    const list = [
      {
        id: 'deephat',
        name: 'DeepHat-V1-7B (vLLM)',
        defaultModel: process.env.AI_MODEL || 'DeepHat/DeepHat-V1-7B',
        isConfigured: Boolean(process.env.AI_BASE_URL),
      },
      {
        id: 'gpt',
        name: 'OpenAI API (GPT)',
        defaultModel: process.env.OPENAI_MODEL || 'gpt-4o',
        isConfigured: Boolean(process.env.OPENAI_API_KEY),
      },
      {
        id: 'gemini',
        name: 'Google Gemini API',
        defaultModel: process.env.GEMINI_MODEL || 'gemini-flash-lite-latest',
        isConfigured: Boolean(process.env.GEMINI_API_KEY),
      },
      {
        id: 'groq',
        name: 'Groq Hosted LLM API',
        defaultModel: process.env.GROQ_MODEL || 'qwen/qwen3.8-27b',
        isConfigured: Boolean(process.env.GROQ_API_KEY),
      },
      {
        id: 'whiterabbitneo',
        name: 'WhiteRabbitNeo (vLLM)',
        defaultModel: process.env.WHITERABBITNEO_MODEL || 'WhiteRabbitNeo-33B',
        isConfigured: Boolean(process.env.WHITERABBITNEO_BASE_URL),
      },
    ];
    return list;
  }
}

