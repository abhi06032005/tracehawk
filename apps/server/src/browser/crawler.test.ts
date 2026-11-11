import { describe, expect, it, vi } from 'vitest';
import { PlaywrightCrawler } from './crawler.js';

describe('PlaywrightCrawler', () => {
  const allowedOrigins = ['http://127.0.0.1:3000'];

  it('rejects target if root target is outside allowed scope', async () => {
    const mockContext: any = {
      newPage: vi.fn(),
    };

    await expect(
      PlaywrightCrawler.crawl(mockContext, 'https://unauthorized-evil.com', {
        allowedOrigins,
      })
    ).rejects.toThrow(/Crawler target out of scope/);
  });

  it('navigates root page, extracts links and forms, and classifies auth routes', async () => {
    const mockPage: any = {
      isClosed: vi.fn().mockReturnValue(false),
      close: vi.fn().mockResolvedValue(undefined),
      goto: vi.fn().mockResolvedValue({
        headers: () => ({
          server: 'nginx/1.24.0',
          'x-powered-by': 'Express',
        }),
      }),
      waitForTimeout: vi.fn().mockResolvedValue(undefined),
      evaluate: vi.fn().mockResolvedValue({
        hrefs: [
          'http://127.0.0.1:3000/rest/user/login',
          'http://127.0.0.1:3000/about',
          'https://external.com/privacy', // Out of scope
        ],
        extractedForms: [
          {
            action: 'http://127.0.0.1:3000/api/login',
            method: 'POST',
            fields: [
              { name: 'email', type: 'email', required: true },
              { name: 'password', type: 'password', required: true },
            ],
          },
        ],
        domTech: ['React', 'Next.js'],
      }),
    };

    const mockContext: any = {
      newPage: vi.fn().mockResolvedValue(mockPage),
    };

    const result = await PlaywrightCrawler.crawl(mockContext, 'http://127.0.0.1:3000', {
      allowedOrigins,
      maxPages: 2,
      maxDepth: 1,
    });

    expect(result.targetUrl).toBe('http://127.0.0.1:3000');
    expect(result.visitedUrls).toContain('http://127.0.0.1:3000/');
    expect(result.identifiedTech).toContain('Server: nginx/1.24.0');
    expect(result.identifiedTech).toContain('Framework: Express');
    expect(result.identifiedTech).toContain('React');
    expect(result.identifiedTech).toContain('Next.js');

    // Verify auth route detection
    expect(result.authRoutes).toContain('http://127.0.0.1:3000/api/login');

    // Verify forms
    expect(result.forms.length).toBeGreaterThanOrEqual(1);
    expect(result.forms[0].action).toBe('http://127.0.0.1:3000/api/login');
    expect(result.forms[0].method).toBe('POST');
    expect(result.forms[0].fields).toHaveLength(2);

    // Verify endpoints
    const postEndpoint = result.endpoints.find((e) => e.method === 'POST');
    expect(postEndpoint).toBeDefined();
    expect(postEndpoint?.url).toBe('http://127.0.0.1:3000/api/login');
    expect(postEndpoint?.parameters).toEqual(['email', 'password']);
  });

  it('honors AbortSignal and terminates crawl early', async () => {
    const controller = new AbortController();
    controller.abort();

    const mockPage: any = {
      isClosed: vi.fn().mockReturnValue(false),
      close: vi.fn().mockResolvedValue(undefined),
      goto: vi.fn(),
      evaluate: vi.fn(),
    };

    const mockContext: any = {
      newPage: vi.fn().mockResolvedValue(mockPage),
    };

    const result = await PlaywrightCrawler.crawl(mockContext, 'http://127.0.0.1:3000', {
      allowedOrigins,
      signal: controller.signal,
    });

    expect(result.visitedUrls).toHaveLength(0);
    expect(mockPage.goto).not.toHaveBeenCalled();
  });
});
