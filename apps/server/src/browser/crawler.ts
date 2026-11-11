import type { BrowserContext, Page } from 'playwright';
import { SecurityPolicyGateway } from '../security/policy.js';

export interface DiscoveredEndpoint {
  method: string;
  url: string;
  source: 'link' | 'form' | 'xhr' | 'script' | 'dom';
  parameters?: string[];
}

export interface DiscoveredForm {
  pageUrl: string;
  action: string;
  method: string;
  fields: Array<{
    name: string;
    type: string;
    required: boolean;
    defaultValue?: string;
  }>;
}

export interface CrawlResult {
  targetUrl: string;
  visitedUrls: string[];
  endpoints: DiscoveredEndpoint[];
  forms: DiscoveredForm[];
  identifiedTech: string[];
  authRoutes: string[];
  durationMs: number;
}

export interface CrawlerOptions {
  maxPages?: number;
  maxDepth?: number;
  allowedOrigins: string[];
  signal?: AbortSignal;
  onProgress?: (visited: number, queueSize: number, currentUrl: string) => void;
  authProfile?: string;
  authHeaders?: Record<string, string>;
}

export class PlaywrightCrawler {
  /**
   * Autonomously crawls an authorized target web application using an existing Playwright browser context.
   */
  public static async crawl(
    context: BrowserContext,
    targetUrl: string,
    options: CrawlerOptions
  ): Promise<CrawlResult> {
    const startTime = Date.now();
    const maxPages = options.maxPages ?? 20;
    const maxDepth = options.maxDepth ?? 3;
    const allowedOrigins = options.allowedOrigins;
    const signal = options.signal;

    // Validate root target scope
    const rootCheck = SecurityPolicyGateway.isTargetInScope(targetUrl, allowedOrigins);
    if (!rootCheck.allowed) {
      throw new Error(`Crawler target out of scope: ${rootCheck.reason}`);
    }

    // Apply extra authentication headers (e.g. Bearer JWT) if provided
    if (options.authHeaders && Object.keys(options.authHeaders).length > 0) {
      try {
        await context.setExtraHTTPHeaders(options.authHeaders);
      } catch {
        // Ignore if headers cannot be set on mocked context in tests
      }
    }

    const visited = new Set<string>();
    const queue: Array<{ url: string; depth: number }> = [{ url: targetUrl, depth: 0 }];
    const endpointsMap = new Map<string, DiscoveredEndpoint>();
    const forms: DiscoveredForm[] = [];
    const techSet = new Set<string>();
    const authRoutesSet = new Set<string>();

    const normalizeUrl = (rawUrl: string): string | null => {
      try {
        const u = new URL(rawUrl);
        u.hash = ''; // strip fragment
        return u.toString();
      } catch {
        return null;
      }
    };

    const isAuthCandidate = (urlStr: string): boolean => {
      const lower = urlStr.toLowerCase();
      return /login|signin|sign-in|auth|signup|sign-up|register|password|oauth|session|token|profile|account/i.test(lower);
    };

    let page: Page | null = null;

    try {
      page = await context.newPage();

      while (queue.length > 0 && visited.size < maxPages) {
        if (signal?.aborted) break;

        const current = queue.shift()!;
        const normalized = normalizeUrl(current.url);

        if (!normalized || visited.has(normalized)) continue;

        // Scope check before navigating
        if (!SecurityPolicyGateway.isTargetInScope(normalized, allowedOrigins).allowed) {
          continue;
        }

        visited.add(normalized);
        if (options.onProgress) {
          options.onProgress(visited.size, queue.length, normalized);
        }

        if (isAuthCandidate(normalized)) {
          authRoutesSet.add(normalized);
        }

        endpointsMap.set(`GET ${normalized}`, {
          method: 'GET',
          url: normalized,
          source: 'link',
        });

        try {
          // Navigate with timeout
          const response = await page.goto(normalized, {
            waitUntil: 'domcontentloaded',
            timeout: 10000,
          });

          if (!response) continue;

          // Technology fingerprinting from headers
          const serverHeader = response.headers()['server'];
          if (serverHeader) techSet.add(`Server: ${serverHeader}`);
          const poweredBy = response.headers()['x-powered-by'];
          if (poweredBy) techSet.add(`Framework: ${poweredBy}`);

          // Wait a moment for dynamic SPAs (e.g. React/Angular/Vue)
          await page.waitForTimeout(500);

          if (signal?.aborted) break;

          // Extract DOM elements: links, forms, scripts, meta tags
          const domExtraction = await page.evaluate(() => {
            // 1. Extract Links
            const anchors = Array.from(document.querySelectorAll('a[href]'));
            const hrefs = anchors.map((a) => (a as HTMLAnchorElement).href).filter(Boolean);

            // 2. Extract Forms
            const formElements = Array.from(document.querySelectorAll('form'));
            const extractedForms = formElements.map((f) => {
              const action = f.action || window.location.href;
              const method = (f.method || 'GET').toUpperCase();
              const inputs = Array.from(f.querySelectorAll('input, select, textarea'));
              const fields = inputs.map((input) => {
                const el = input as HTMLInputElement;
                return {
                  name: el.name || el.id || 'unnamed',
                  type: el.type || 'text',
                  required: el.required || false,
                  defaultValue: el.value || undefined,
                };
              });
              return { action, method, fields };
            });

            // 3. Framework clues from DOM
            const domTech: string[] = [];
            if ((window as any).__NEXT_DATA__) domTech.push('Next.js');
            if ((window as any).__REACT_DEVTOOLS_GLOBAL_HOOK__) domTech.push('React');
            if ((window as any).angular || document.querySelector('[ng-app], [ng-version]')) domTech.push('Angular');
            if ((window as any).__VUE__ || document.querySelector('[data-v-]')) domTech.push('Vue.js');

            return { hrefs, extractedForms, domTech };
          });

          // Process detected technologies
          for (const tech of domExtraction.domTech) {
            techSet.add(tech);
          }

          // Process forms
          for (const f of domExtraction.extractedForms) {
            const formActionNorm = normalizeUrl(f.action);
            if (formActionNorm && SecurityPolicyGateway.isTargetInScope(formActionNorm, allowedOrigins).allowed) {
              forms.push({
                pageUrl: normalized,
                action: formActionNorm,
                method: f.method,
                fields: f.fields,
              });

              endpointsMap.set(`${f.method} ${formActionNorm}`, {
                method: f.method,
                url: formActionNorm,
                source: 'form',
                parameters: f.fields.map((field) => field.name),
              });

              if (isAuthCandidate(formActionNorm)) {
                authRoutesSet.add(formActionNorm);
              }
            }
          }

          // Process discovered links for the queue if within max depth
          if (current.depth < maxDepth) {
            for (const href of domExtraction.hrefs) {
              const nextUrl = normalizeUrl(href);
              if (
                nextUrl &&
                !visited.has(nextUrl) &&
                SecurityPolicyGateway.isTargetInScope(nextUrl, allowedOrigins).allowed
              ) {
                // Avoid queuing static assets
                if (!/\.(png|jpg|jpeg|gif|svg|ico|css|woff|woff2|ttf|eot|pdf|zip)$/i.test(nextUrl)) {
                  queue.push({ url: nextUrl, depth: current.depth + 1 });
                }
              }
            }
          }
        } catch (navError: any) {
          // Continue gracefully if a single page fails or times out
          console.warn(`[Crawler] Failed navigating to ${normalized}:`, navError.message);
        }
      }
    } finally {
      if (page && !page.isClosed()) {
        await page.close().catch(() => {});
      }
    }

    return {
      targetUrl,
      visitedUrls: [...visited],
      endpoints: [...endpointsMap.values()],
      forms,
      identifiedTech: [...techSet],
      authRoutes: [...authRoutesSet],
      durationMs: Date.now() - startTime,
    };
  }
}

