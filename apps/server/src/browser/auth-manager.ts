import { resolve } from 'node:path';
import { mkdir, readFile, writeFile, unlink, readdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { chromium, type Browser, type BrowserContext } from 'playwright';

export interface StorageCookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  expires: number;
  httpOnly: boolean;
  secure: boolean;
  sameSite: 'Strict' | 'Lax' | 'None';
}

export interface StorageOrigin {
  origin: string;
  localStorage: Array<{ name: string; value: string }>;
}

export interface PlaywrightStorageState {
  cookies: StorageCookie[];
  origins: StorageOrigin[];
}

export interface AuthProfileMeta {
  name: string;
  slug: string;
  path: string;
  origins: string[];
  cookieCount: number;
  localStorageCount: number;
  createdAt: string;
  description?: string;
  hasJwtTokens: boolean;
}

export class AuthProfileManager {
  private static getProfilesDir(): string {
    const dir = process.env.TRACEHAWK_AUTH_DIR || resolve(process.cwd(), 'artifacts/auth-profiles');
    return dir;
  }

  private static sanitizeProfileName(name: string): string {
    return name
      .trim()
      .replace(/[^a-zA-Z0-9_-]/g, '_')
      .toLowerCase();
  }

  /**
   * Saves a Playwright storageState JSON file for an authenticated session profile.
   */
  public static async saveProfile(
    name: string,
    state: PlaywrightStorageState,
    metadata?: { description?: string; origin?: string }
  ): Promise<{ name: string; path: string }> {
    const dir = this.getProfilesDir();
    await mkdir(dir, { recursive: true });

    const slug = this.sanitizeProfileName(name);
    const filePath = resolve(dir, `${slug}.json`);

    const payload = {
      ...state,
      _tracehawk_meta: {
        name,
        slug,
        createdAt: new Date().toISOString(),
        description: metadata?.description,
        origin: metadata?.origin,
      },
    };

    await writeFile(filePath, JSON.stringify(payload, null, 2), 'utf8');
    return { name, path: filePath };
  }

  /**
   * Loads an existing auth profile's storageState.
   */
  public static async loadProfile(nameOrSlug: string): Promise<PlaywrightStorageState | null> {
    const filePath = this.getProfilePath(nameOrSlug);
    if (!filePath || !existsSync(filePath)) return null;

    try {
      const raw = await readFile(filePath, 'utf8');
      const data = JSON.parse(raw);
      return {
        cookies: Array.isArray(data.cookies) ? data.cookies : [],
        origins: Array.isArray(data.origins) ? data.origins : [],
      };
    } catch {
      return null;
    }
  }

  /**
   * Resolves the absolute path of a profile by name, slug, or direct path.
   */
  public static getProfilePath(nameOrPath: string): string | null {
    if (existsSync(nameOrPath)) return resolve(nameOrPath);

    const dir = this.getProfilesDir();
    const slug = this.sanitizeProfileName(nameOrPath);
    const candidate = resolve(dir, `${slug}.json`);

    return existsSync(candidate) ? candidate : null;
  }

  /**
   * Lists all saved authentication profiles.
   */
  public static async listProfiles(): Promise<AuthProfileMeta[]> {
    const dir = this.getProfilesDir();
    if (!existsSync(dir)) return [];

    const files = await readdir(dir);
    const results: AuthProfileMeta[] = [];

    for (const file of files) {
      if (!file.endsWith('.json')) continue;
      const fullPath = resolve(dir, file);
      try {
        const content = JSON.parse(await readFile(fullPath, 'utf8'));
        const cookies: StorageCookie[] = content.cookies || [];
        const origins: StorageOrigin[] = content.origins || [];

        const originList = origins.map((o) => o.origin);
        for (const c of cookies) {
          if (c.domain && !originList.includes(c.domain)) {
            originList.push(c.domain);
          }
        }

        const lsItems = origins.flatMap((o) => o.localStorage || []);
        const hasJwt =
          cookies.some((c) => c.value?.startsWith('eyJ')) ||
          lsItems.some((item) => item.value?.startsWith('eyJ') || /token|jwt|auth/i.test(item.name));

        results.push({
          name: content._tracehawk_meta?.name || file.replace(/\.json$/, ''),
          slug: file.replace(/\.json$/, ''),
          path: fullPath,
          origins: Array.from(new Set(originList)),
          cookieCount: cookies.length,
          localStorageCount: lsItems.length,
          createdAt: content._tracehawk_meta?.createdAt || new Date().toISOString(),
          description: content._tracehawk_meta?.description,
          hasJwtTokens: hasJwt,
        });
      } catch {
        // Skip corrupted files
      }
    }

    return results;
  }

  /**
   * Deletes an authentication profile.
   */
  public static async deleteProfile(nameOrSlug: string): Promise<boolean> {
    const path = this.getProfilePath(nameOrSlug);
    if (!path) return false;
    try {
      await unlink(path);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Exports an active Playwright BrowserContext's storageState directly to an auth profile.
   */
  public static async exportContextStorageState(
    context: BrowserContext,
    profileName: string,
    metadata?: { description?: string; origin?: string }
  ): Promise<{ name: string; path: string }> {
    const state = await context.storageState();
    return this.saveProfile(profileName, state as PlaywrightStorageState, metadata);
  }

  /**
   * Creates an authentication profile from a Bearer token or API key for Single Page Apps (SPAs).
   */
  public static async createBearerProfile(
    name: string,
    origin: string,
    token: string,
    storageKey = 'token'
  ): Promise<{ name: string; path: string }> {
    const cleanToken = token.replace(/^Bearer\s+/i, '').trim();
    const cleanOrigin = new URL(origin).origin;

    const state: PlaywrightStorageState = {
      cookies: [],
      origins: [
        {
          origin: cleanOrigin,
          localStorage: [
            { name: storageKey, value: cleanToken },
            { name: 'access_token', value: cleanToken },
            { name: 'auth_token', value: cleanToken },
          ],
        },
      ],
    };

    return this.saveProfile(name, state, {
      origin: cleanOrigin,
      description: `Bearer JWT profile created for ${cleanOrigin}`,
    });
  }

  /**
   * Interactive OAuth / SSO Login Recorder:
   * Launches a dedicated visible browser window for the user to complete their OAuth flow
   * (e.g. Google, GitHub, Okta, Auth0, Keycloak with 2FA/MFA if needed).
   * Once authentication redirects back to the target origin, captures storageState and saves the profile.
   */
  public static async recordInteractiveOAuth(
    targetUrl: string,
    options?: {
      profileName?: string;
      timeoutMs?: number;
      headless?: boolean;
    }
  ): Promise<{
    profileName: string;
    path: string;
    cookieCount: number;
    tokenCount: number;
  }> {
    const targetOrigin = new URL(targetUrl).origin;
    const profileName =
      options?.profileName || `oauth-${new URL(targetUrl).hostname}-${Date.now()}`;
    const timeoutMs = options?.timeoutMs || 180000; // 3 minutes for human to complete OAuth/2FA

    const browser = await chromium.launch({
      headless: options?.headless ?? false,
      args: ['--start-maximized'],
    });

    const context = await browser.newContext({
      viewport: null,
      ignoreHTTPSErrors: true,
    });

    const page = await context.newPage();
    console.log(`[OAuth Helper] Opening browser for target: ${targetUrl}`);
    console.log(`[OAuth Helper] Complete the login in the opened browser window.`);

    await page.goto(targetUrl).catch(() => {});

    // Wait until the user completes the OAuth redirect back to the target origin with auth cookies/tokens
    const startTime = Date.now();
    let authenticated = false;

    while (Date.now() - startTime < timeoutMs) {
      await page.waitForTimeout(1500);

      try {
        const currentUrl = page.url();
        const currentOrigin = new URL(currentUrl).origin;

        // Check if returned to target origin
        if (currentOrigin === targetOrigin && !/login|signin|oauth|auth/i.test(new URL(currentUrl).pathname)) {
          const state = await context.storageState();
          const hasCookies = state.cookies.some((c) => c.domain.includes(new URL(targetUrl).hostname));
          const hasStorage = state.origins.some((o) => o.origin === targetOrigin && o.localStorage.length > 0);

          if (hasCookies || hasStorage) {
            authenticated = true;
            break;
          }
        }
      } catch {
        // Continue waiting
      }
    }

    if (!authenticated) {
      await browser.close().catch(() => {});
      throw new Error(
        `OAuth login timed out or failed to detect authenticated session on ${targetOrigin} after ${Math.round(timeoutMs / 1000)}s.`
      );
    }

    const state = (await context.storageState()) as PlaywrightStorageState;
    const saveResult = await this.saveProfile(profileName, state, {
      origin: targetOrigin,
      description: `Interactive OAuth profile captured from ${targetUrl}`,
    });

    await browser.close().catch(() => {});

    const cookieCount = state.cookies.length;
    const tokenCount = state.origins.flatMap((o) => o.localStorage).length;

    console.log(`[OAuth Helper] Successfully captured OAuth profile '${profileName}' (${cookieCount} cookies, ${tokenCount} storage tokens)`);

    return {
      profileName,
      path: saveResult.path,
      cookieCount,
      tokenCount,
    };
  }

  /**
   * Helper to initialize a new authenticated Playwright BrowserContext with an auth profile or bearer headers.
   */
  public static async createAuthenticatedContext(
    browser: Browser,
    options?: {
      authProfile?: string;
      authHeaders?: Record<string, string>;
      ignoreHTTPSErrors?: boolean;
    }
  ): Promise<BrowserContext> {
    const contextOptions: Parameters<Browser['newContext']>[0] = {
      viewport: null,
      ignoreHTTPSErrors: options?.ignoreHTTPSErrors ?? true,
    };

    if (options?.authProfile) {
      const profilePath = this.getProfilePath(options.authProfile);
      if (profilePath) {
        contextOptions.storageState = profilePath;
      }
    }

    const context = await browser.newContext(contextOptions);

    if (options?.authHeaders && Object.keys(options.authHeaders).length > 0) {
      await context.setExtraHTTPHeaders(options.authHeaders);
    }

    return context;
  }
}

