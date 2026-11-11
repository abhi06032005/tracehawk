import { BrowserContext, Page } from "playwright";
import { prisma } from "../db.js";
import { sanitizeStorageValue } from "../utils/redact.js";

export interface StorageItem {
  origin: string;
  storageType: "COOKIE" | "LOCAL_STORAGE" | "SESSION_STORAGE" | "INDEXED_DB";
  key: string;
  sanitizedValue: string;
  metadata?: Record<string, unknown>;
}

/**
 * Collects cookies from the browser context
 */
export async function collectCookies(context: BrowserContext): Promise<StorageItem[]> {
  try {
    const cookies = await context.cookies();
    return cookies.map((c) => ({
      origin: `${c.secure ? "https://" : "http://"}${c.domain.startsWith(".") ? c.domain.substring(1) : c.domain}`,
      storageType: "COOKIE" as const,
      key: c.name,
      sanitizedValue: '[COOKIE_VALUE_OMITTED]',
      metadata: {
        domain: c.domain,
        path: c.path,
        expires: c.expires,
        httpOnly: c.httpOnly,
        secure: c.secure,
        sameSite: c.sameSite,
      },
    }));
  } catch (error) {
    console.error("Failed to collect cookies:", error);
    return [];
  }
}

/**
 * Collects Web Storage (localStorage & sessionStorage) from an active page
 */
export async function collectPageWebStorage(page: Page): Promise<StorageItem[]> {
  try {
    if (page.isClosed()) return [];

    const storageData = await page.evaluate(() => {
      const items: Array<{
        storageType: "LOCAL_STORAGE" | "SESSION_STORAGE";
        key: string;
        value: string;
      }> = [];

      try {
        for (let i = 0; i < localStorage.length; i++) {
          const key = localStorage.key(i);
          if (key) {
            items.push({
              storageType: "LOCAL_STORAGE",
              key,
              value: localStorage.getItem(key) || "",
            });
          }
        }
      } catch (e) {
        // Access denied (e.g. cross-origin iframe or restricted origin)
      }

      try {
        for (let i = 0; i < sessionStorage.length; i++) {
          const key = sessionStorage.key(i);
          if (key) {
            items.push({
              storageType: "SESSION_STORAGE",
              key,
              value: sessionStorage.getItem(key) || "",
            });
          }
        }
      } catch (e) {
        // Access denied
      }

      return items;
    });

    const origin = new URL(page.url()).origin;

    return storageData.map((item) => ({
      origin,
      storageType: item.storageType,
      key: item.key,
      sanitizedValue: sanitizeStorageValue(item.key, item.value),
    }));
  } catch {
    return [];
  }
}

/**
 * Collects IndexedDB database metadata from an active page
 */
export async function collectPageIndexedDB(page: Page): Promise<StorageItem[]> {
  try {
    if (page.isClosed()) return [];

    const dbNames = await page.evaluate(async () => {
      try {
        const idb = (window as any).indexedDB;
        if (!idb || !idb.databases) return [];
        const databases = await idb.databases();
        return (databases as Array<{ name?: string }>)
          .map((db) => db.name)
          .filter((n): n is string => Boolean(n));
      } catch {
        return [];
      }
    });

    const origin = new URL(page.url()).origin;

    return dbNames.map((dbName: string) => ({
      origin,
      storageType: "INDEXED_DB" as const,
      key: dbName,
      sanitizedValue: "[INDEXED_DB_DATABASE]",
    }));
  } catch {
    return [];
  }
}

/**
 * Captures full storage snapshot across all pages in context and persists to database
 */
export async function captureAndPersistStorage(
  sessionId: string,
  context: BrowserContext
): Promise<StorageItem[]> {
  const allItems: StorageItem[] = [];

  // 1. Context Cookies
  const cookies = await collectCookies(context);
  allItems.push(...cookies);

  // 2. Page storages
  const pages = context.pages();
  for (const page of pages) {
    if (!page.isClosed() && page.url() && page.url() !== "about:blank") {
      const webStorage = await collectPageWebStorage(page);
      allItems.push(...webStorage);

      const idb = await collectPageIndexedDB(page);
      allItems.push(...idb);
    }
  }

  // Deduplicate items by origin + storageType + key
  const uniqueItems = new Map<string, StorageItem>();
  for (const item of allItems) {
    const key = `${item.origin}:${item.storageType}:${item.key}`;
    uniqueItems.set(key, item);
  }

  const itemsToPersist = Array.from(uniqueItems.values());

  if (itemsToPersist.length > 0) {
    try {
      await prisma.storageObservation.createMany({
        data: itemsToPersist.map((item) => ({
          sessionId,
          origin: item.origin,
          storageType: item.storageType,
          key: item.key,
          sanitizedValue: item.sanitizedValue,
          metadata: item.metadata as any,
          timestamp: new Date(),
        })),
        skipDuplicates: true,
      });
    } catch (error) {
      console.error(`Failed to persist storage observations for session ${sessionId}:`, error);
    }
  }

  return itemsToPersist;
}
