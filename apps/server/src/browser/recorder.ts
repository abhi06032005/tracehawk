import { BrowserContext, Page, Request, Response, WebSocket } from "playwright";
import { prisma } from "../db.js";
import { sanitizeHeaders, sanitizeUrl, sanitizeBody, stripNullBytes, stripNullBytesDeep } from "../utils/redact.js";

export interface LiveTelemetryUpdate {
  type: "telemetry";
  sessionId: string;
  status: string;
  totalRequests: number;
  totalErrors: number;
  recentEndpoint?: {
    method: string;
    url: string;
    statusCode: number | null;
    duration: number | null;
    timestamp: string;
  };
  currentPageUrl?: string;
  activeTabsCount: number;
}

export type TelemetryListener = (update: LiveTelemetryUpdate) => void;

interface PendingExchange {
  id?: string;
  sessionId: string;
  timestamp: Date;
  method: string;
  url: string;
  statusCode?: number | null;
  requestHeaders?: Record<string, string | string[]>;
  responseHeaders?: Record<string, string | string[]>;
  sanitizedRequestBody?: string | null;
  sanitizedResponseBody?: string | null;
  contentType?: string | null;
  duration?: number | null;
  resourceType?: string | null;
  failureReason?: string | null;
  pageUrl?: string | null;
}

interface PendingBrowserEvent {
  sessionId: string;
  timestamp: Date;
  type: string;
  message: string;
  pageUrl?: string | null;
  metadata?: Record<string, unknown>;
}

export class SessionRecorder {
  private sessionId: string;
  private allowedOrigins: Set<string>;
  private isPaused: boolean = false;
  private isStopped: boolean = false;
  private requestStartTimes: Map<Request, number> = new Map();
  private pendingExchanges: PendingExchange[] = [];
  private pendingEvents: PendingBrowserEvent[] = [];
  private flushTimer: NodeJS.Timeout | null = null;
  private listeners: Set<TelemetryListener> = new Set();
  private currentPageUrl: string = "";
  private attachedPages = new WeakSet<Page>();

  public totalRequests: number = 0;
  public totalErrors: number = 0;

  constructor(sessionId: string, targetUrl: string, allowedOrigins: string[]) {
    this.sessionId = sessionId;
    this.allowedOrigins = new Set(allowedOrigins.map((o) => o.toLowerCase()));
    try {
      const targetOrigin = new URL(targetUrl).origin.toLowerCase();
      this.allowedOrigins.add(targetOrigin);
    } catch {
      // invalid target url handled elsewhere
    }

    // Periodic flush timer every 1000ms
    this.flushTimer = setInterval(() => {
      this.flushToDatabase().catch((err) =>
        console.error(`[Recorder:${this.sessionId}] Error during background flush:`, err)
      );
    }, 1000);
  }

  public addListener(listener: TelemetryListener): void {
    this.listeners.add(listener);
    // Emit immediate current state
    listener(this.getTelemetrySnapshot(1));
  }

  public removeListener(listener: TelemetryListener): void {
    this.listeners.delete(listener);
  }

  private broadcastTelemetry(activeTabsCount: number, recentEndpoint?: PendingExchange): void {
    const update = this.getTelemetrySnapshot(activeTabsCount, recentEndpoint);
    for (const listener of this.listeners) {
      try {
        listener(update);
      } catch (err) {
        console.error("Error in telemetry listener:", err);
      }
    }
  }

  public getTelemetrySnapshot(
    activeTabsCount: number = 1,
    recent?: PendingExchange
  ): LiveTelemetryUpdate {
    return {
      type: "telemetry",
      sessionId: this.sessionId,
      status: this.isPaused ? "PAUSED" : this.isStopped ? "STOPPED" : "RECORDING",
      totalRequests: this.totalRequests,
      totalErrors: this.totalErrors,
      recentEndpoint: recent
        ? {
          method: recent.method,
          url: recent.url,
          statusCode: recent.statusCode ?? null,
          duration: recent.duration ?? null,
          timestamp: recent.timestamp.toISOString(),
        }
        : undefined,
      currentPageUrl: this.currentPageUrl,
      activeTabsCount,
    };
  }

  public pause(): void {
    this.isPaused = true;
    this.broadcastTelemetry(1);
  }

  public resume(): void {
    this.isPaused = false;
    this.broadcastTelemetry(1);
  }

  public isInScope(url: string): boolean {
    try {
      const origin = new URL(url).origin.toLowerCase();
      if (this.allowedOrigins.has(origin)) return true;
      return false;
    } catch {
      return false;
    }
  }

  /**
   * Attaches network and console event listeners to a page
   */
  public attachToPage(page: Page, context: BrowserContext): void {
    if (this.attachedPages.has(page)) return;
    this.attachedPages.add(page);
    const getTabsCount = () => context.pages().filter((p) => !p.isClosed()).length;

    // Track page navigations
    page.on("framenavigated", (frame) => {
      if (frame === page.mainFrame()) {
        const url = frame.url();
        if (url && url !== "about:blank") {
          this.currentPageUrl = url;
          this.recordEvent("NAVIGATE", `Navigated to ${url}`, url);
          this.broadcastTelemetry(getTabsCount());
        }
      }
    });

    // Track console messages
    page.on("console", (msg) => {
      if (this.isPaused || this.isStopped) return;
      const type = msg.type();
      const text = msg.text();
      const pageUrl = page.url();

      if (type === "error") {
        this.totalErrors++;
        this.recordEvent("CONSOLE_ERROR", text, pageUrl);
        this.broadcastTelemetry(getTabsCount());
      } else if (type === "warning") {
        this.recordEvent("CONSOLE_WARN", text, pageUrl);
      }
    });

    // Track unhandled page errors
    page.on("pageerror", (error) => {
      if (this.isPaused || this.isStopped) return;
      this.totalErrors++;
      const pageUrl = page.url();
      this.recordEvent(
        "PAGE_CRASH",
        error.message || "Unhandled Page Error",
        pageUrl,
        { stack: error.stack }
      );
      this.broadcastTelemetry(getTabsCount());
    });

    // Track WebSockets
    page.on("websocket", (ws: WebSocket) => {
      if (this.isPaused || this.isStopped) return;
      const wsUrl = ws.url();
      this.recordEvent("WEBSOCKET", `WebSocket opened: ${wsUrl}`, page.url(), {
        url: wsUrl,
      });

      ws.on("framesent", (event) => {
        if (this.isPaused) return;
        this.recordEvent("WEBSOCKET_FRAME", `WS Frame sent to ${wsUrl}`, page.url(), {
          direction: "sent",
          payloadLength: typeof event.payload === "string" ? event.payload.length : (event.payload as Buffer)?.length || 0,
        });
      });

      ws.on("framereceived", (event) => {
        if (this.isPaused) return;
        this.recordEvent("WEBSOCKET_FRAME", `WS Frame received from ${wsUrl}`, page.url(), {
          direction: "received",
          payloadLength: typeof event.payload === "string" ? event.payload.length : (event.payload as Buffer)?.length || 0,
        });
      });
    });

    // Track Requests
    page.on("request", (request: Request) => {
      if (this.isPaused || this.isStopped) return;
      this.requestStartTimes.set(request, Date.now());
      this.totalRequests++;
    });

    // Track Responses
    page.on("response", async (response: Response) => {
      if (this.isPaused || this.isStopped) return;
      const request = response.request();
      const startTime = this.requestStartTimes.get(request) || Date.now();
      const duration = Date.now() - startTime;
      this.requestStartTimes.delete(request);

      const rawUrl = request.url();
      const inScope = this.isInScope(rawUrl);

      // Sanitize URL query parameters
      const { sanitizedUrl } = sanitizeUrl(rawUrl);
      const reqHeaders = sanitizeHeaders(request.headers());
      const resHeaders = sanitizeHeaders(response.headers());
      const contentType = response.headers()["content-type"] || "";
      const resourceType = request.resourceType();

      let sanitizedRequestBody: string | null = null;
      let sanitizedResponseBody: string | null = null;

      // Extract Request Body if present
      try {
        const postData = request.postData();
        if (postData) {
          sanitizedRequestBody = sanitizeBody(
            postData,
            request.headers()["content-type"]
          );
        }
      } catch {
        // Failed to get post data
      }

      // Extract Response Body for in-scope requests
      // Skip large media, video, audio, image binary payloads
      const isBinaryType =
        resourceType === "image" ||
        resourceType === "media" ||
        resourceType === "font" ||
        contentType.includes("image/") ||
        contentType.includes("video/") ||
        contentType.includes("audio/") ||
      contentType.includes("octet-stream") ||
        contentType.includes("wasm") ||
        contentType.includes("zip") ||
        contentType.includes("pdf");

      if (inScope && !isBinaryType) {
        try {
          const bodyBuffer = await response.body();
          if (bodyBuffer && bodyBuffer.length <= 512 * 1024) {
            const hasNullByte = bodyBuffer.includes(0);
            if (hasNullByte) {
              const isTextual =
                contentType.includes("json") ||
                contentType.includes("text") ||
                contentType.includes("javascript") ||
                contentType.includes("xml") ||
                contentType.includes("html");
              if (isTextual) {
                sanitizedResponseBody = sanitizeBody(
                  bodyBuffer.toString("utf-8").replace(/\0/g, ""),
                  contentType
                );
              } else {
                sanitizedResponseBody = "[BINARY_PAYLOAD_NOT_STORED]";
              }
            } else {
              sanitizedResponseBody = sanitizeBody(
                bodyBuffer.toString("utf-8"),
                contentType
              );
            }
          } else if (bodyBuffer && bodyBuffer.length > 512 * 1024) {
            sanitizedResponseBody = "[PAYLOAD_EXCEEDS_MAX_SIZE_512KB]";
          }
        } catch {
          sanitizedResponseBody = "[RESPONSE_BODY_UNAVAILABLE]";
        }
      } else if (!inScope) {
        sanitizedResponseBody = "[OUT_OF_SCOPE_PAYLOAD_NOT_STORED]";
      }

      const statusCode = response.status();
      if (statusCode >= 400) {
        this.totalErrors++;
      }

      const exchange: PendingExchange = {
        sessionId: this.sessionId,
        timestamp: new Date(startTime),
        method: request.method(),
        url: sanitizedUrl,
        statusCode,
        requestHeaders: reqHeaders,
        responseHeaders: resHeaders,
        sanitizedRequestBody,
        sanitizedResponseBody,
        contentType,
        duration,
        resourceType,
        pageUrl: page.url(),
      };

      this.pendingExchanges.push(exchange);
      this.broadcastTelemetry(getTabsCount(), exchange);

      if (this.pendingExchanges.length >= 25) {
        this.flushToDatabase().catch(console.error);
      }
    });

    // Track Request Failures (network errors, DNS resolution, aborted requests)
    page.on("requestfailed", (request: Request) => {
      if (this.isPaused || this.isStopped) return;
      const startTime = this.requestStartTimes.get(request) || Date.now();
      const duration = Date.now() - startTime;
      this.requestStartTimes.delete(request);
      this.totalErrors++;

      const rawUrl = request.url();
      const { sanitizedUrl } = sanitizeUrl(rawUrl);
      const failure = request.failure();
      const failureReason = failure ? failure.errorText : "Network Request Failed";

      const exchange: PendingExchange = {
        sessionId: this.sessionId,
        timestamp: new Date(startTime),
        method: request.method(),
        url: sanitizedUrl,
        statusCode: null,
        requestHeaders: sanitizeHeaders(request.headers()),
        responseHeaders: undefined,
        sanitizedRequestBody: sanitizeBody(request.postData()),
        sanitizedResponseBody: null,
        contentType: null,
        duration,
        resourceType: request.resourceType(),
        failureReason,
        pageUrl: page.url(),
      };

      this.pendingExchanges.push(exchange);
      this.recordEvent("REQUEST_FAILED", `${request.method()} ${sanitizedUrl} failed: ${failureReason}`, page.url());
      this.broadcastTelemetry(getTabsCount(), exchange);
    });
  }

  public recordEvent(
    type: string,
    message: string,
    pageUrl?: string,
    metadata?: Record<string, unknown>
  ): void {
    this.pendingEvents.push({
      sessionId: this.sessionId,
      timestamp: new Date(),
      type: stripNullBytes(type),
      message: stripNullBytes(sanitizeBody(message, 'text/plain', 8192)) || '',
      pageUrl: stripNullBytes(pageUrl || this.currentPageUrl),
      metadata: stripNullBytesDeep(metadata),
    });
  }

  /**
   * Flushes queued HTTP exchanges and browser events to PostgreSQL
   */
  public async flushToDatabase(): Promise<void> {
    if (this.pendingExchanges.length === 0 && this.pendingEvents.length === 0) {
      return;
    }

    const exchangesToFlush = [...this.pendingExchanges];
    const eventsToFlush = [...this.pendingEvents];
    this.pendingExchanges = [];
    this.pendingEvents = [];

    try {
      if (exchangesToFlush.length > 0) {
        await prisma.httpExchange.createMany({
          data: exchangesToFlush.map((ex) => ({
            sessionId: ex.sessionId,
            timestamp: ex.timestamp,
            method: stripNullBytes(ex.method) || "GET",
            url: stripNullBytes(ex.url) || "",
            statusCode: ex.statusCode,
            requestHeaders: stripNullBytesDeep(ex.requestHeaders) as any,
            responseHeaders: stripNullBytesDeep(ex.responseHeaders) as any,
            sanitizedRequestBody: stripNullBytes(ex.sanitizedRequestBody),
            sanitizedResponseBody: stripNullBytes(ex.sanitizedResponseBody),
            contentType: stripNullBytes(ex.contentType),
            duration: ex.duration,
            resourceType: stripNullBytes(ex.resourceType),
            failureReason: stripNullBytes(ex.failureReason),
            pageUrl: stripNullBytes(ex.pageUrl),
          })),
        });
      }

      if (eventsToFlush.length > 0) {
        await prisma.browserEvent.createMany({
          data: eventsToFlush.map((ev) => ({
            sessionId: ev.sessionId,
            timestamp: ev.timestamp,
            type: stripNullBytes(ev.type) || "EVENT",
            message: stripNullBytes(ev.message) || "",
            pageUrl: stripNullBytes(ev.pageUrl),
            metadata: stripNullBytesDeep(ev.metadata) as any,
          })),
        });
      }

      // Update session totals in database
      await prisma.session.update({
        where: { id: this.sessionId },
        data: {
          totalRequests: this.totalRequests,
          totalErrors: this.totalErrors,
        },
      });
    } catch (error: any) {
      console.error(`[Recorder:${this.sessionId}] Error persisting batch to database:`, error);
      // If error is code 22021 (invalid byte sequence / null byte) or P2039 driver error:
      // Don't re-queue a corrupted batch in an infinite crash loop.
      if (
        error?.code === "P2039" ||
        error?.message?.includes("22021") ||
        error?.message?.includes("invalid byte sequence")
      ) {
        console.warn(
          `[Recorder:${this.sessionId}] Dropped corrupted batch containing invalid encoding bytes to prevent retry loop.`
        );
      } else {
        // Re-queue items that failed due to transient database connection drops
        this.pendingExchanges.unshift(...exchangesToFlush);
        this.pendingEvents.unshift(...eventsToFlush);
      }
    }
  }

  /**
   * Stops the recorder, flushes all pending data, and cleans up timers
   */
  public async stop(): Promise<void> {
    this.isStopped = true;
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
    await this.flushToDatabase();
  }
}
