import { Browser, BrowserContext, chromium } from "playwright";
import { Response } from "express";
import path from "node:path";
import fs from "node:fs";
import { prisma } from "../db.js";
import { SessionRecorder, LiveTelemetryUpdate } from "./recorder.js";
import { captureAndPersistStorage } from "./storage.js";
import { attachCredentialCapture } from './credentials.js';
import { controlExtensionSession, focusExtensionSession } from './extension.js';
import { AuthProfileManager } from './auth-manager.js';

const PROFILE_DIR = process.env.TRACEHAWK_PROFILE_DIR || path.resolve("d:/tracehawk/.tracehawk-profile");

interface ActiveSessionEntry {
  sessionId: string;
  projectId: string;
  browser?: Browser | null;
  context: BrowserContext;
  recorder: SessionRecorder;
  isStopping: boolean;
  browserName: string;
  stopCredentialCapture: () => Promise<void>;
}

export class BrowserManager {
  private static instance: BrowserManager;
  private activeSessions: Map<string, ActiveSessionEntry> = new Map();
  private sseClients: Map<string, Set<Response>> = new Map();

  private constructor() {}

  public static getInstance(): BrowserManager {
    if (!BrowserManager.instance) {
      BrowserManager.instance = new BrowserManager();
    }
    return BrowserManager.instance;
  }

  public getProfileDir(): string {
    return PROFILE_DIR;
  }

  public clearPersistentProfile(): { success: boolean; message: string } {
    if (this.activeSessions.size > 0) {
      throw new Error("Cannot clear profile while a recording session is active. Please stop the session first.");
    }
    if (fs.existsSync(PROFILE_DIR)) {
      try {
        fs.rmSync(PROFILE_DIR, { recursive: true, force: true });
        fs.mkdirSync(PROFILE_DIR, { recursive: true });
        return { success: true, message: "Persistent browser profile and saved sign-ins cleared." };
      } catch (e: any) {
        throw new Error(`Failed to clear profile directory: ${e.message}`);
      }
    }
    return { success: true, message: "Profile was already empty." };
  }

  public getActiveSession(sessionId: string): ActiveSessionEntry | undefined {
    return this.activeSessions.get(sessionId);
  }

  public getActiveSessionsCount(): number {
    return this.activeSessions.size;
  }

  /**
   * Launches a dedicated visible Chromium browser with a persistent profile and begins recording
   */
  public async launchSession(
    projectId: string,
    targetUrl: string,
    options?: {
      authProfile?: string;
      authHeaders?: Record<string, string>;
    }
  ): Promise<{ sessionId: string; status: string; browserName: string }> {
    // 1. Verify project exists
    const project = await prisma.project.findUnique({
      where: { id: projectId },
    });
    if (!project) {
      throw new Error(`Project with ID ${projectId} not found`);
    }

    // Validate target URL format
    try {
      const target = new URL(targetUrl);
      if (!['http:', 'https:'].includes(target.protocol) || target.username || target.password) throw new Error('Use an HTTP or HTTPS URL without credentials');
      if (!project.allowedOrigins.map(o => new URL(o).origin).includes(target.origin)) throw new Error('Target is outside the project allowed origins');
    } catch {
      throw new Error(`Invalid target URL: ${targetUrl}`);
    }

    // Stop any existing active session
    if (this.activeSessions.size > 0) {
      for (const [activeId] of this.activeSessions) {
        console.log(`[BrowserManager] Stopping previous active session ${activeId}...`);
        try {
          await this.stopSession(activeId);
        } catch (stopErr) {
          console.warn(`[BrowserManager] Error stopping previous session:`, stopErr);
        }
      }
    }

    // 2. Create Session in database
    const session = await prisma.session.create({
      data: {
        projectId,
        status: "RECORDING",
        startedAt: new Date(),
        totalRequests: 0,
        totalErrors: 0,
      },
    });

    const sessionId = session.id;

    // 3. Launch normal dedicated visible browser
    let browser: Browser | null = null;
    let context: BrowserContext;
    let browserName = 'Google Chrome';

    const launchArgs = [
      '--start-maximized',

    ];

    try {
      try {
        browser = await chromium.launch({
          headless: false,
          channel: 'chrome',
          args: launchArgs,
        });
      } catch (chromeErr: any) {
        if(!/executable|distribution.*not found/i.test(chromeErr.message))throw chromeErr;
        browserName = 'Chromium';
        browser = await chromium.launch({
          headless: false,
          args: launchArgs,
        });
      }

      const contextOptions: Parameters<Browser['newContext']>[0] = {
        viewport: null,
        ignoreHTTPSErrors: true,
      };

      if (options?.authProfile) {
        const profilePath = AuthProfileManager.getProfilePath(options.authProfile);
        if (profilePath) {
          console.log(`[BrowserManager] Hydrating browser session with auth profile: ${profilePath}`);
          contextOptions.storageState = profilePath;
        }
      }

      context = await browser.newContext(contextOptions);

      if (options?.authHeaders && Object.keys(options.authHeaders).length > 0) {
        await context.setExtraHTTPHeaders(options.authHeaders);
      }
    } catch (err: any) {
      await browser?.close().catch(()=>{});
      // Mark session as failed
      await prisma.session.update({
        where: { id: sessionId },
        data: { status: "STOPPED", endedAt: new Date() },
      });
      throw new Error(`Failed to launch visible browser: ${err.message}`);
    }

    // 5. Initialize Recorder
    const allowedOrigins = [...(project.allowedOrigins || []), targetUrl];
    const recorder = new SessionRecorder(sessionId, targetUrl, allowedOrigins);

    const activeEntry: ActiveSessionEntry = {
      sessionId,
      projectId,
      browser,
      context,
      recorder,
      isStopping: false,
      browserName,
      stopCredentialCapture: attachCredentialCapture(sessionId, context, project.allowedOrigins, () => recorder.getTelemetrySnapshot().status === 'RECORDING'),
    };
    this.activeSessions.set(sessionId, activeEntry);

    // Stream recorder telemetry to all SSE clients for this session
    recorder.addListener((update) => {
      this.broadcastToSse(sessionId, update);
    });

    // 6. Handle multi-tab management & popups
    context.on("page", (newPage) => {
      recorder.attachToPage(newPage, context);
      recorder.recordEvent("TAB_OPENED", `New tab opened: ${newPage.url() || "about:blank"}`, newPage.url());

      newPage.on("close", () => {
        recorder.recordEvent("TAB_CLOSED", `Tab closed: ${newPage.url() || ""}`, newPage.url());
      });
    });

    // Attach to existing pages in the persistent context
    for (const p of context.pages()) {
      recorder.attachToPage(p, context);
    }

    // 7. Handle manual browser closure gracefully
    const handleBrowserClosure = async () => {
      if (activeEntry.isStopping) return;
      activeEntry.isStopping = true;
      await activeEntry.stopCredentialCapture();

      console.log(`[BrowserManager] Browser closed manually for session ${sessionId}. Finalizing...`);

      try {
        // Collect storage before closing context if context is still active
        await captureAndPersistStorage(sessionId, context).catch(() => {});
      } catch {}

      try {
        await recorder.stop();
      } catch (err) {
        console.error("Error stopping recorder on manual browser close:", err);
      }

      await prisma.session.update({
        where: { id: sessionId },
        data: {
          status: "STOPPED",
          endedAt: new Date(),
          totalRequests: recorder.totalRequests,
          totalErrors: recorder.totalErrors,
        },
      });

      this.broadcastToSse(sessionId, {
        type: "telemetry",
        sessionId,
        status: "STOPPED",
        totalRequests: recorder.totalRequests,
        totalErrors: recorder.totalErrors,
        activeTabsCount: 0,
      });

      this.activeSessions.delete(sessionId);
    };

    context.on("close", handleBrowserClosure);
    if (browser) {
      browser.on("disconnected", handleBrowserClosure);
    }

    // 8. Open initial page & attach recorder
    const initialPage = context.pages().length > 0 ? context.pages()[0] : await context.newPage();
    recorder.attachToPage(initialPage, context);

    // Record initial browser launch event
    recorder.recordEvent(
      "BROWSER_LAUNCHED",
      `Dedicated visible ${browserName} launched for target: ${targetUrl}`,
      targetUrl
    );

    // Navigate to target URL
    try {
      await initialPage.goto(targetUrl, { waitUntil: "domcontentloaded", timeout: 30000 });
      await initialPage.bringToFront().catch(() => {});
    } catch (navErr: any) {
      console.warn(`[BrowserManager] Initial navigation warning for ${targetUrl}:`, navErr.message);
      recorder.recordEvent(
        "NAVIGATE_WARNING",
        `Initial navigation error: ${navErr.message}`,
        targetUrl
      );
    }

    return { sessionId, status: "RECORDING", browserName };
  }

  public async focusBrowser(sessionId: string): Promise<void> {
    if(focusExtensionSession(sessionId))return;
    const active = this.activeSessions.get(sessionId);
    if (!active) throw new Error('The recording browser is closed. Start a new session.');
    const pages = active.context.pages().filter(p => !p.isClosed());
    if (!pages.length) throw new Error('No connected browser tab is open');
    await pages[pages.length - 1].bringToFront();
    if (process.platform === 'win32') {
      try {
        const { exec } = await import('node:child_process');
        const targetTitle = active.browserName.toLowerCase().includes('chrome') ? 'Chrome' : active.browserName;
        exec(`powershell -command "(New-Object -ComObject WScript.Shell).AppActivate('${targetTitle}')"`);
      } catch {}
    }
  }

  /**
   * Pauses an active recording session
   */
  public async pauseSession(sessionId: string): Promise<void> {
    if(await controlExtensionSession(sessionId,'PAUSED'))return;
    const active = this.activeSessions.get(sessionId);
    if (!active) {
      throw new Error(`Active session ${sessionId} not found`);
    }

    active.recorder.pause();
    await prisma.session.update({
      where: { id: sessionId },
      data: { status: "PAUSED" },
    });

    this.broadcastToSse(sessionId, {
      type: "telemetry",
      sessionId,
      status: "PAUSED",
      totalRequests: active.recorder.totalRequests,
      totalErrors: active.recorder.totalErrors,
      activeTabsCount: active.context.pages().filter((p) => !p.isClosed()).length,
    });
  }

  /**
   * Resumes a paused recording session
   */
  public async resumeSession(sessionId: string): Promise<void> {
    if(await controlExtensionSession(sessionId,'RECORDING'))return;
    const active = this.activeSessions.get(sessionId);
    if (!active) {
      throw new Error(`Active session ${sessionId} not found`);
    }

    active.recorder.resume();
    await prisma.session.update({
      where: { id: sessionId },
      data: { status: "RECORDING" },
    });

    this.broadcastToSse(sessionId, {
      type: "telemetry",
      sessionId,
      status: "RECORDING",
      totalRequests: active.recorder.totalRequests,
      totalErrors: active.recorder.totalErrors,
      activeTabsCount: active.context.pages().filter((p) => !p.isClosed()).length,
    });
  }

  /**
   * Stops an active recording session, captures storage, closes browser, flushes DB
   */
  public async stopSession(sessionId: string): Promise<void> {
    const active = this.activeSessions.get(sessionId);
    if (!active) {
      await controlExtensionSession(sessionId, 'STOPPED').catch(() => {});
      await prisma.session.updateMany({
        where: { id: sessionId, status: { in: ['RECORDING', 'PAUSED'] } },
        data: { status: "STOPPED", endedAt: new Date() },
      });
      return;
    }

    active.isStopping = true;
    await active.stopCredentialCapture();

    // 1. Capture storage snapshot
    try {
      await captureAndPersistStorage(sessionId, active.context);
    } catch (err) {
      console.error(`[BrowserManager] Failed to capture storage snapshot:`, err);
    }

    // 2. Stop recorder and flush remaining items
    await active.recorder.stop();

    // 3. Close context and browser
    try {
      await active.context.close().catch(() => {});
      if (active.browser) {
        await active.browser.close().catch(() => {});
      }
    } catch (err) {
      console.error(`[BrowserManager] Error closing browser:`, err);
    }

    // 4. Update session status in database
    await prisma.session.update({
      where: { id: sessionId },
      data: {
        status: "STOPPED",
        endedAt: new Date(),
        totalRequests: active.recorder.totalRequests,
        totalErrors: active.recorder.totalErrors,
      },
    });

    // 5. Notify SSE clients
    this.broadcastToSse(sessionId, {
      type: "telemetry",
      sessionId,
      status: "STOPPED",
      totalRequests: active.recorder.totalRequests,
      totalErrors: active.recorder.totalErrors,
      activeTabsCount: 0,
    });

    this.activeSessions.delete(sessionId);
  }

  /**
   * Subscribes an SSE HTTP response stream to live updates for a session
   */
  public subscribeSse(sessionId: string, res: Response): void {
    if (!this.sseClients.has(sessionId)) {
      this.sseClients.set(sessionId, new Set());
    }
    const clients = this.sseClients.get(sessionId)!;
    clients.add(res);

    // Initial ping
    res.write(`: ping\n\n`);

    // If session is active, emit current snapshot immediately
    const active = this.activeSessions.get(sessionId);
    if (active) {
      const snapshot = active.recorder.getTelemetrySnapshot(
        active.context.pages().filter((p) => !p.isClosed()).length
      );
      res.write(`data: ${JSON.stringify(snapshot)}\n\n`);
    } else {
      // Fetch DB session status
      prisma.session
        .findUnique({ where: { id: sessionId } })
        .then((s) => {
          if (s && !res.writableEnded) {
            res.write(
              `data: ${JSON.stringify({
                type: "telemetry",
                sessionId,
                status: s.status,
                totalRequests: s.totalRequests,
                totalErrors: s.totalErrors,
                activeTabsCount: 0,
              })}\n\n`
            );
          }
        })
        .catch(() => {});
    }

    // Keepalive ping every 15 seconds
    const pingInterval = setInterval(() => {
      if (!res.writableEnded) {
        res.write(`: ping\n\n`);
      } else {
        clearInterval(pingInterval);
      }
    }, 15000);

    res.on("close", () => {
      clearInterval(pingInterval);
      clients.delete(res);
      if (clients.size === 0) {
        this.sseClients.delete(sessionId);
      }
    });
  }

  public broadcastTelemetry(sessionId: string, data: LiveTelemetryUpdate): void {
    this.broadcastToSse(sessionId, data);
  }

  private broadcastToSse(sessionId: string, data: LiveTelemetryUpdate): void {
    const clients = this.sseClients.get(sessionId);
    if (!clients || clients.size === 0) return;

    const payload = `data: ${JSON.stringify(data)}\n\n`;
    for (const client of clients) {
      if (!client.writableEnded) {
        client.write(payload);
      }
    }
  }
}

export const browserManager = BrowserManager.getInstance();

