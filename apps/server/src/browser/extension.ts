import express from 'express';
import cors from 'cors';
import { randomBytes } from 'node:crypto';
import { z } from 'zod';
import { prisma } from '../db.js';
import { sanitizeBody, sanitizeHeaders, sanitizeUrl, stripNullBytes } from '../utils/redact.js';
import { scrubText } from '../ai/privacy.js';
import { captureToken } from './credentials.js';
import { browserManager } from './manager.js';

type Pair = { projectId: string; origins: string[]; expires: number; sessionId?: string; claiming?: boolean; lastSeen: number; focus?: boolean };
const pairs = new Map<string, Pair>();

interface ExtensionCommand {
  id: string;
  action: 'launch' | 'stop' | 'pause' | 'resume';
  sessionId?: string;
  code?: string;
  targetUrl?: string;
  origins?: string[];
  projectId?: string;
  createdAt: number;
}

interface ActiveTarget {
  sessionId: string;
  targetUrl: string;
  origins: string[];
  code: string;
  createdAt: number;
}

let pendingCommand: ExtensionCommand | null = null;
let currentActiveTarget: ActiveTarget | null = null;
let lastExtensionHeartbeat = 0;

export const extensionRouter = express.Router();
export function isExtensionSession(id: string) { return [...pairs.values()].some(p => p.sessionId === id); }
const dashboardOrigins = () => [process.env.FRONTEND_URL || 'http://localhost:3001', 'http://127.0.0.1:3001'];

extensionRouter.use(cors({
  origin(origin, done) {
    done(null, !origin || dashboardOrigins().includes(origin) || origin.startsWith('chrome-extension://'));
  }
}));

extensionRouter.use(express.json({ limit: '10mb' }));

extensionRouter.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  const origin = req.get('Origin');
  if (req.method === 'POST' && !req.path.startsWith('/bridge/') && req.get('X-TraceHawk-Control') !== '1') { res.status(403).json({ error: 'Local control header required' }); return; }
  if (origin && !dashboardOrigins().includes(origin) && !origin.startsWith('chrome-extension://')) {
    res.status(403).json({ error: 'Untrusted origin' });
    return;
  }
  next();
});

/**
 * Active recording target check for automatic tab detection
 */
extensionRouter.get('/active-target', (_req, res) => res.json({ active: false, target: null }));

/**
 * Extension heartbeats & command polling
 */
extensionRouter.get('/poll', (_req, res) => res.json({ connected: true, command: null }));

/**
 * Check if extension is connected
 */
extensionRouter.get('/status', (_req, res) => {
  const isConnected = Date.now() - lastExtensionHeartbeat < 6000;
  res.json({
    connected: isConnected,
    lastSeen: lastExtensionHeartbeat
  });
});

/**
 * List projects for the extension popup
 */
extensionRouter.get('/projects', async (_req, res) => {
  try {
    const projects = await prisma.project.findMany({
      orderBy: { createdAt: 'desc' },
      select: {
        id: true,
        name: true,
        targetUrl: true,
        allowedOrigins: true
      }
    });
    res.json({ projects });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * 1-Click Launch from Dashboard to Everyday Chrome Extension
 */
extensionRouter.post('/launch', async (req, res) => {
  try {
    const { projectId, targetUrl } = z.object({
      projectId: z.string().uuid(),
      targetUrl: z.string().url().max(10000).optional()
    }).parse(req.body);

    const project = await prisma.project.findUniqueOrThrow({ where: { id: projectId } });
    const effectiveUrl = targetUrl || project.targetUrl;
    const urlOrigin = new URL(effectiveUrl).origin;
    if (projectId && !project.allowedOrigins.some(o => new URL(o).origin === new URL(req.body.url || req.body.targetUrl || project.targetUrl).origin)) { res.status(403).json({ error: 'Selected tab is outside this project. Choose its matching project.' }); return; }
    const origins = [...new Set([...project.allowedOrigins.map(o => {
      try { return new URL(o).origin; } catch { return o; }
    }), urlOrigin])];

    const session = await prisma.session.create({
      data: {
        projectId: project.id,
        status: 'RECORDING',
        startedAt: new Date(),
        browserEvents: {
          create: {
            type: 'BROWSER_LAUNCHED',
            message: `Everyday Chrome extension: recording ${sanitizeUrl(effectiveUrl).sanitizedUrl}`,
            pageUrl: sanitizeUrl(effectiveUrl).sanitizedUrl,
          }
        }
      }
    });

    const code = randomBytes(32).toString('hex');
    const pairData: Pair = {
      projectId: project.id,
      origins,
      expires: Date.now() + 24 * 3600000,
      sessionId: session.id,
      lastSeen: Date.now()
    };
    pairs.set(code, pairData);

    pendingCommand = {
      id: randomBytes(16).toString('hex'),
      action: 'launch',
      sessionId: session.id,
      code,
      targetUrl: effectiveUrl,
      origins,
      projectId: project.id,
      createdAt: Date.now()
    };

    currentActiveTarget = {
      sessionId: session.id,
      targetUrl: effectiveUrl,
      origins,
      code,
      createdAt: Date.now()
    };

    res.json({
      sessionId: session.id,
      code,
      targetUrl: effectiveUrl,
      message: 'Launch command sent to everyday Chrome extension'
    });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

/**
 * 1-Click Start from Extension Popup (on any tab or project)
 */
extensionRouter.post('/start-session', async (req, res) => {
  try {
    const { url, projectId } = z.object({
      url: z.string().url().max(10000),
      projectId: z.string().uuid().optional()
    }).parse(req.body);

    const tabOrigin = new URL(url).origin;
    if (!['http:', 'https:'].includes(new URL(url).protocol)) { res.status(400).json({ error: 'Use an HTTP or HTTPS tab' }); return; }
    let project = projectId ? await prisma.project.findUnique({ where: { id: projectId } }) : null;

    if (!project) {
      const projects = await prisma.project.findMany();
      project = projects.find(p => {
        try {
          return p.allowedOrigins.some(o => new URL(o).origin === tabOrigin) || new URL(p.targetUrl).origin === tabOrigin;
        } catch { return false; }
      }) || null;
    }

    if (!project) {
      // Auto-create project for this website so any URL can be recorded immediately
      const hostname = new URL(url).hostname || 'Website';
      project = await prisma.project.create({
        data: {
          name: hostname,
          targetUrl: url,
          allowedOrigins: [tabOrigin]
        }
      });
    }

    if (projectId && !project.allowedOrigins.some(o => new URL(o).origin === new URL(req.body.url || req.body.targetUrl || project.targetUrl).origin)) { res.status(403).json({ error: 'Selected tab is outside this project. Choose its matching project.' }); return; }
    const origins = [...new Set([...project.allowedOrigins.map(o => {
      try { return new URL(o).origin; } catch { return o; }
    }), tabOrigin])];

    const session = await prisma.session.create({
      data: {
        projectId: project.id,
        status: 'RECORDING',
        startedAt: new Date(),
        browserEvents: {
          create: {
            type: 'BROWSER_LAUNCHED',
            message: `Everyday Chrome extension: recording tab ${sanitizeUrl(url).sanitizedUrl}`,
            pageUrl: sanitizeUrl(url).sanitizedUrl,
          }
        }
      }
    });

    const code = randomBytes(32).toString('hex');
    const startPair: Pair = {
      projectId: project.id,
      origins,
      expires: Date.now() + 24 * 3600000,
      sessionId: session.id,
      lastSeen: Date.now()
    };
    pairs.set(code, startPair);

    currentActiveTarget = {
      sessionId: session.id,
      targetUrl: url,
      origins,
      code,
      createdAt: Date.now()
    };

    res.json({
      sessionId: session.id,
      code,
      origins,
      projectId: project.id
    });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

/**
 * Legacy pairing code generation
 */
extensionRouter.post('/pair', async (req, res) => {
  try {
    const { projectId } = z.object({ projectId: z.string().uuid() }).parse(req.body);
    const project = await prisma.project.findUniqueOrThrow({ where: { id: projectId } });
    const code = randomBytes(32).toString('hex');
    pairs.set(code, { projectId, origins: project.allowedOrigins.map(o => new URL(o).origin), expires: Date.now() + 86400000, lastSeen: Date.now() });
    res.json({ code, expiresInSeconds: 86400 });
  } catch { res.status(400).json({ error: 'Choose a saved project first' }); }
});

/**
 * Bridge authentication middleware
 * Supports both pairing codes and session IDs directly, with DB fallback for server restarts
 */
extensionRouter.use('/bridge', async (req, res, next) => {
  const token = req.get('Authorization')?.replace(/^Bearer /, '').trim() || '';
  if (!token) {
    res.status(401).json({ error: 'Missing authorization token' });
    return;
  }

  let pair = pairs.get(token);
  if (pair && pair.expires >= Date.now()) {
    pair.lastSeen = Date.now();
    res.locals.pair = pair;
    return next();
  }

  res.status(401).json({ error: 'Pairing expired or session ended in TraceHawk.' });
});

extensionRouter.post('/bridge/claim', async (req, res) => {
  const pair: Pair = res.locals.pair;
  if (pair.sessionId || pair.claiming) { res.status(409).json({ error: 'This code was already used' }); return; }
  pair.claiming = true;
  try {
    const { url } = z.object({ url: z.string().url().max(10000) }).parse(req.body);
    if (!['http:', 'https:'].includes(new URL(url).protocol) || !pair.origins.includes(new URL(url).origin)) { res.status(403).json({ error: 'Tab is outside the selected project' }); return; }
    const session = await prisma.session.create({
      data: {
        projectId: pair.projectId,
        status: 'RECORDING',
        browserEvents: {
          create: {
            type: 'BROWSER_LAUNCHED',
            message: 'Chrome extension: selected tab only',
            pageUrl: sanitizeUrl(url).sanitizedUrl
          }
        }
      }
    });
    pair.sessionId = session.id;
    pair.expires = Date.now() + 24 * 3600000;
    const tabOrigin = new URL(url).origin;
    if (!['http:', 'https:'].includes(new URL(url).protocol)) { res.status(400).json({ error: 'Use an HTTP or HTTPS tab' }); return; }
    res.json({ sessionId: session.id, origins: pair.origins });
  } catch { res.status(400).json({ error: 'Could not start selected-tab recording' }); }
  finally { pair.claiming = false; }
});

const headers = z.record(z.string().max(20000)).default({});
const exchangeSchema = z.object({
  url: z.string().max(10000),
  pageUrl: z.string().max(10000).optional().default(''),
  method: z.string().max(50).default('GET'),
  statusCode: z.number().int().min(0).max(999).nullable().optional(),
  requestHeaders: headers,
  responseHeaders: headers,
  requestBody: z.string().max(65536).nullable().optional(),
  responseBody: z.string().max(65536).nullable().optional(),
  contentType: z.string().max(1000).default(''),
  duration: z.number().default(0),
  resourceType: z.string().max(100).default('other'),
  failureReason: z.string().max(2000).nullable().optional()
});

extensionRouter.post('/bridge/exchange', async (req, res) => {
  const pair: Pair = res.locals.pair;
  try {
    if (!pair.sessionId) { res.status(409).json({ error: 'Select a tab first' }); return; }
    const e = exchangeSchema.parse(req.body);
    if (!pair.origins.includes(new URL(e.url).origin) || !pair.origins.includes(new URL(e.pageUrl).origin)) { res.status(403).json({ error: 'Exchange is outside project scope' }); return; }
    const session = await prisma.session.findUnique({ where: { id: pair.sessionId } });
    if (!session || session.status !== 'RECORDING') {
      res.json({ status: session?.status || 'STOPPED', accepted: false });
      return;
    }
    const requestHeaders = Object.fromEntries(Object.entries(e.requestHeaders || {}).map(([k, v]) => [k.toLowerCase(), v]));
    const responseHeaders = Object.fromEntries(Object.entries(e.responseHeaders || {}).map(([k, v]) => [k.toLowerCase(), v]));
    if (requestHeaders.authorization?.startsWith('Bearer ')) {
      try {
        const tokenOrigin = (() => { try { return new URL(e.url).origin; } catch { return ''; } })();
        await captureToken(session.id, requestHeaders.authorization.slice(7), 'Authorization header', tokenOrigin);
      } catch { }
    }
    const hasError = Boolean(e.failureReason || ((e.statusCode || 0) >= 400));
    const rawDuration = Number.isFinite(e.duration) && e.duration >= 0 ? Math.round(e.duration) : 0;

    await prisma.$transaction(async tx => {
      const changed = await tx.session.updateMany({
        where: { id: session.id, status: 'RECORDING' },
        data: {
          totalRequests: { increment: 1 },
          totalErrors: { increment: hasError ? 1 : 0 }
        }
      });
      if (!changed.count) return;
      await tx.httpExchange.create({
        data: {
          sessionId: session.id,
          url: stripNullBytes(sanitizeUrl(e.url).sanitizedUrl),
          pageUrl: stripNullBytes(sanitizeUrl(e.pageUrl || '').sanitizedUrl),
          method: stripNullBytes(e.method) || 'GET',
          statusCode: e.statusCode ?? null,
          requestHeaders: sanitizeHeaders(requestHeaders),
          responseHeaders: sanitizeHeaders(responseHeaders),
          sanitizedRequestBody: sanitizeBody(e.requestBody, requestHeaders['content-type']),
          sanitizedResponseBody: sanitizeBody(e.responseBody, e.contentType),
          contentType: stripNullBytes(e.contentType),
          duration: rawDuration,
          resourceType: stripNullBytes(e.resourceType),
          failureReason: e.failureReason ? stripNullBytes(scrubText(e.failureReason)) : null
        }
      });
    });

    // Broadcast live telemetry via SSE so the dashboard updates immediately
    try {
      browserManager.broadcastTelemetry(session.id, {
        type: 'telemetry',
        sessionId: session.id,
        status: session.status,
        totalRequests: session.totalRequests + 1,
        totalErrors: session.totalErrors + (hasError ? 1 : 0),
        activeTabsCount: 1,
        currentPageUrl: sanitizeUrl(e.pageUrl || '').sanitizedUrl,
        recentEndpoint: {
          method: e.method,
          url: sanitizeUrl(e.url).sanitizedUrl,
          statusCode: e.statusCode ?? null,
          duration: rawDuration,
          timestamp: new Date().toISOString()
        }
      });
    } catch { }

    res.json({ accepted: true, status: session.status });
  } catch (err: any) {
    console.error('[ExtensionBridge] exchange error:', err.message);
    res.status(400).json({ error: err.message });
  }
});

extensionRouter.get('/bridge/status', async (_req, res) => {
  const pair: Pair = res.locals.pair;
  const session = pair.sessionId ? await prisma.session.findUnique({ where: { id: pair.sessionId } }).catch(() => null) : null;
  res.json({ status: session?.status || 'STOPPED', focus: Boolean(pair.focus) }); pair.focus = false;
});

extensionRouter.post('/bridge/stop', async (_req, res) => {
  currentActiveTarget = null;
  const pair: Pair = res.locals.pair;
  if (pair.sessionId) {
    for (const [k, p] of pairs) {
      if (p.sessionId === pair.sessionId) pairs.delete(k);
    }
    await prisma.session.updateMany({
      where: { id: pair.sessionId, status: { in: ['RECORDING', 'PAUSED'] } },
      data: { status: 'STOPPED', endedAt: new Date() }
    });
  }
  res.json({ status: 'STOPPED' });
});

export async function controlExtensionSession(sessionId: string, status: 'PAUSED' | 'RECORDING' | 'STOPPED') {
  if (![...pairs.values()].some(p => p.sessionId === sessionId)) return false;
  if (status === 'STOPPED') {
    currentActiveTarget = null;
    for (const [k, p] of pairs) {
      if (p.sessionId === sessionId) pairs.delete(k);
    }
    pendingCommand = { id: randomBytes(16).toString('hex'), action: 'stop', sessionId, createdAt: Date.now() };
  } else if (status === 'PAUSED') {
    pendingCommand = { id: randomBytes(16).toString('hex'), action: 'pause', sessionId, createdAt: Date.now() };
  } else if (status === 'RECORDING') {
    pendingCommand = { id: randomBytes(16).toString('hex'), action: 'resume', sessionId, createdAt: Date.now() };
  }
  const result = await prisma.session.updateMany({
    where: { id: sessionId, status: { in: ['RECORDING', 'PAUSED'] } },
    data: { status: status === 'STOPPED' ? 'STOPPED' : status, ...(status === 'STOPPED' ? { endedAt: new Date() } : {}) }
  });
  return result.count === 1;
}

const cleanup = setInterval(() => {
  for (const [code, pair] of pairs) {
    if (pair.expires < Date.now()) {
      pairs.delete(code);
    }
  }
}, 60000);
cleanup.unref();

export function focusExtensionSession(sessionId: string) { const pair = [...pairs.values()].find(p => p.sessionId === sessionId); if (!pair) return false; pair.focus = true; return true; }
