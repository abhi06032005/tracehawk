import { Router, Request, Response } from "express";
import { z } from "zod";
import { prisma, checkDatabaseConnection } from "../db.js";
import { browserManager } from "../browser/manager.js";
import { analyzeSession } from "../security/analyzer.js";
import { aiProvider } from "../ai/provider.js";
import { investigationManager } from "../ai/agent.js";
import { StartAuditSchema } from "../ai/contracts.js";
import { availableScenarios } from "../ai/tools.js";
import { revealToken, forgetTokens } from '../browser/credentials.js';
import { isExtensionSession } from '../browser/extension.js';
import { startReportChat, stopReportChat } from '../ai/chat.js';
import { PlaywrightCrawler } from '../browser/crawler.js';
import { AuthProfileManager } from '../browser/auth-manager.js';
import { SourceSecurityScanner } from '../security/scanners/source-scanner.js';
import { ReportGenerator } from '../reporting/generator.js';
import { normalizePassiveFinding, normalizeAiHypothesis, deduplicateFindings } from '../security/findings.js';
import { SecurityPolicyGateway } from '../security/policy.js';
import { copilotRouter } from './copilot.js';

export const apiRouter = Router();
apiRouter.use("/copilot", copilotRouter);
apiRouter.post('/investigations/:id/chat',async(req,res)=>{
  if(req.get('X-TraceHawk-Control')!=='1'){res.status(403).json({error:'Local control header required'});return;}
  try{res.status(202).json(await startReportChat(String(req.params.id),req.body));}
  catch(error){res.status(400).json({error:error instanceof z.ZodError?'Enter a question up to 2000 characters.':error instanceof Error?error.message:'Could not start response'});}
});
apiRouter.post('/investigations/:id/chat/stop',(req,res)=>{
  if(req.get('X-TraceHawk-Control')!=='1'){res.status(403).json({error:'Local control header required'});return;}
  stopReportChat(String(req.params.id));res.json({stopped:true});
});

function getParam(param: string | string[] | undefined): string {
  if (Array.isArray(param)) return param[0] || "";
  return param || "";
}

// Validation Schemas
const CreateProjectSchema = z.object({
  name: z.string().min(1, "Project name is required").max(100),
  targetUrl: z.string().url("Valid target URL is required"),
  allowedOrigins: z.array(z.string()).optional().default([]),
});

const LaunchSessionSchema = z.object({
  projectId: z.string().min(1, "Project ID is required"),
  targetUrl: z.string().url().optional(),
  authProfile: z.string().optional(),
  authHeaders: z.record(z.string()).optional(),
});

/**
 * GET /api/health
 */
apiRouter.get("/health", async (_req: Request, res: Response) => {
  const dbOk = await checkDatabaseConnection();
  const activeSessionsCount = browserManager.getActiveSessionsCount();
  const aiConfig = aiProvider.getConfigSummary();

  res.json({
    status: dbOk ? "healthy" : "degraded",
    timestamp: new Date().toISOString(),
    services: {
      database: dbOk ? "connected" : "disconnected",
      browserEngine: "ready",
      activeSessions: activeSessionsCount,
      aiProvider: aiConfig,
    },
  });
});

/**
 * GET /api/projects
 */
apiRouter.get("/projects", async (_req: Request, res: Response) => {
  try {
    const projects = await prisma.project.findMany({
      orderBy: { createdAt: "desc" },
      include: {
        sessions: {
          select: {
            id: true,
            status: true,
            startedAt: true,
            endedAt: true,
            totalRequests: true,
            totalErrors: true,
            findings: {
              select: { id: true, severity: true },
            },
          },
          orderBy: { startedAt: "desc" },
        },
      },
    });

    res.json({ projects });
  } catch (error: any) {
    res.status(500).json({ error: "Failed to fetch projects", details: error.message });
  }
});

/**
 * POST /api/projects
 */
apiRouter.post("/projects", async (req: Request, res: Response) => {
  try {
    const parsed = CreateProjectSchema.parse(req.body);

    const origins = new Set(parsed.allowedOrigins);
    try {
      const urlOrigin = new URL(parsed.targetUrl).origin;
      origins.add(urlOrigin);
    } catch {}

    const project = await prisma.project.create({
      data: {
        name: parsed.name,
        targetUrl: parsed.targetUrl,
        allowedOrigins: Array.from(origins),
      },
    });

    res.status(201).json({ project });
  } catch (error: any) {
    if (error instanceof z.ZodError) {
      res.status(400).json({ error: "Validation failed", issues: error.issues });
      return;
    }
    res.status(500).json({ error: "Failed to create project", details: error.message });
  }
});

/**
 * GET /api/projects/:id
 */
apiRouter.get("/projects/:id", async (req: Request, res: Response) => {
  try {
    const id = getParam(req.params.id);
    const project = await prisma.project.findUnique({
      where: { id },
      include: {
        sessions: {
          orderBy: { startedAt: "desc" },
          include: {
            findings: {
              select: { id: true, severity: true, category: true },
            },
          },
        },
      },
    });

    if (!project) {
      res.status(404).json({ error: "Project not found" });
      return;
    }

    res.json({ project });
  } catch (error: any) {
    res.status(500).json({ error: "Failed to fetch project", details: error.message });
  }
});

/**
 * POST /api/sessions (Launch visible browser & record)
 */
apiRouter.post("/sessions", async (req: Request, res: Response) => {
  try {
    const parsed = LaunchSessionSchema.parse(req.body);

    const project = await prisma.project.findUnique({
      where: { id: parsed.projectId },
    });

    if (!project) {
      res.status(404).json({ error: "Project not found" });
      return;
    }

    const targetUrl = parsed.targetUrl || project.targetUrl;
    const result = await browserManager.launchSession(project.id, targetUrl, {
      authProfile: parsed.authProfile,
      authHeaders: parsed.authHeaders,
    });

    res.status(201).json({
      message: "Browser launched and recording started successfully",
      sessionId: result.sessionId,
      targetUrl,
      status: result.status,
    });
  } catch (error: any) {
    if (error instanceof z.ZodError) {
      res.status(400).json({ error: "Validation failed", issues: error.issues });
      return;
    }
    console.error("Failed to launch browser session:", error);
    res.status(500).json({ error: "Failed to launch session", details: error.message });
  }
});

/**
 * POST /api/browser/clear-profile
 */
apiRouter.post("/browser/clear-profile", async (_req: Request, res: Response) => {
  try {
    const result = browserManager.clearPersistentProfile();
    res.json(result);
  } catch (error: any) {
    res.status(400).json({ error: error.message });
  }
});

/**
 * GET /api/sessions/:id
 */
apiRouter.get("/sessions/:id", async (req: Request, res: Response) => {
  try {
    const id = getParam(req.params.id);
    const session = await prisma.session.findUnique({
      where: { id },
      include: {
        project: true,
        findings: true,
        analysisRuns: {
          orderBy: { startedAt: "desc" },
          take: 5,
        },
        _count: {
          select: {
            httpExchanges: true,
            browserEvents: true,
            storageObservations: true,
            findings: true,
          },
        },
      },
    });

    if (!session) {
      res.status(404).json({ error: "Session not found" });
      return;
    }

    const active = browserManager.getActiveSession(session.id);
    const liveStatus = active ? (active.recorder.getTelemetrySnapshot().status as string) : session.status;

    res.json({
      session: {
        ...session,
        status: liveStatus,
        isLiveActive: Boolean(active)||isExtensionSession(session.id),
        browserName: active?.browserName || (isExtensionSession(session.id)?'Chrome extension · selected tab':null),
        ...(active ? { totalRequests: active.recorder.totalRequests, totalErrors: active.recorder.totalErrors } : {}),
      },
    });
  } catch (error: any) {
    res.status(500).json({ error: "Failed to fetch session", details: error.message });
  }
});

apiRouter.post('/sessions/:id/focus', async (req, res) => {
  try { await browserManager.focusBrowser(getParam(req.params.id)); res.json({ message: 'Connected browser brought to front' }); }
  catch (error: any) { res.status(409).json({ error: error.message }); }
});

apiRouter.get('/sessions/:id/storage', async (req, res) => {
  try { res.json({ observations: await prisma.storageObservation.findMany({ where: { sessionId: getParam(req.params.id) }, orderBy: { timestamp: 'desc' } }) }); }
  catch { res.status(500).json({ error: 'Could not load storage observations' }); }
});

/**
 * POST /api/sessions/:id/pause
 */
apiRouter.post("/sessions/:id/pause", async (req: Request, res: Response) => {
  try {
    const id = getParam(req.params.id);
    await browserManager.pauseSession(id);
    res.json({ message: "Session recording paused", status: "PAUSED" });
  } catch (error: any) {
    res.status(400).json({ error: error.message });
  }
});

apiRouter.get('/sessions/:id/tokens', async (req, res) => {
  try { res.json({ observations: await prisma.browserEvent.findMany({ where: { sessionId: getParam(req.params.id), type: 'TOKEN_OBSERVATION' }, orderBy: { timestamp: 'desc' } }) }); }
  catch { res.status(500).json({ error: 'Could not load token security observations' }); }
});
apiRouter.post('/sessions/:id/tokens/:tokenId/reveal', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');
  if(req.get('X-TraceHawk-Control')!=='1'){res.status(403).json({error:'Local control header required'});return}
  const value=revealToken(getParam(req.params.id),getParam(req.params.tokenId));
  if(value===null){res.status(410).json({error:'The raw value has expired or the server restarted. Its security metadata is still saved.'});return}
  res.json({value});
});

/**
 * POST /api/sessions/:id/resume
 */
apiRouter.post("/sessions/:id/resume", async (req: Request, res: Response) => {
  try {
    const id = getParam(req.params.id);
    await browserManager.resumeSession(id);
    res.json({ message: "Session recording resumed", status: "RECORDING" });
  } catch (error: any) {
    res.status(400).json({ error: error.message });
  }
});

/**
 * POST /api/sessions/:id/stop
 */
apiRouter.post("/sessions/:id/stop", async (req: Request, res: Response) => {
  try {
    const id = getParam(req.params.id);
    await browserManager.stopSession(id);
    const session = await prisma.session.findUnique({
      where: { id },
      include: {
        _count: {
          select: {
            httpExchanges: true,
            storageObservations: true,
            browserEvents: true,
          },
        },
      },
    });
    res.json({
      message: "Session recording stopped and finalized",
      session,
    });
  } catch (error: any) {
    res.status(500).json({ error: "Failed to stop session", details: error.message });
  }
});

/**
 * DELETE /api/sessions/:id
 */
apiRouter.delete("/sessions/:id", async (req: Request, res: Response) => {
  try {
    const id = getParam(req.params.id);
    await browserManager.stopSession(id).catch(() => {});
    forgetTokens(id);
    await prisma.session.delete({
      where: { id },
    });

    res.json({ message: "Session deleted successfully" });
  } catch (error: any) {
    res.status(500).json({ error: "Failed to delete session", details: error.message });
  }
});

/**
 * GET /api/sessions/:id/stream (Server-Sent Events)
 */
apiRouter.get("/sessions/:id/stream", (req: Request, res: Response) => {
  const sessionId = getParam(req.params.id);

  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });

  browserManager.subscribeSse(sessionId, res);
});

/**
 * GET /api/sessions/:id/traffic (Network Inspector table data)
 */
apiRouter.get("/sessions/:id/traffic", async (req: Request, res: Response) => {
  try {
    const sessionId = getParam(req.params.id);
    const { method, resourceType, search, statusCode, limit = "200", offset = "0" } = req.query;
    const pagination = z.object({ limit: z.coerce.number().int().min(1).max(500), offset: z.coerce.number().int().min(0) }).safeParse({ limit, offset });
    if (!pagination.success) { res.status(400).json({ error: 'Invalid traffic pagination' }); return; }

    const where: any = { sessionId };

    if (method && typeof method === "string" && method !== "ALL") {
      where.method = method.toUpperCase();
    }

    if (resourceType && typeof resourceType === "string" && resourceType !== "ALL") {
      where.resourceType = resourceType === 'api' ? { in: ['fetch', 'xhr'] } : resourceType.toLowerCase();
    }

    if (statusCode && typeof statusCode === "string") {
      if (statusCode === "FAILED") {
        where.OR = [{ statusCode: { gte: 400 } }, { statusCode: null }];
      } else {
        where.statusCode = parseInt(statusCode, 10);
      }
    }

    if (search && typeof search === "string") {
      where.url = { contains: search, mode: "insensitive" };
    }

    const [exchanges, total] = await Promise.all([
      prisma.httpExchange.findMany({
        where,
        orderBy: { timestamp: "desc" },
        take: pagination.data.limit,
        skip: pagination.data.offset,
      }),
      prisma.httpExchange.count({ where }),
    ]);

    res.json({ exchanges, total });
  } catch (error: any) {
    res.status(500).json({ error: "Failed to fetch traffic", details: error.message });
  }
});

/**
 * GET /api/sessions/:id/events (Browser events: console errors, nav, websockets)
 */
apiRouter.get("/sessions/:id/events", async (req: Request, res: Response) => {
  try {
    const sessionId = getParam(req.params.id);
    const { type, limit = "100" } = req.query;
    const where: any = { sessionId };

    if (type && typeof type === "string") {
      where.type = type;
    }

    const events = await prisma.browserEvent.findMany({
      where,
      orderBy: { timestamp: "desc" },
      take: parseInt(limit as string, 10),
    });

    res.json({ events });
  } catch (error: any) {
    res.status(500).json({ error: "Failed to fetch browser events", details: error.message });
  }
});

/**
 * POST /api/sessions/:id/analyze (Run passive security analysis)
 */
apiRouter.post("/sessions/:id/analyze", async (req: Request, res: Response) => {
  try {
    const sessionId = getParam(req.params.id);
    const completed = await prisma.session.findUnique({ where: { id: sessionId } });
    if (!completed || !['STOPPED','ANALYZED'].includes(completed.status)) { res.status(409).json({ error: 'Stop recording before running security checks.' }); return; }
    const summary = await analyzeSession(sessionId);

    res.json({
      message: "Session security analysis complete",
      summary,

    });
  } catch (error: any) {
    console.error("Session analysis failed:", error);
    res.status(500).json({ error: "Analysis failed", details: error.message });
  }
});

/**
 * POST /api/sessions/:id/investigate (Start autonomous AI security investigation)
 */
apiRouter.post("/sessions/:id/investigate", async (req: Request, res: Response) => {
  try {
    if (req.get('X-TraceHawk-Control') !== '1') { res.status(403).json({ error: 'Local control header required' }); return; }
    const sessionId = getParam(req.params.id);
    const result = await investigationManager.startInvestigation(sessionId, StartAuditSchema.parse(req.body));
    res.status(201).json({
      message: "DeepHat autonomous investigation started",
      investigationId: result.investigationId,
      status: result.status,
    });
  } catch (error: any) {
    res.status(400).json({ error: "Unable to start investigation", details: error instanceof z.ZodError ? 'Invalid authorization or execution limits' : error.message });
  }
});

/**
 * GET /api/sessions/:id/investigations (List investigations for session)
 */
apiRouter.get("/sessions/:id/investigations", async (req: Request, res: Response) => {
  try {
    const sessionId = getParam(req.params.id);
    const investigations = await prisma.investigation.findMany({
      where: { sessionId },
      orderBy: { startedAt: "desc" },
      include: {
        hypotheses: true,
        steps: {
          orderBy: { stepNumber: "desc" },
          take: 5,
        },
      },
    });

    res.json({ investigations });
  } catch (error: any) {
    res.status(500).json({ error: "Failed to list investigations", details: error.message });
  }
});

/**
 * GET /api/investigations/:id (Get full investigation details, hypotheses and steps)
 */
apiRouter.get("/investigations/:id", async (req: Request, res: Response) => {
  try {
    const id = getParam(req.params.id);
    const investigation = await prisma.investigation.findUnique({
      where: { id },
      include: {
        session: {
          include: { project: true },
        },
        hypotheses: {
          orderBy: { createdAt: "desc" },
        },
        steps: {
          orderBy: { stepNumber: "asc" },
        },
      },
    });

    if (!investigation) {
      res.status(404).json({ error: "Investigation not found" });
      return;
    }

    res.json({ investigation });
  } catch (error: any) {
    res.status(500).json({ error: "Failed to fetch investigation", details: error.message });
  }
});

/**
 * POST /api/investigations/:id/stop (Emergency Stop / Cancel investigation)
 */
apiRouter.post("/investigations/:id/stop", async (req: Request, res: Response) => {
  try {
    if (req.get('X-TraceHawk-Control') !== '1') { res.status(403).json({ error: 'Local control header required' }); return; }
    const id = getParam(req.params.id);
    await investigationManager.stopInvestigation(id);
    res.json({ message: "Investigation cancelled successfully by emergency stop" });
  } catch (error: any) {
    res.status(500).json({ error: "Failed to stop investigation", details: error.message });
  }
});

apiRouter.get('/ai/config', (_req, res) => {
  try { res.json({ ...aiProvider.getConfigSummary(), baseUrl: undefined, scenarios: availableScenarios(), zapConfigured: Boolean(process.env.ZAP_BASE_URL && process.env.ZAP_API_KEY) }); }
  catch { res.status(400).json({ error: 'Invalid server-side test-account configuration' }); }
});

apiRouter.post('/investigations/:id/approvals/:approvalId', async (req, res) => {
  try {
    if (req.get('X-TraceHawk-Control') !== '1') { res.status(403).json({ error: 'Local control header required' }); return; }
    const { approved } = z.object({ approved: z.boolean() }).strict().parse(req.body);
    await investigationManager.resolveApproval(getParam(req.params.id), getParam(req.params.approvalId), approved);
    res.json({ message: approved ? 'Action approved once' : 'Action denied' });
  } catch { res.status(409).json({ error: 'Invalid or expired approval' }); }
});

/**
 * GET /api/investigations/:id/stream (SSE live updates stream)
 */
apiRouter.get("/investigations/:id/stream", (req: Request, res: Response) => {
  const investigationId = getParam(req.params.id);

  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });

  investigationManager.subscribeSse(investigationId, res);
});

/**
 * GET /api/sessions/:id/findings
 */
apiRouter.get("/sessions/:id/findings", async (req: Request, res: Response) => {
  try {
    const sessionId = getParam(req.params.id);
    const { category, severity } = req.query;
    const where: any = { sessionId };

    if (category && typeof category === "string") where.category = category;
    if (severity && typeof severity === "string") where.severity = severity;

    const findings = await prisma.finding.findMany({
      where,
      orderBy: [{ severity: "asc" }, { createdAt: "desc" }],
    });

    res.json({ findings });
  } catch (error: any) {
    res.status(500).json({ error: "Failed to fetch findings", details: error.message });
  }
});

/**
 * GET /api/sessions/:id/export (Export reports)
 */
apiRouter.get("/sessions/:id/export", async (req: Request, res: Response) => {
  try {
    const sessionId = getParam(req.params.id);
    const format = (req.query.format as string) || "json";
    const session = await prisma.session.findUnique({
      where: { id: sessionId },
      include: {
        project: true,
        findings: true,
        httpExchanges: true,
        storageObservations: true,
        browserEvents: true,
      },
    });

    if (!session) {
      res.status(404).json({ error: "Session not found" });
      return;
    }

    if (format === "traffic") {
      res.setHeader("Content-Disposition", `attachment; filename="tracehawk-traffic-${session.id}.json"`);
      res.setHeader("Content-Type", "application/json");
      res.json({
        sessionId: session.id,
        targetUrl: session.project.targetUrl,
        exportedAt: new Date().toISOString(),
        totalRequests: session.httpExchanges.length,
        exchanges: session.httpExchanges,
      });
      return;
    }

    if (format === "har") {
      const har = {
        log: {
          version: "1.2",
          creator: { name: "TraceHawk", version: "1.0.0" },
          pages: [
            {
              startedDateTime: session.startedAt.toISOString(),
              id: session.id,
              title: session.project.name,
              pageTimings: { onContentLoad: -1, onLoad: -1 },
            },
          ],
          entries: session.httpExchanges.map((ex: any) => ({
            startedDateTime: ex.timestamp.toISOString(),
            time: ex.duration || 0,
            request: {
              method: ex.method,
              url: ex.url,
              httpVersion: "HTTP/1.1",
              headers: Object.entries(
                (ex.requestHeaders as Record<string, string | string[]>) || {}
              ).map(([name, value]) => ({
                name,
                value: Array.isArray(value) ? value.join(", ") : String(value),
              })),
              queryString: [],
              cookies: [],
              headersSize: -1,
              bodySize: ex.sanitizedRequestBody ? ex.sanitizedRequestBody.length : 0,
              postData: ex.sanitizedRequestBody
                ? { mimeType: ex.contentType || "text/plain", text: ex.sanitizedRequestBody }
                : undefined,
            },
            response: {
              status: ex.statusCode || 0,
              statusText: ex.statusCode === 200 ? "OK" : "",
              httpVersion: "HTTP/1.1",
              headers: Object.entries(
                (ex.responseHeaders as Record<string, string | string[]>) || {}
              ).map(([name, value]) => ({
                name,
                value: Array.isArray(value) ? value.join(", ") : String(value),
              })),
              cookies: [],
              content: {
                size: ex.sanitizedResponseBody ? ex.sanitizedResponseBody.length : 0,
                mimeType: ex.contentType || "text/plain",
                text: ex.sanitizedResponseBody || "",
              },
              redirectURL: "",
              headersSize: -1,
              bodySize: ex.sanitizedResponseBody ? ex.sanitizedResponseBody.length : 0,
            },
            cache: {},
            timings: { send: 0, wait: ex.duration || 0, receive: 0 },
          })),
        },
      };

      res.setHeader("Content-Disposition", `attachment; filename="tracehawk-session-${session.id}.har"`);
      res.setHeader("Content-Type", "application/json");
      res.json(har);
      return;
    }

    if (format === "markdown" || format === "md") {
      const normFindings = session.findings.map((f: any) =>
        normalizePassiveFinding(f, session.project.targetUrl, session.id)
      );
      const md = ReportGenerator.generateMarkdown(
        {
          reportId: session.id,
          projectName: session.project.name,
          targetUrl: session.project.targetUrl,
          scanDate: session.startedAt.toISOString(),
          scannerVersion: "2.0.0",
        },
        normFindings
      );

      res.setHeader("Content-Disposition", `attachment; filename="tracehawk-report-${session.id}.md"`);
      res.setHeader("Content-Type", "text/markdown; charset=utf-8");
      res.send(md);
      return;
    }

    if (format === "html") {
      const normFindings = session.findings.map((f: any) =>
        normalizePassiveFinding(f, session.project.targetUrl, session.id)
      );
      const html = ReportGenerator.generateHtml(
        {
          reportId: session.id,
          projectName: session.project.name,
          targetUrl: session.project.targetUrl,
          scanDate: session.startedAt.toISOString(),
          scannerVersion: "2.0.0",
        },
        normFindings
      );

      res.setHeader("Content-Disposition", `attachment; filename="tracehawk-report-${session.id}.html"`);
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.send(html);
      return;
    }

    // Default: JSON Security Report
    const report = {
      title: "TraceHawk Security Inspection Report",
      generatedAt: new Date().toISOString(),
      project: {
        id: session.project.id,
        name: session.project.name,
        targetUrl: session.project.targetUrl,
        allowedOrigins: session.project.allowedOrigins,
      },
      session: {
        id: session.id,
        status: session.status,
        startedAt: session.startedAt,
        endedAt: session.endedAt,
        totalRequests: session.totalRequests,
        totalErrors: session.totalErrors,
      },
      summary: {
        totalFindings: session.findings.length,
        critical: session.findings.filter((f: any) => f.severity === "CRITICAL").length,
        high: session.findings.filter((f: any) => f.severity === "HIGH").length,
        medium: session.findings.filter((f: any) => f.severity === "MEDIUM").length,
        low: session.findings.filter((f: any) => f.severity === "LOW").length,
        info: session.findings.filter((f: any) => f.severity === "INFO").length,
      },
      findings: session.findings,
      storageObservations: session.storageObservations.map((s: any) => ({
        origin: s.origin,
        storageType: s.storageType,
        key: s.key,
        sanitizedValue: s.sanitizedValue,
      })),
    };

    res.setHeader("Content-Disposition", `attachment; filename="tracehawk-report-${session.id}.json"`);
    res.setHeader("Content-Type", "application/json");
    res.json(report);
  } catch (error: any) {
    res.status(500).json({ error: "Failed to export report", details: error.message });
  }
});

/**
 * GET /api/sessions/:id/unified-findings
 * Returns deduplicated normalized findings from deterministic passive checks and AI hypotheses.
 */
apiRouter.get("/sessions/:id/unified-findings", async (req: Request, res: Response) => {
  try {
    const sessionId = getParam(req.params.id);
    const session = await prisma.session.findUnique({
      where: { id: sessionId },
      include: {
        project: true,
        findings: true,
        investigations: {
          include: {
            hypotheses: true,
            steps: true,
          },
        },
      },
    });

    if (!session) {
      res.status(404).json({ error: "Session not found" });
      return;
    }

    const passive = session.findings.map((f: any) =>
      normalizePassiveFinding(f, session.project.targetUrl, session.id)
    );
    const aiHypotheses = session.investigations.flatMap((inv: any) => {
      const evidence = inv.steps.flatMap((s: any) => (s.toolResult as any)?.evidence || []);
      return inv.hypotheses.map((h: any) =>
        normalizeAiHypothesis(h, session.project.targetUrl, evidence)
      );
    });

    const unified = deduplicateFindings([...passive, ...aiHypotheses]);
    res.json({
      sessionId,
      targetUrl: session.project.targetUrl,
      totalFindings: unified.length,
      findings: unified,
    });
  } catch (error: any) {
    res.status(500).json({ error: "Failed to fetch unified findings", details: error.message });
  }
});

const SourceScanSchema = z.object({
  path: z.string().min(1, "Source path is required"),
  enableSemgrep: z.boolean().default(true),
  enableTrivy: z.boolean().default(true),
  enableGitleaks: z.boolean().default(true),
});

/**
 * POST /api/security/source-scan
 * Runs SAST, SCA, and secret detection on an authorized source code directory.
 */
apiRouter.post("/security/source-scan", async (req: Request, res: Response) => {
  try {
    const parsed = SourceScanSchema.parse(req.body);
    const summary = await SourceSecurityScanner.scanDirectory(parsed.path, {
      enableSemgrep: parsed.enableSemgrep,
      enableTrivy: parsed.enableTrivy,
      enableGitleaks: parsed.enableGitleaks,
    });
    res.json(summary);
  } catch (error: any) {
    res.status(400).json({ error: error.message || "Source scan failed" });
  }
});

const SaveAuthProfileSchema = z.object({
  name: z.string().min(1, 'Profile name is required'),
  origin: z.string().url('Origin must be a valid URL').optional(),
  description: z.string().optional(),
  storageState: z.record(z.any()).optional(),
  bearerToken: z.string().optional(),
});

/**
 * GET /api/auth/profiles
 * Lists all saved authenticated session profiles (OAuth, Bearer JWT, Cookie sessions).
 */
apiRouter.get('/auth/profiles', async (_req: Request, res: Response) => {
  try {
    const profiles = await AuthProfileManager.listProfiles();
    res.json({ total: profiles.length, profiles });
  } catch (error: any) {
    res.status(500).json({ error: 'Failed to list auth profiles', details: error.message });
  }
});

/**
 * POST /api/auth/profiles
 * Creates or imports an authenticated profile from storageState JSON or a Bearer token.
 */
apiRouter.post('/auth/profiles', async (req: Request, res: Response) => {
  try {
    const parsed = SaveAuthProfileSchema.parse(req.body);

    if (parsed.bearerToken && parsed.origin) {
      const result = await AuthProfileManager.createBearerProfile(
        parsed.name,
        parsed.origin,
        parsed.bearerToken
      );
      res.status(201).json({ message: 'Bearer token auth profile created', ...result });
      return;
    }

    if (parsed.storageState) {
      const result = await AuthProfileManager.saveProfile(
        parsed.name,
        parsed.storageState as any,
        { description: parsed.description, origin: parsed.origin }
      );
      res.status(201).json({ message: 'Auth profile created successfully', ...result });
      return;
    }

    res.status(400).json({ error: 'Must provide either storageState JSON or bearerToken + origin' });
  } catch (error: any) {
    res.status(400).json({ error: error.message || 'Failed to save auth profile' });
  }
});

/**
 * GET /api/auth/profiles/:name
 * Retrieves an individual auth profile's storage state.
 */
apiRouter.get('/auth/profiles/:name', async (req: Request, res: Response) => {
  try {
    const name = getParam(req.params.name);
    const profile = await AuthProfileManager.loadProfile(name);
    if (!profile) {
      res.status(404).json({ error: `Auth profile '${name}' not found` });
      return;
    }
    res.json(profile);
  } catch (error: any) {
    res.status(500).json({ error: 'Failed to load profile', details: error.message });
  }
});

/**
 * DELETE /api/auth/profiles/:name
 * Deletes an auth profile.
 */
apiRouter.delete('/auth/profiles/:name', async (req: Request, res: Response) => {
  try {
    const name = getParam(req.params.name);
    const ok = await AuthProfileManager.deleteProfile(name);
    if (!ok) {
      res.status(404).json({ error: `Profile '${name}' not found` });
      return;
    }
    res.json({ deleted: true, name });
  } catch (error: any) {
    res.status(500).json({ error: 'Failed to delete profile', details: error.message });
  }
});

/**
 * POST /api/auth/interactive-login
 * Launches a visible browser for the user to complete OAuth/SSO handshake.
 * Automatically captures cookies & localStorage once returned to target origin.
 */
apiRouter.post('/auth/interactive-login', async (req: Request, res: Response) => {
  try {
    const { targetUrl, profileName, timeoutMs } = req.body;
    if (!targetUrl || typeof targetUrl !== 'string') {
      res.status(400).json({ error: 'Valid targetUrl is required' });
      return;
    }

    const result = await AuthProfileManager.recordInteractiveOAuth(targetUrl, {
      profileName,
      timeoutMs: Number(timeoutMs) || 180000,
    });

    res.status(201).json({
      message: 'OAuth profile captured successfully',
      ...result,
    });
  } catch (error: any) {
    res.status(500).json({ error: 'Interactive OAuth login failed', details: error.message });
  }
});



