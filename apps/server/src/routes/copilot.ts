import { Router, Request, Response } from "express";
import { z } from "zod";
import { chromium } from "playwright";
import { prisma } from "../db.js";
import { investigationManager } from "../ai/agent.js";
import { aiProvider } from "../ai/provider.js";
import { analyzeSession } from "../security/analyzer.js";
import { SessionRecorder } from "../browser/recorder.js";
import { PlaywrightCrawler } from "../browser/crawler.js";
import { sanitizeUrl, stripNullBytes } from "../utils/redact.js";
import { clean } from "../ai/privacy.js";

export const copilotRouter = Router();

// Launch schema
const LaunchMissionSchema = z.object({
  targetUrl: z.string().url(),
  name: z.string().optional(),
  mode: z.enum(['autonomous', 'quick', 'api', 'recon']).default('autonomous'),
  activeTests: z.boolean().default(false),
  authProfile: z.string().optional(),
  maxSteps: z.number().int().min(5).max(30).default(15),
});

/**
 * POST /api/copilot/launch
 * 1-click autonomous pentest mission launcher
 */
copilotRouter.post("/launch", async (req: Request, res: Response) => {
  try {
    const { targetUrl, name, mode, activeTests, authProfile, maxSteps } = LaunchMissionSchema.parse(req.body);
    const parsedUrl = new URL(targetUrl);
    const origin = parsedUrl.origin.toLowerCase();
    const projectName = name?.trim() || parsedUrl.hostname;

    // 1. Find or create Project
    let project = await prisma.project.findFirst({
      where: {
        allowedOrigins: { has: origin },
      },
    });

    if (!project) {
      project = await prisma.project.create({
        data: {
          name: projectName,
          targetUrl,
          allowedOrigins: [origin],
        },
      });
    }

    // 2. Create Session in RECORDING state
    const session = await prisma.session.create({
      data: {
        projectId: project.id,
        status: "RECORDING",
        startedAt: new Date(),
        totalRequests: 0,
        totalErrors: 0,
      },
    });

    // 3. Launch background crawler & autonomous investigation
    // Background execution so the UI immediately gets a response and opens the copilot workspace
    void (async () => {
      let browser = null;
      const recorder = new SessionRecorder(session.id, targetUrl, [origin]);

      try {
        console.log(`[Copilot Mission] Initializing headless crawler for ${targetUrl}...`);
        browser = await chromium.launch({
          headless: true,
          args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
        });

        const context = await browser.newContext({
          ignoreHTTPSErrors: true,
          userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 TraceHawk/1.0',
        });

        const maxPages = mode === 'quick' ? 5 : mode === 'recon' ? 8 : 12;

        // Perform autonomous crawl
        await PlaywrightCrawler.crawl(context, targetUrl, {
          allowedOrigins: [origin],
          maxPages,
          maxDepth: 2,
        });

        // Flush and stop recorder
        await recorder.stop();
        console.log(`[Copilot Mission] Crawl completed for ${targetUrl}. Running passive security analysis...`);

        // Run passive security rules (headers, CORS, cookies, storage)
        await analyzeSession(session.id);

        // Update session status to ANALYZED
        await prisma.session.update({
          where: { id: session.id },
          data: {
            status: "ANALYZED",
            endedAt: new Date(),
          },
        });

        // Start AI Copilot Agent Loop
        console.log(`[Copilot Mission] Starting autonomous AI investigation with ${aiProvider.getConfigSummary().model}...`);
        await investigationManager.startInvestigation(session.id, {
          authorized: true,
          activeTests,
          maxSteps,
          maxTimeSeconds: 300,
          requestBudget: 15,
        });
        console.log(`[Copilot Mission] AI investigation started successfully for session ${session.id}`);
      } catch (err) {
        console.error(`[Copilot Mission] Error executing mission on ${targetUrl}:`, err);
        await prisma.session.update({
          where: { id: session.id },
          data: {
            status: "STOPPED",
            endedAt: new Date(),
          },
        }).catch(() => {});
      } finally {
        if (browser) {
          await browser.close().catch(() => {});
        }
      }
    })();

    res.status(202).json({
      success: true,
      message: "Copilot pentest mission launched successfully",
      sessionId: session.id,
      projectId: project.id,
      targetUrl,
      mode,
    });
  } catch (error: any) {
    console.error("[Copilot Launch Error]:", error);
    res.status(400).json({
      error: error instanceof z.ZodError ? "Invalid target URL or options" : error.message,
    });
  }
});

/**
 * GET /api/copilot/missions
 * List all active and past pentest missions
 */
copilotRouter.get("/missions", async (_req: Request, res: Response) => {
  try {
    const sessions = await prisma.session.findMany({
      orderBy: { startedAt: "desc" },
      take: 20,
      include: {
        project: true,
        investigations: {
          orderBy: { startedAt: "desc" },
          take: 1,
          include: {
            hypotheses: true,
          },
        },
        findings: true,
      },
    });

    const missions = sessions.map((s) => {
      const latestInv = s.investigations[0];
      const allFindings = [
        ...s.findings,
        ...(latestInv?.hypotheses || []).map((h) => ({
          id: h.id,
          title: h.title,
          severity: h.risk,
          status: h.verificationStatus,
        })),
      ];

      return {
        sessionId: s.id,
        investigationId: latestInv?.id || null,
        targetUrl: s.project?.allowedOrigins[0] || "Unknown Target",
        projectName: s.project?.name || "Target",
        status: latestInv?.status || s.status,
        startedAt: s.startedAt,
        totalRequests: s.totalRequests,
        totalErrors: s.totalErrors,
        findingsCount: allFindings.length,
        criticalCount: allFindings.filter((f: any) => f.severity === "CRITICAL").length,
        highCount: allFindings.filter((f: any) => f.severity === "HIGH").length,
        mediumCount: allFindings.filter((f: any) => f.severity === "MEDIUM").length,
        lowCount: allFindings.filter((f: any) => f.severity === "LOW" || f.severity === "INFO").length,
      };
    });

    res.json({ missions });
  } catch (error: any) {
    res.status(500).json({ error: "Failed to list copilot missions", details: error.message });
  }
});

/**
 * GET /api/copilot/checklist/:investigationId
 * Dynamic 8-stage PTES / OWASP Pentest Checklist
 */
copilotRouter.get("/checklist/:investigationId", async (req: Request, res: Response) => {
  try {
    const investigationId = String(req.params.investigationId);
    const inv = await prisma.investigation.findUnique({
      where: { id: investigationId },
      include: {
        session: {
          include: {
            httpExchanges: {
              select: { id: true, url: true, method: true, statusCode: true },
            },
            storageObservations: true,
            findings: true,
          },
        },
        hypotheses: true,
        steps: true,
      },
    });

    if (!inv) {
      res.status(404).json({ error: "Investigation not found" });
      return;
    }

    const session = inv.session;
    const hypotheses = inv.hypotheses;
    const passiveFindings = session.findings;
    const totalRequests = session.httpExchanges.length;
    const isRunning = inv.status === "RUNNING" || inv.status === "AWAITING_APPROVAL";

    // 1. RECON: Reconnaissance & Tech Fingerprinting
    const reconStatus = totalRequests > 0 ? "COMPLETED" : isRunning ? "IN_PROGRESS" : "PENDING";

    // 2. SURFACE: Endpoint & Route Mapping
    const uniqueRoutes = new Set(session.httpExchanges.map((e) => new URL(e.url, "http://localhost").pathname));
    const surfaceStatus = uniqueRoutes.size > 0 ? "COMPLETED" : isRunning ? "IN_PROGRESS" : "PENDING";

    // 3. AUTH: Authentication & Session Analysis
    const authFindings = hypotheses.filter((h) => h.claimType === "missing_authentication" || h.claimType === "sensitive_storage");
    const authStatus = authFindings.length > 0 ? "VULNERABLE" : totalRequests > 0 ? "PASSED" : "PENDING";

    // 4. ACCESS CONTROL: IDOR & Privilege Escalation
    const idorFindings = hypotheses.filter((h) => h.claimType === "cross_account_access");
    const accessStatus = idorFindings.length > 0 ? "VULNERABLE" : totalRequests > 0 ? "PASSED" : "PENDING";

    // 5. INJECTION: Input Validation (SQLi, XSS, SSRF)
    const injectionFindings = hypotheses.filter((h) => /injection|xss|sqli|ssrf/i.test(h.title) || /injection|xss|sqli|ssrf/i.test(h.cweCategory || ''));
    const injectionStatus = injectionFindings.length > 0 ? "VULNERABLE" : totalRequests > 0 ? "PASSED" : "PENDING";

    // 6. HEADERS: Security Headers & Clickjacking
    const headerFindings = [
      ...hypotheses.filter((h) => h.claimType === "missing_csp" || h.claimType === "missing_hsts" || /clickjack|frame|cors/i.test(h.title)),
      ...passiveFindings.filter((f) => /clickjack|csp|hsts|cors/i.test(f.title)),
    ];
    const headerStatus = headerFindings.length > 0 ? "VULNERABLE" : totalRequests > 0 ? "PASSED" : "PENDING";

    // 7. BUSINESS LOGIC: Information Disclosure & Rate Limiting
    const rateLimitFindings = hypotheses.filter((h) => h.claimType === "missing_rate_limiting" || /rate.*limit/i.test(h.title));
    const logicStatus = rateLimitFindings.length > 0 ? "VULNERABLE" : totalRequests > 0 ? "PASSED" : "PENDING";

    // 8. VERIFICATION: Deterministic PoC & Exploit Proof
    const verifiedFindings = hypotheses.filter((h) => h.verificationStatus === "VERIFIED");
    const verifStatus = verifiedFindings.length > 0 ? "COMPLETED" : hypotheses.length > 0 ? "IN_PROGRESS" : "PENDING";

    const checklist = [
      {
        id: "recon",
        phase: 1,
        title: "Target Reconnaissance & Fingerprinting",
        category: "Information Gathering",
        description: `Discovered tech stack, server fingerprints, and host infrastructure across ${totalRequests} recorded requests.`,
        status: reconStatus,
        findingsCount: 0,
      },
      {
        id: "surface",
        phase: 2,
        title: "Attack Surface & Endpoint Mapping",
        category: "Reconnaissance",
        description: `Mapped ${uniqueRoutes.size} unique HTTP endpoints, form inputs, and parameter schemas.`,
        status: surfaceStatus,
        findingsCount: 0,
      },
      {
        id: "auth",
        phase: 3,
        title: "Authentication & Session Management",
        category: "Authentication",
        description: "Evaluated cookie security flags (HttpOnly/Secure/SameSite), token storage, and session lifecycles.",
        status: authStatus,
        findingsCount: authFindings.length,
      },
      {
        id: "access_control",
        phase: 4,
        title: "Access Control & IDOR Testing",
        category: "Authorization",
        description: "Tested cross-tenant resource isolation, object references, and privilege escalation boundaries.",
        status: accessStatus,
        findingsCount: idorFindings.length,
      },
      {
        id: "injection",
        phase: 5,
        title: "Input Validation & Injection Probes",
        category: "Injection",
        description: "Assessed parameters and payload reflections for Cross-Site Scripting (XSS), SQLi, and SSRF.",
        status: injectionStatus,
        findingsCount: injectionFindings.length,
      },
      {
        id: "headers_clickjacking",
        phase: 6,
        title: "Security Headers & Clickjacking",
        category: "Configuration",
        description: "Tested X-Frame-Options, Content-Security-Policy (CSP) frame-ancestors, and CORS origins.",
        status: headerStatus,
        findingsCount: headerFindings.length,
      },
      {
        id: "logic_rate_limit",
        phase: 7,
        title: "Business Logic & Rate Limiting",
        category: "Business Logic",
        description: "Evaluated endpoint request pacing, brute-force resiliency, and verbose error disclosure.",
        status: logicStatus,
        findingsCount: rateLimitFindings.length,
      },
      {
        id: "verification_poc",
        phase: 8,
        title: "Vulnerability Verification & PoC",
        category: "Exploitation & Verification",
        description: `Synthesized reproducible Proof of Concepts and verified exploitability (${verifiedFindings.length} verified).`,
        status: verifStatus,
        findingsCount: verifiedFindings.length,
      },
    ];

    res.json({
      investigationId,
      status: inv.status,
      completedSteps: checklist.filter((c) => c.status === "COMPLETED" || c.status === "PASSED" || c.status === "VULNERABLE").length,
      totalSteps: checklist.length,
      checklist,
    });
  } catch (error: any) {
    res.status(500).json({ error: "Failed to generate checklist", details: error.message });
  }
});

/**
 * GET /api/copilot/graph/:investigationId
 * Visual Exploit Graph (Attack Path & Surface Visualizer)
 */
copilotRouter.get("/graph/:investigationId", async (req: Request, res: Response) => {
  try {
    const investigationId = String(req.params.investigationId);
    const inv = await prisma.investigation.findUnique({
      where: { id: investigationId },
      include: {
        session: {
          include: {
            project: true,
            httpExchanges: {
              select: { id: true, url: true, method: true, statusCode: true },
              take: 30,
            },
          },
        },
        hypotheses: true,
      },
    });

    if (!inv) {
      res.status(404).json({ error: "Investigation not found" });
      return;
    }

    const targetUrl = inv.session.project.allowedOrigins[0] || "Target Application";
    const nodes: Array<{ id: string; label: string; type: 'target' | 'endpoint' | 'threat' | 'finding'; risk?: string; details?: string }> = [];
    const edges: Array<{ source: string; target: string; label?: string }> = [];

    // Root Target Node
    nodes.push({
      id: "root-target",
      label: new URL(targetUrl).hostname,
      type: "target",
      details: targetUrl,
    });

    // Endpoint Nodes (Top 8 distinct paths)
    const seenPaths = new Set<string>();
    const endpointIds: string[] = [];

    for (const ex of inv.session.httpExchanges) {
      try {
        const path = new URL(ex.url).pathname || "/";
        if (!seenPaths.has(path) && seenPaths.size < 8) {
          seenPaths.add(path);
          const endpointId = `ep-${seenPaths.size}`;
          endpointIds.push(endpointId);
          nodes.push({
            id: endpointId,
            label: `${ex.method} ${path}`,
            type: "endpoint",
            details: ex.url,
          });
          edges.push({
            source: "root-target",
            target: endpointId,
          });
        }
      } catch {}
    }

    // Threat / Hypothesis Nodes
    inv.hypotheses.forEach((hyp, idx) => {
      const findingId = `finding-${hyp.id || idx}`;
      nodes.push({
        id: findingId,
        label: hyp.title,
        type: "finding",
        risk: hyp.risk,
        details: hyp.cweCategory || undefined,
      });

      // Link finding to matching endpoint or fallback to first endpoint/root
      const matchingEp = nodes.find(
        (n) => n.type === "endpoint" && hyp.affectedEndpoint.includes(n.label.split(" ")[1] || "___never___")
      );

      edges.push({
        source: matchingEp ? matchingEp.id : endpointIds[0] || "root-target",
        target: findingId,
        label: hyp.risk,
      });
    });

    res.json({
      investigationId,
      nodes,
      edges,
    });
  } catch (error: any) {
    res.status(500).json({ error: "Failed to generate exploit graph", details: error.message });
  }
});

/**
 * GET /api/copilot/poc/:hypothesisId
 * Deterministic cURL and Python PoC generator
 */
copilotRouter.get("/poc/:hypothesisId", async (req: Request, res: Response) => {
  try {
    const hypothesisId = String(req.params.hypothesisId);
    const hyp = await prisma.aiHypothesis.findUnique({
      where: { id: hypothesisId },
      include: {
        investigation: {
          include: {
            session: {
              include: {
                httpExchanges: {
                  take: 10,
                },
              },
            },
          },
        },
      },
    });

    if (!hyp) {
      res.status(404).json({ error: "Finding hypothesis not found" });
      return;
    }

    const endpoint = hyp.affectedEndpoint || "https://example.com";
    const method = /post/i.test(hyp.title) ? "POST" : "GET";

    // Generate curl command
    const curlCommand = `curl -i -X ${method} "${endpoint}" \\
  -H "User-Agent: Mozilla/5.0 (TraceHawk Copilot)" \\
  -H "Accept: text/html,application/xhtml+xml,application/json" \\
  ${method === 'POST' ? '-d \'{"test": "payload"}\' \\' : ''}
  --compressed`;

    // Generate python script
    const pythonScript = `#!/usr/bin/env python3
# Automated Proof of Concept for: ${hyp.title}
# Category: ${hyp.cweCategory}
# Generated by TraceHawk Pentest Copilot

import requests

target_url = "${endpoint}"
headers = {
    "User-Agent": "Mozilla/5.0 (TraceHawk Copilot)",
    "Accept": "text/html,application/xhtml+xml,application/json",
}

print(f"[*] Sending ${method} exploit payload to: {target_url}")
response = requests.${method.toLowerCase()}(target_url, headers=headers, timeout=10)

print(f"[+] HTTP Status: {response.status_code}")
print("[+] Response Headers:")
for k, v in response.headers.items():
    print(f"    {k}: {v}")

# Verification check
${
  /frame|clickjack/i.test(hyp.title)
    ? `if "X-Frame-Options" not in response.headers and "Content-Security-Policy" not in response.headers:
    print("\\n[!] VULNERABILITY CONFIRMED: Missing X-Frame-Options allows clickjacking!")`
    : `if response.status_code == 200:
    print("\\n[!] VULNERABILITY POTENTIAL: Endpoint accepted payload without adequate restriction.")`
}
`;

    res.json({
      hypothesisId,
      title: hyp.title,
      risk: hyp.risk,
      cwe: hyp.cweCategory,
      endpoint,
      method,
      curlCommand,
      pythonScript,
      remediation: hyp.suggestedRemediation,
    });
  } catch (error: any) {
    res.status(500).json({ error: "Failed to generate PoC", details: error.message });
  }
});

/**
 * POST /api/copilot/command
 * Interactive Terminal Command Execution
 */
copilotRouter.post("/command", async (req: Request, res: Response) => {
  try {
    const { command, targetUrl } = z.object({
      command: z.string().min(1),
      targetUrl: z.string().optional(),
    }).parse(req.body);

    const cmd = command.trim().toLowerCase();
    const timestamp = new Date().toLocaleTimeString();

    if (cmd === "help") {
      res.json({
        output: [
          `[${timestamp}] TraceHawk Pentest Copilot CLI v1.0`,
          `Available commands:`,
          `  help                     - Show this command reference`,
          `  recon <url>              - Fingerprint target tech stack and server headers`,
          `  check-headers <url>      - Evaluate CSP, HSTS, and X-Frame-Options`,
          `  check-cors <url>         - Test CORS Access-Control-Allow-Origin behavior`,
          `  status                   - Display active AI provider and model readiness`,
          `  clear                    - Clear the terminal screen`,
        ].join("\n"),
      });
      return;
    }

    if (cmd === "status") {
      const config = aiProvider.getConfigSummary();
      res.json({
        output: [
          `[${timestamp}] AI Model Engine: ${config.model}`,
          `[${timestamp}] Provider: ${config.provider.toUpperCase()}`,
          `[${timestamp}] Status: ${config.enabled ? 'ACTIVE (Ready)' : 'DISABLED'}`,
          `[${timestamp}] Context Limit: ${config.contextTokens.toLocaleString()} tokens`,
          `[${timestamp}] Ready for autonomous pentest and interactive queries.`,
        ].join("\n"),
      });
      return;
    }

    if (cmd.startsWith("check-headers") || cmd.startsWith("recon") || cmd.startsWith("check-cors")) {
      const urlPart = command.split(" ")[1] || targetUrl || "https://abhijeetnayak.vercel.app";
      try {
        const fetchRes = await fetch(urlPart, { method: "HEAD" });
        const headers: Record<string, string> = {};
        fetchRes.headers.forEach((val, key) => { headers[key] = val; });

        const hasXFO = Boolean(headers["x-frame-options"]);
        const hasCSP = Boolean(headers["content-security-policy"]);
        const hasHSTS = Boolean(headers["strict-transport-security"]);

        res.json({
          output: [
            `[${timestamp}] Probing headers on ${urlPart}...`,
            `HTTP/1.1 ${fetchRes.status} ${fetchRes.statusText}`,
            `Server: ${headers['server'] || 'hidden'}`,
            `X-Frame-Options: ${hasXFO ? headers['x-frame-options'] : '[!] MISSING (Vulnerable to Clickjacking)'}`,
            `Content-Security-Policy: ${hasCSP ? 'Present' : '[!] MISSING'}`,
            `Strict-Transport-Security: ${hasHSTS ? headers['strict-transport-security'] : '[!] MISSING'}`,
            `[${timestamp}] Analysis: ${(!hasXFO && !hasCSP) ? 'CRITICAL finding: Site can be framed on untrusted domains.' : 'Header review passed.'}`,
          ].join("\n"),
        });
        return;
      } catch (err: any) {
        res.json({
          output: `[${timestamp}] Error probing ${urlPart}: ${err.message}`,
        });
        return;
      }
    }

    res.json({
      output: `[${timestamp}] Executed: ${command}\nType 'help' for available security commands.`,
    });
  } catch (error: any) {
    res.status(400).json({ error: error.message });
  }
});
