import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "http";
import express from "express";
import cors from "cors";
import { apiRouter } from "./routes/api.js";
import { prisma, checkDatabaseConnection } from "./db.js";

const testApp = express();
testApp.use(cors());
testApp.use(express.json());
testApp.use("/api", apiRouter);

let server: http.Server;
const TEST_PORT = 4055;
const BASE_URL = `http://127.0.0.1:${TEST_PORT}/api`;

beforeAll(async () => {
  let ready = false;
  for (let i = 0; i < 90; i++) {
    try { if ((await fetch('http://127.0.0.1:3000', { signal: AbortSignal.timeout(1000) })).ok) { ready = true; break; } } catch {}
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  if (!ready) throw new Error('Start the authorized local Juice Shop container before recorder tests');
  await new Promise<void>((resolve) => {
    server = testApp.listen(TEST_PORT, "127.0.0.1", () => resolve());
  });
}, 60000);

afterAll(async () => {
  if (!server) return;
  await new Promise<void>((resolve) => {
    server.close(() => resolve());
  });
});

describe("TraceHawk End-to-End System Tests", () => {
  let projectId: string;
  let sessionId: string;
  afterAll(async () => {
    if (sessionId) await fetch(`${BASE_URL}/sessions/${sessionId}/stop`, { method: 'POST' }).catch(() => {});
    if (projectId) await prisma.project.delete({ where: { id: projectId } });
  });

  it("should verify health endpoint and PostgreSQL connection", async () => {
    const res = await fetch(`${BASE_URL}/health`);
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.status).toBe("healthy");
    expect(json.services.database).toBe("connected");
  });

  it("should create an inspection project with target URL and allowed origins", async () => {
    const res = await fetch(`${BASE_URL}/projects`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: "E2E Test Target",
        targetUrl: "http://127.0.0.1:3000",
        allowedOrigins: ["http://127.0.0.1:3000"],
      }),
    });

    expect(res.status).toBe(201);
    const json = await res.json();
    expect(json.project).toBeDefined();
    expect(json.project.name).toBe("E2E Test Target");
    expect(json.project.targetUrl).toBe("http://127.0.0.1:3000");
    projectId = json.project.id;
  });

  it("should launch visible browser session, record network & storage, and navigate", async () => {
    const res = await fetch(`${BASE_URL}/sessions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        projectId,
        targetUrl: "http://127.0.0.1:3000",
      }),
    });

    expect(res.status).toBe(201);
    const json = await res.json();
    expect(json.sessionId).toBeDefined();
    expect(json.status).toBe("RECORDING");
    sessionId = json.sessionId;

    // Allow browser time to navigate and record initial traffic
    await new Promise((r) => setTimeout(r, 4000));
  }, 20000);

  it("should pause and resume recording session", async () => {
    const pauseRes = await fetch(`${BASE_URL}/sessions/${sessionId}/pause`, {
      method: "POST",
    });
    expect(pauseRes.status).toBe(200);

    const resumeRes = await fetch(`${BASE_URL}/sessions/${sessionId}/resume`, {
      method: "POST",
    });
    expect(resumeRes.status).toBe(200);
  });

  it("should stop recording session, capture storage snapshot, and finalize", async () => {
    const res = await fetch(`${BASE_URL}/sessions/${sessionId}/stop`, {
      method: "POST",
    });
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.session.status).toBe("STOPPED");
  });

  it("should retrieve recorded traffic and browser events from database", async () => {
    const trafficRes = await fetch(`${BASE_URL}/sessions/${sessionId}/traffic`);
    expect(trafficRes.status).toBe(200);
    const trafficJson = await trafficRes.json();
    expect(trafficJson.exchanges.length).toBeGreaterThan(0);

    const first = trafficJson.exchanges[0];
    expect(first.url).toContain("127.0.0.1:3000");
    expect(first.method).toBeDefined();

    const eventsRes = await fetch(`${BASE_URL}/sessions/${sessionId}/events`);
    expect(eventsRes.status).toBe(200);
    const eventsJson = await eventsRes.json();
    expect(eventsJson.events.length).toBeGreaterThan(0);
  });

  it("should run passive security analysis and produce real findings linked to evidence", async () => {
    const res = await fetch(`${BASE_URL}/sessions/${sessionId}/analyze`, {
      method: "POST",
    });
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.summary.status).toBe("COMPLETED");
    expect(json.summary.findingsCount).toBeGreaterThan(0);

    // Retrieve findings
    const findingsRes = await fetch(`${BASE_URL}/sessions/${sessionId}/findings`);
    expect(findingsRes.status).toBe(200);
    const findingsJson = await findingsRes.json();
    expect(findingsJson.findings.length).toBeGreaterThan(0);

    const firstFinding = findingsJson.findings[0];
    expect(firstFinding.title).toBeDefined();
    expect(firstFinding.category).toBeDefined();
    expect(firstFinding.severity).toBeDefined();
    expect(firstFinding.evidence).toBeDefined();
    expect(firstFinding.impact).toBeDefined();
    expect(firstFinding.remediation).toBeDefined();
  });

  it("should export sanitized security report and traffic JSON", async () => {
    const res = await fetch(`${BASE_URL}/sessions/${sessionId}/export?format=json`);
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.title).toBe("TraceHawk Security Inspection Report");
    expect(json.session.id).toBe(sessionId);
    expect(json.findings.length).toBeGreaterThan(0);
  });
});

