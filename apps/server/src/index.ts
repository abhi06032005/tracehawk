import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { apiRouter } from "./routes/api.js";
import { prisma, checkDatabaseConnection } from "./db.js";
import { investigationManager } from './ai/agent.js';
import { extensionRouter } from './browser/extension.js';
import { recoverReportChats, stopAllReportChats } from './ai/chat.js';

dotenv.config();

const app = express();
const PORT = parseInt(process.env.PORT || "4000", 10);
const HOST = "127.0.0.1"; // Strictly bound to localhost for security
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3001";
let agentReady = false;
app.use('/api/extension', extensionRouter);

// CORS configuration - only allow frontend dashboard
app.use(
  cors({
    origin: [FRONTEND_URL, "http://127.0.0.1:3001"],
    credentials: true,
  })
);

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use((req, res, next) => {
  if (!agentReady && req.method === 'POST' && /\/investigat/.test(req.path)) {
    res.status(503).json({ error: 'Investigation recovery is not complete; check database migrations and retry.' }); return;
  }
  const origin = req.get('Origin');
  if (origin && ![FRONTEND_URL, 'http://127.0.0.1:3001'].includes(origin) && !['GET','HEAD','OPTIONS'].includes(req.method)) {
    res.status(403).json({ error: 'Untrusted control origin' }); return;
  }
  next();
});

// Mount API routes
app.use("/api", apiRouter);

// Root fallback
app.get("/", (_req, res) => {
  res.json({
    name: "TraceHawk Browser Security Inspection Platform API",
    version: "1.0.0",
    docs: "/api/health",
  });
});

const server = app.listen(PORT, HOST, async () => {
  console.log(`=======================================================`);
  console.log(` TraceHawk API Server running at http://${HOST}:${PORT}`);
  console.log(` Bound locally to 127.0.0.1 for browser security testing`);
  console.log(` Frontend Dashboard allowed: ${FRONTEND_URL}`);
  console.log(`=======================================================`);

  const dbOk = await checkDatabaseConnection();
  if (dbOk) {
    try { await investigationManager.recoverInterrupted(); await recoverReportChats(); agentReady = true; }
    catch { console.error('[Database] Apply database migrations before starting AI audits.'); }
    console.log(`[Database] Connected to PostgreSQL 17 successfully.`);
  } else {
    console.error(`[Database] WARNING: Could not connect to PostgreSQL on startup.`);
  }
});

// Graceful shutdown
async function gracefulShutdown(signal: string) {
  stopAllReportChats();
  await investigationManager.stopAll();
  console.log(`[Server] Received ${signal}. Shutting down gracefully...`);
  server.close(async () => {
    try {
      await prisma.$disconnect();
      console.log("[Server] Database disconnected. Process exiting cleanly.");
      process.exit(0);
    } catch (err) {
      console.error("[Server] Error during shutdown:", err);
      process.exit(1);
    }
  });
}

process.on("SIGINT", () => gracefulShutdown("SIGINT"));
process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
