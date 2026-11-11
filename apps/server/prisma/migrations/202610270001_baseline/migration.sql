-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "public";

-- CreateTable
CREATE TABLE "projects" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "targetUrl" TEXT NOT NULL,
    "allowedOrigins" TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "projects_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sessions" (
    "id" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'RECORDING',
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "endedAt" TIMESTAMP(3),
    "totalRequests" INTEGER NOT NULL DEFAULT 0,
    "totalErrors" INTEGER NOT NULL DEFAULT 0,

    CONSTRAINT "sessions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "http_exchanges" (
    "id" TEXT NOT NULL,
    "sessionId" TEXT NOT NULL,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "method" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "statusCode" INTEGER,
    "requestHeaders" JSONB,
    "responseHeaders" JSONB,
    "sanitizedRequestBody" TEXT,
    "sanitizedResponseBody" TEXT,
    "contentType" TEXT,
    "duration" DOUBLE PRECISION,
    "resourceType" TEXT,
    "failureReason" TEXT,
    "pageUrl" TEXT,

    CONSTRAINT "http_exchanges_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "browser_events" (
    "id" TEXT NOT NULL,
    "sessionId" TEXT NOT NULL,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "type" TEXT NOT NULL,
    "message" TEXT NOT NULL,
    "pageUrl" TEXT,
    "metadata" JSONB,

    CONSTRAINT "browser_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "storage_observations" (
    "id" TEXT NOT NULL,
    "sessionId" TEXT NOT NULL,
    "origin" TEXT NOT NULL,
    "storageType" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "sanitizedValue" TEXT,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "storage_observations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "findings" (
    "id" TEXT NOT NULL,
    "sessionId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "category" TEXT NOT NULL,
    "cweId" TEXT,
    "severity" TEXT NOT NULL,
    "confidence" TEXT NOT NULL,
    "verificationStatus" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "evidence" JSONB NOT NULL,
    "impact" TEXT NOT NULL,
    "remediation" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "findings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "analysis_runs" (
    "id" TEXT NOT NULL,
    "sessionId" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),
    "errorMessage" TEXT,

    CONSTRAINT "analysis_runs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "investigations" (
    "id" TEXT NOT NULL,
    "sessionId" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "currentStep" INTEGER NOT NULL DEFAULT 0,
    "maxSteps" INTEGER NOT NULL DEFAULT 10,
    "model" TEXT,
    "riskSummary" TEXT,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),
    "errorMessage" TEXT,

    CONSTRAINT "investigations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "investigation_steps" (
    "id" TEXT NOT NULL,
    "investigationId" TEXT NOT NULL,
    "stepNumber" INTEGER NOT NULL,
    "phase" TEXT NOT NULL,
    "thought" TEXT NOT NULL,
    "toolName" TEXT,
    "toolArgs" JSONB,
    "toolResult" JSONB,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "investigation_steps_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ai_hypotheses" (
    "id" TEXT NOT NULL,
    "investigationId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "affectedEndpoint" TEXT NOT NULL,
    "cweCategory" TEXT,
    "attackMechanism" TEXT,
    "prerequisites" TEXT,
    "potentialImpact" TEXT,
    "suggestedRemediation" TEXT,
    "confidence" TEXT NOT NULL DEFAULT 'MEDIUM',
    "verificationStatus" TEXT NOT NULL DEFAULT 'HYPOTHESIS',
    "supportingEvidenceIds" TEXT[],
    "verificationNotes" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ai_hypotheses_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "sessions_projectId_idx" ON "sessions"("projectId");

-- CreateIndex
CREATE INDEX "sessions_status_idx" ON "sessions"("status");

-- CreateIndex
CREATE INDEX "sessions_startedAt_idx" ON "sessions"("startedAt");

-- CreateIndex
CREATE INDEX "http_exchanges_sessionId_timestamp_idx" ON "http_exchanges"("sessionId", "timestamp");

-- CreateIndex
CREATE INDEX "http_exchanges_url_idx" ON "http_exchanges"("url");

-- CreateIndex
CREATE INDEX "http_exchanges_statusCode_idx" ON "http_exchanges"("statusCode");

-- CreateIndex
CREATE INDEX "http_exchanges_resourceType_idx" ON "http_exchanges"("resourceType");

-- CreateIndex
CREATE INDEX "browser_events_sessionId_timestamp_idx" ON "browser_events"("sessionId", "timestamp");

-- CreateIndex
CREATE INDEX "browser_events_type_idx" ON "browser_events"("type");

-- CreateIndex
CREATE INDEX "storage_observations_sessionId_timestamp_idx" ON "storage_observations"("sessionId", "timestamp");

-- CreateIndex
CREATE INDEX "storage_observations_origin_idx" ON "storage_observations"("origin");

-- CreateIndex
CREATE INDEX "storage_observations_storageType_idx" ON "storage_observations"("storageType");

-- CreateIndex
CREATE INDEX "findings_sessionId_severity_idx" ON "findings"("sessionId", "severity");

-- CreateIndex
CREATE INDEX "findings_category_idx" ON "findings"("category");

-- CreateIndex
CREATE INDEX "analysis_runs_sessionId_idx" ON "analysis_runs"("sessionId");

-- CreateIndex
CREATE INDEX "investigations_sessionId_status_idx" ON "investigations"("sessionId", "status");

-- CreateIndex
CREATE INDEX "investigation_steps_investigationId_stepNumber_idx" ON "investigation_steps"("investigationId", "stepNumber");

-- CreateIndex
CREATE INDEX "ai_hypotheses_investigationId_verificationStatus_idx" ON "ai_hypotheses"("investigationId", "verificationStatus");

-- AddForeignKey
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "projects"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "http_exchanges" ADD CONSTRAINT "http_exchanges_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "sessions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "browser_events" ADD CONSTRAINT "browser_events_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "sessions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "storage_observations" ADD CONSTRAINT "storage_observations_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "sessions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "findings" ADD CONSTRAINT "findings_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "sessions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "analysis_runs" ADD CONSTRAINT "analysis_runs_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "sessions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "investigations" ADD CONSTRAINT "investigations_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "sessions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "investigation_steps" ADD CONSTRAINT "investigation_steps_investigationId_fkey" FOREIGN KEY ("investigationId") REFERENCES "investigations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ai_hypotheses" ADD CONSTRAINT "ai_hypotheses_investigationId_fkey" FOREIGN KEY ("investigationId") REFERENCES "investigations"("id") ON DELETE CASCADE ON UPDATE CASCADE;
