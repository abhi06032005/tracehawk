-- AlterTable
ALTER TABLE "investigations" ADD COLUMN     "activeTests" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "allowedOrigins" TEXT[],
ADD COLUMN     "authorized" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "deadline" TIMESTAMP(3),
ADD COLUMN     "maxTimeSeconds" INTEGER NOT NULL DEFAULT 120,
ADD COLUMN     "requestBudget" INTEGER NOT NULL DEFAULT 10,
ADD COLUMN     "requestsUsed" INTEGER NOT NULL DEFAULT 0;

-- AlterTable
ALTER TABLE "investigation_steps" ADD COLUMN     "approvalId" TEXT,
ADD COLUMN     "approvalStatus" TEXT,
ADD COLUMN     "decision" JSONB,
ADD COLUMN     "evaluation" JSONB;

-- AlterTable
ALTER TABLE "ai_hypotheses" ADD COLUMN     "claimType" TEXT NOT NULL DEFAULT 'other',
ADD COLUMN     "risk" TEXT NOT NULL DEFAULT 'INFO';

-- CreateIndex
CREATE UNIQUE INDEX "investigation_steps_approvalId_key" ON "investigation_steps"("approvalId");
