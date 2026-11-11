import { prisma } from "../db.js";
import { ALL_PASSIVE_RULES, FindingDraft } from "./rules.js";

export interface AnalysisSummary {
  analysisRunId: string;
  sessionId: string;
  status: string;
  findingsCount: number;
  bySeverity: Record<string, number>;
  byCategory: Record<string, number>;
  findings: FindingDraft[];
}

/**
 * Runs passive deterministic security analysis for a given session
 */
export async function analyzeSession(sessionId: string): Promise<AnalysisSummary> {
  const session = await prisma.session.findUnique({
    where: { id: sessionId },
    include: {
      httpExchanges: true,
      storageObservations: true,
      browserEvents: true,
    },
  });

  if (!session) {
    throw new Error(`Session with ID ${sessionId} not found`);
  }

  // 1. Create AnalysisRun record
  const run = await prisma.analysisRun.create({
    data: {
      sessionId,
      provider: "PASSIVE_ENGINE",
      status: "STARTED",
      startedAt: new Date(),
    },
  });

  try {
    const allFindings: FindingDraft[] = [];

    // 2. Execute each passive security rule
    for (const rule of ALL_PASSIVE_RULES) {
      try {
        const drafts = rule(
          session.httpExchanges,
          session.storageObservations,
          session.browserEvents
        );
        allFindings.push(...drafts);
      } catch (ruleError) {
        console.error(`Rule execution failed during analysis of session ${sessionId}:`, ruleError);
      }
    }

    // 3. Deduplicate findings by title + category
    const uniqueMap = new Map<string, FindingDraft>();
    for (const f of allFindings) {
      const key = `${f.category}:${f.title}:${JSON.stringify(f.evidence)}`;
      if (!uniqueMap.has(key)) {
        uniqueMap.set(key, f);
      }
    }
    const finalFindings = Array.from(uniqueMap.values());

    // 4. Persist findings in database
    if (finalFindings.length > 0) {
      // Clear any prior findings for this session to avoid duplicates on re-analysis
      await prisma.finding.deleteMany({
        where: { sessionId },
      });

      await prisma.finding.createMany({
        data: finalFindings.map((f) => ({
          sessionId,
          title: f.title,
          category: f.category,
          cweId: f.cweId,
          severity: f.severity,
          confidence: f.confidence,
          verificationStatus: f.verificationStatus,
          description: f.description,
          evidence: f.evidence as any,
          impact: f.impact,
          remediation: f.remediation,
        })),
      });
    }

    // 5. Update AnalysisRun and Session
    await prisma.analysisRun.update({
      where: { id: run.id },
      data: {
        status: "COMPLETED",
        completedAt: new Date(),
      },
    });

    await prisma.session.update({
      where: { id: sessionId },
      data: {
        status: "ANALYZED",
      },
    });

    // 6. Calculate breakdown metrics
    const bySeverity: Record<string, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };
    const byCategory: Record<string, number> = {};

    for (const f of finalFindings) {
      bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
      byCategory[f.category] = (byCategory[f.category] || 0) + 1;
    }

    return {
      analysisRunId: run.id,
      sessionId,
      status: "COMPLETED",
      findingsCount: finalFindings.length,
      bySeverity,
      byCategory,
      findings: finalFindings,
    };
  } catch (error: any) {
    await prisma.analysisRun.update({
      where: { id: run.id },
      data: {
        status: "FAILED",
        completedAt: new Date(),
        errorMessage: error.message,
      },
    });
    throw error;
  }
}
