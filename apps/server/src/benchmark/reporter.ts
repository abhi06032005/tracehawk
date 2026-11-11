import type { BenchmarkResult, ScoredRun } from './types.js';
import type { NormalizedFinding } from '../security/findings.js';

export class BenchmarkReporter {
  /**
   * Generates a detailed benchmark comparison report in Markdown.
   */
  public static generateMarkdown(result: BenchmarkResult): string {
    let md = `# TraceHawk Model Security Benchmark Comparison Report\n\n`;
    md += `**Benchmark Run ID:** \`${result.runId}\`  \n`;
    md += `**Date:** ${result.timestamp}  \n`;
    md += `**Target Application:** \`${result.targetUrl}\`  \n`;
    md += `**Test Fixture:** ${result.fixtureName} (\`${result.fixtureId}\`)  \n`;
    md += `**Models Evaluated:** ${result.modelsTested.join(', ')}  \n`;
    md += `**Prompt Variants:** ${result.promptVariantsTested.join(', ')}  \n`;
    md += `**Repeats Per Configuration:** ${result.repeats}  \n\n`;

    md += `---\n\n`;
    md += `## 1. Overall Model Performance Summary\n\n`;
    md += `| Model | Prompt Variant | Runs | Refusals | Avg Precision | Avg Recall | Avg F1 Score | Avg Latency | Total Cost (USD) |\n`;
    md += `|---|---|---|---|---|---|---|---|---|\n`;

    for (const agg of result.aggregates) {
      md += `| **${agg.modelName}** | \`${agg.promptVariantId}\` | ${agg.totalRuns} | ${agg.refusalCount} | ${(agg.avgPrecision * 100).toFixed(1)}% | ${(agg.avgRecall * 100).toFixed(1)}% | **${(agg.avgF1Score * 100).toFixed(1)}%** | ${agg.avgLatencyMs} ms | \$${agg.totalCostUsd.toFixed(4)} |\n`;
    }

    md += `\n---\n\n`;
    md += `## 2. Granular Vulnerability Detection Matrix\n\n`;
    md += `This matrix shows each model's detection rate, confirmation status, latency, and estimated cost across ground-truth vulnerabilities.\n\n`;

    md += `| Model | Prompt Variant | Vulnerability Class | Vulnerability Title | Status | Repeat Hit Rate | Avg Latency | Cost / Run |\n`;
    md += `|---|---|---|---|---|---|---|---|\n`;

    for (const row of result.comparisonTable) {
      const statusBadge =
        row.status === 'confirmed'
          ? '`CONFIRMED`'
          : row.status === 'declined'
          ? '`DECLINED (REFUSAL)`'
          : '`MISSED`';

      md += `| **${row.model}** | \`${row.promptVariant}\` | ${row.vulnerabilityClass} | ${row.vulnerabilityTitle} | ${statusBadge} | ${row.hitRate} | ${row.avgLatencyMs} ms | \$${row.costPerRunUsd.toFixed(4)} |\n`;
    }

    md += `\n---\n\n`;
    md += `## 3. Key Observations & Variant Analysis\n\n`;

    const variantGroups = new Map<string, typeof result.aggregates>();
    for (const agg of result.aggregates) {
      const list = variantGroups.get(agg.promptVariantId) || [];
      list.push(agg);
      variantGroups.set(agg.promptVariantId, list);
    }

    for (const [vId, list] of variantGroups.entries()) {
      const avgRecall = (list.reduce((sum, a) => sum + a.avgRecall, 0) / list.length) * 100;
      const refusals = list.reduce((sum, a) => sum + a.refusalCount, 0);
      md += `### Prompt Variant: \`${vId}\`\n`;
      md += `- **Average Detection Recall:** ${avgRecall.toFixed(1)}%\n`;
      md += `- **Total Model Refusals:** ${refusals}\n\n`;
    }

    md += `---\n*Generated autonomously by TraceHawk Research Benchmark Suite.*\n`;
    return md;
  }

  /**
   * Generates standalone individual security finding reports for each model evaluated.
   */
  public static generateIndividualModelReports(result: BenchmarkResult): Map<string, string> {
    const modelReports = new Map<string, string>();
    const runsByModel = new Map<string, typeof result.runs>();

    for (const run of result.runs) {
      const list = runsByModel.get(run.modelName) || [];
      list.push(run);
      runsByModel.set(run.modelName, list);
    }

    for (const [modelName, runs] of runsByModel.entries()) {
      modelReports.set(modelName, this.generateSingleModelReport(modelName, runs, result));
    }

    return modelReports;
  }

  /**
   * Builds an individual model's comprehensive markdown finding report.
   */
  public static generateSingleModelReport(
    modelName: string,
    runs: ScoredRun[],
    result: BenchmarkResult
  ): string {
    const providerId = runs[0]?.providerId || 'unknown';
    const totalRuns = runs.length;
    const refusals = runs.filter((r) => r.isRefusal).length;
    const avgPrecision = (runs.reduce((sum, r) => sum + r.precision, 0) / (totalRuns || 1)) * 100;
    const avgRecall = (runs.reduce((sum, r) => sum + r.recall, 0) / (totalRuns || 1)) * 100;
    const avgF1 = (runs.reduce((sum, r) => sum + r.f1Score, 0) / (totalRuns || 1)) * 100;
    const avgLatency = Math.round(runs.reduce((sum, r) => sum + r.latencyMs, 0) / (totalRuns || 1));
    const totalTokens = runs.reduce((sum, r) => sum + (r.tokenUsage?.totalTokens || 0), 0);
    const totalCost = runs.reduce((sum, r) => sum + (r.estimatedCostUsd || 0), 0);

    let md = `# Security Audit & Finding Report: ${modelName}\n\n`;
    md += `**Evaluated Model:** \`${modelName}\`  \n`;
    md += `**Provider ID:** \`${providerId}\`  \n`;
    md += `**Target Application:** \`${result.targetUrl}\`  \n`;
    md += `**Benchmark Test Suite:** ${result.fixtureName} (\`${result.fixtureId}\`)  \n`;
    md += `**Audit Timestamp:** ${result.timestamp}  \n`;
    md += `**Execution Runs:** ${totalRuns}  \n\n`;

    md += `---\n\n`;
    md += `## 1. Executive Performance & Alignment Scorecard\n\n`;
    md += `| Evaluation Metric | Value |\n`;
    md += `|---|---|\n`;
    md += `| **Average Precision** | ${avgPrecision.toFixed(1)}% |\n`;
    md += `| **Average Recall (Coverage)** | ${avgRecall.toFixed(1)}% |\n`;
    md += `| **Average F1 Score** | **${avgF1.toFixed(1)}%** |\n`;
    md += `| **Safety Guardrail Refusals** | ${refusals} / ${totalRuns} |\n`;
    md += `| **Average Response Latency** | ${avgLatency} ms |\n`;
    md += `| **Total Tokens Consumed** | ${totalTokens.toLocaleString()} |\n`;
    md += `| **Total API Cost (USD)** | \$${totalCost.toFixed(4)} |\n\n`;

    if (refusals > 0) {
      const reasons = runs.filter((r) => r.isRefusal && r.refusalReason).map((r) => r.refusalReason);
      md += `> [!WARNING] **Safety Guardrail Triggered:** This model declined or hedged ${refusals} run(s) due to safety policy filters.\n`;
      if (reasons.length > 0) {
        md += `> **Observed Reason:** ${reasons[0]}\n\n`;
      }
    } else {
      md += `> [!NOTE] **Full Policy Compliance:** This model completed all security audit runs without triggering alignment refusals.\n\n`;
    }

    md += `---\n\n`;
    md += `## 2. Security Findings Written by ${modelName}\n\n`;

    // Collect and de-duplicate unique findings produced by this model
    const seenFindingKeys = new Set<string>();
    const uniqueFindings: NormalizedFinding[] = [];

    for (const run of runs) {
      for (const finding of run.findings) {
        const key = `${finding.title}::${finding.endpoint}`;
        if (!seenFindingKeys.has(key)) {
          seenFindingKeys.add(key);
          uniqueFindings.push(finding);
        }
      }
    }

    if (uniqueFindings.length === 0) {
      md += `*No actionable security findings were recorded by this model (or all outputs were declined by safety filters).*\n\n`;
    } else {
      uniqueFindings.forEach((finding, idx) => {
        const statusBadge =
          finding.status === 'verified'
            ? '`VERIFIED`'
            : finding.status === 'false_positive'
            ? '`FALSE_POSITIVE`'
            : finding.status === 'declined'
            ? '`DECLINED (SAFETY FILTER)`'
            : '`NEEDS_VERIFICATION`';

        md += `### ${idx + 1}. [${finding.severity.toUpperCase()}] ${finding.title}\n\n`;
        md += `- **Deterministic Status:** ${statusBadge}\n`;
        md += `- **Affected Endpoint:** \`${finding.method || 'GET'} ${finding.endpoint}\`\n`;
        md += `- **OWASP Category:** \`${finding.owasp_category}\`\n`;
        md += `- **CWE Identifiers:** ${finding.cwe?.length ? finding.cwe.join(', ') : 'N/A'}\n`;
        md += `- **Model Confidence:** ${finding.confidence}% ${finding.raw_confidence_text ? `(\"${finding.raw_confidence_text}\")` : ''}\n`;
        md += `- **Prompt Variant Evaluated:** \`${finding.prompt_variant_id}\`\n\n`;

        md += `#### Attack Mechanism & Explanation\n`;
        md += `${finding.description || 'No detailed mechanism provided by model.'}\n\n`;

        md += `#### Prerequisites & Reproduction Steps\n`;
        if (finding.reproduction_steps && finding.reproduction_steps.length > 0) {
          for (const step of finding.reproduction_steps) {
            md += `- ${step}\n`;
          }
        } else {
          md += `- Follow standard endpoint interrogation.\n`;
        }
        md += `\n`;

        md += `#### Remediation Guidance\n`;
        md += `${finding.remediation || 'Apply standard input validation and defense-in-depth controls.'}\n\n`;

        if (finding.verifier_result) {
          md += `#### Deterministic Verification Proof\n`;
          md += `- **Verifier Decision:** \`${finding.verifier_result.status}\`\n`;
          md += `- **Verification Reason:** ${finding.verifier_result.reason || 'Verified through deterministic rule match.'}\n\n`;
        }

        md += `---\n\n`;
      });
    }

    md += `## 3. Raw Model Output Transcripts\n\n`;
    for (let i = 0; i < runs.length; i++) {
      const run = runs[i];
      md += `### Run #${i + 1} (Variant: \`${run.promptVariantId}\`, Latency: ${run.latencyMs}ms)\n\n`;
      if (run.rawText) {
        md += `\`\`\`json\n${run.rawText}\n\`\`\`\n\n`;
      } else {
        md += `*No raw text logged for this run.*\n\n`;
      }
    }

    md += `---\n*Generated autonomously by TraceHawk Reporting Suite.*\n`;
    return md;
  }

  /**
   * Generates a structured JSON benchmark export.
   */
  public static generateJson(result: BenchmarkResult): string {
    return JSON.stringify(result, null, 2);
  }
}

