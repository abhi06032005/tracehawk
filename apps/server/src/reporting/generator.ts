import type { NormalizedFinding, FindingSeverity, FindingStatus } from '../security/findings.js';

export interface ReportMetadata {
  reportId: string;
  projectName: string;
  targetUrl: string;
  scanDate: string;
  scannerVersion: string;
  executiveSummary?: string;
}

export class ReportGenerator {
  /**
   * Generates a structured JSON security assessment report.
   */
  public static generateJson(metadata: ReportMetadata, findings: NormalizedFinding[]): string {
    const summary = this.calculateSummary(findings);
    return JSON.stringify(
      {
        metadata: {
          ...metadata,
          generator: 'DeepHat-V1-7B Autonomous Security Platform',
        },
        summary,
        findings,
      },
      null,
      2
    );
  }

  /**
   * Generates an executive and technical Markdown report.
   */
  public static generateMarkdown(metadata: ReportMetadata, findings: NormalizedFinding[]): string {
    const summary = this.calculateSummary(findings);

    let md = `# DeepHat Security Assessment Report\n\n`;
    md += `**Target Application:** \`${metadata.targetUrl}\`  \n`;
    md += `**Project:** ${metadata.projectName}  \n`;
    md += `**Date:** ${metadata.scanDate}  \n`;
    md += `**Platform Version:** ${metadata.scannerVersion}  \n`;
    md += `**Primary Reasoning Model:** DeepHat-V1-7B (100k YaRN)  \n\n`;

    md += `---\n\n`;
    md += `## 1. Executive Summary\n\n`;
    md += `Total Findings Discovered: **${findings.length}**  \n\n`;

    md += `| Severity | Count | Verified | Needs Verification | False Positives |\n`;
    md += `|---|---|---|---|---|\n`;
    md += `| **Critical** | ${summary.bySeverity.critical} | ${summary.byStatusAndSeverity.verified.critical} | ${summary.byStatusAndSeverity.needs_verification.critical} | ${summary.byStatusAndSeverity.false_positive.critical} |\n`;
    md += `| **High** | ${summary.bySeverity.high} | ${summary.byStatusAndSeverity.verified.high} | ${summary.byStatusAndSeverity.needs_verification.high} | ${summary.byStatusAndSeverity.false_positive.high} |\n`;
    md += `| **Medium** | ${summary.bySeverity.medium} | ${summary.byStatusAndSeverity.verified.medium} | ${summary.byStatusAndSeverity.needs_verification.medium} | ${summary.byStatusAndSeverity.false_positive.medium} |\n`;
    md += `| **Low** | ${summary.bySeverity.low} | ${summary.byStatusAndSeverity.verified.low} | ${summary.byStatusAndSeverity.needs_verification.low} | ${summary.byStatusAndSeverity.false_positive.low} |\n`;
    md += `| **Informational** | ${summary.bySeverity.informational} | ${summary.byStatusAndSeverity.verified.informational} | ${summary.byStatusAndSeverity.needs_verification.informational} | ${summary.byStatusAndSeverity.false_positive.informational} |\n\n`;

    if (metadata.executiveSummary) {
      md += `### Assessment Overview\n\n${metadata.executiveSummary}\n\n`;
    }

    md += `---\n\n`;
    md += `## 2. Detailed Technical Findings\n\n`;

    if (findings.length === 0) {
      md += `*No vulnerabilities or security weaknesses were identified in this session.*\n`;
      return md;
    }

    for (let i = 0; i < findings.length; i++) {
      const f = findings[i];
      md += `### ${i + 1}. ${f.title}\n\n`;
      md += `- **Severity:** \`${f.severity.toUpperCase()}\`\n`;
      md += `- **Status:** \`${f.status.toUpperCase()}\`\n`;
      md += `- **Endpoint:** \`${f.method} ${f.endpoint}\`\n`;
      md += `- **CWE:** ${f.cwe.length > 0 ? f.cwe.join(', ') : 'None'}\n`;
      md += `- **OWASP Category:** ${f.owasp_category || 'N/A'}\n`;
      md += `- **Confidence:** ${f.confidence}%\n`;
      md += `- **Source Agent/Tool:** ${f.source_agent} (${f.source_tool})\n\n`;

      md += `#### Description\n${f.description || 'No description provided.'}\n\n`;
      md += `#### Attacker Impact\n${f.impact || 'No impact analysis provided.'}\n\n`;
      md += `#### Remediation Guidance\n${f.remediation || 'Follow OWASP best practices to remediate this issue.'}\n\n`;

      if (f.reproduction_steps.length > 0) {
        md += `#### Reproduction Steps\n`;
        for (const step of f.reproduction_steps) {
          md += `- ${step}\n`;
        }
        md += `\n`;
      }

      if (f.evidence.length > 0) {
        md += `#### Supporting Evidence\n\`\`\`json\n${JSON.stringify(f.evidence, null, 2)}\n\`\`\`\n\n`;
      }

      md += `---\n\n`;
    }

    return md;
  }

  /**
   * Generates a self-contained, print-ready HTML/PDF report with styling.
   */
  public static generateHtml(metadata: ReportMetadata, findings: NormalizedFinding[]): string {
    const summary = this.calculateSummary(findings);

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>DeepHat Security Report — ${escapeHtml(metadata.projectName)}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 40px; color: #1c1917; background: #fafaf9; line-height: 1.6; }
    .container { max-width: 900px; margin: 0 auto; background: #ffffff; padding: 40px; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }
    h1 { font-size: 28px; margin-bottom: 8px; color: #0c0a09; }
    h2 { font-size: 20px; border-bottom: 2px solid #e7e5e4; padding-bottom: 8px; margin-top: 36px; }
    h3 { font-size: 16px; margin-top: 24px; color: #292524; }
    .badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
    .badge-critical { background: #fee2e2; color: #991b1b; }
    .badge-high { background: #ffedd5; color: #9a3412; }
    .badge-medium { background: #fef3c7; color: #92400e; }
    .badge-low { background: #e0f2fe; color: #075985; }
    .badge-informational { background: #f5f5f4; color: #57534e; }
    .badge-verified { background: #dcfce7; color: #166534; }
    .badge-needs_verification { background: #fef9c3; color: #854d0e; }
    .badge-false_positive { background: #f3f4f6; color: #6b7280; text-decoration: line-through; }
    table { width: 100%; border-collapse: collapse; margin: 20px 0; font-size: 13px; }
    th, td { border: 1px solid #e7e5e4; padding: 10px 12px; text-align: left; }
    th { background: #f5f5f4; font-weight: 600; }
    pre { background: #f5f5f4; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 12px; }
    .finding-card { border: 1px solid #e7e5e4; border-radius: 8px; padding: 20px; margin-bottom: 24px; background: #fff; }
    @media print { body { background: #fff; margin: 0; } .container { box-shadow: none; padding: 0; } }
  </style>
</head>
<body>
  <div class="container">
    <h1>DeepHat Security Assessment Report</h1>
    <p style="color: #78716c; font-size: 14px; margin-top: 0;">
      Target: <strong>${escapeHtml(metadata.targetUrl)}</strong> | Project: <strong>${escapeHtml(metadata.projectName)}</strong> | Date: ${metadata.scanDate}
    </p>

    <h2>Executive Summary</h2>
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Total</th>
          <th>Verified</th>
          <th>Needs Verification</th>
          <th>False Positive</th>
        </tr>
      </thead>
      <tbody>
        <tr><td><span class="badge badge-critical">Critical</span></td><td>${summary.bySeverity.critical}</td><td>${summary.byStatusAndSeverity.verified.critical}</td><td>${summary.byStatusAndSeverity.needs_verification.critical}</td><td>${summary.byStatusAndSeverity.false_positive.critical}</td></tr>
        <tr><td><span class="badge badge-high">High</span></td><td>${summary.bySeverity.high}</td><td>${summary.byStatusAndSeverity.verified.high}</td><td>${summary.byStatusAndSeverity.needs_verification.high}</td><td>${summary.byStatusAndSeverity.false_positive.high}</td></tr>
        <tr><td><span class="badge badge-medium">Medium</span></td><td>${summary.bySeverity.medium}</td><td>${summary.byStatusAndSeverity.verified.medium}</td><td>${summary.byStatusAndSeverity.needs_verification.medium}</td><td>${summary.byStatusAndSeverity.false_positive.medium}</td></tr>
        <tr><td><span class="badge badge-low">Low</span></td><td>${summary.bySeverity.low}</td><td>${summary.byStatusAndSeverity.verified.low}</td><td>${summary.byStatusAndSeverity.needs_verification.low}</td><td>${summary.byStatusAndSeverity.false_positive.low}</td></tr>
        <tr><td><span class="badge badge-informational">Informational</span></td><td>${summary.bySeverity.informational}</td><td>${summary.byStatusAndSeverity.verified.informational}</td><td>${summary.byStatusAndSeverity.needs_verification.informational}</td><td>${summary.byStatusAndSeverity.false_positive.informational}</td></tr>
      </tbody>
    </table>

    <h2>Detailed Findings (${findings.length})</h2>
    ${findings.map((f, i) => `
      <div class="finding-card">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
          <h3 style="margin: 0;">${i + 1}. ${escapeHtml(f.title)}</h3>
          <div>
            <span class="badge badge-${f.severity}">${f.severity}</span>
            <span class="badge badge-${f.status}">${f.status}</span>
          </div>
        </div>
        <p style="font-size: 13px; font-family: monospace; color: #57534e;">${f.method} ${escapeHtml(f.endpoint)}</p>
        <p><strong>Description:</strong> ${escapeHtml(f.description)}</p>
        <p><strong>Impact:</strong> ${escapeHtml(f.impact)}</p>
        <p><strong>Remediation:</strong> ${escapeHtml(f.remediation)}</p>
        ${f.evidence.length > 0 ? `<details><summary style="cursor: pointer; font-size: 12px; color: #78716c;">Supporting Evidence (${f.evidence.length})</summary><pre>${escapeHtml(JSON.stringify(f.evidence, null, 2))}</pre></details>` : ''}
      </div>
    `).join('')}
  </div>
</body>
</html>`;
  }

  private static calculateSummary(findings: NormalizedFinding[]) {
    const bySeverity: Record<FindingSeverity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      informational: 0,
    };

    const byStatus: Record<FindingStatus, number> = {
      discovered: 0,
      needs_verification: 0,
      verified: 0,
      false_positive: 0,
      inconclusive: 0,
      declined: 0,
    };

    const byStatusAndSeverity: Record<FindingStatus, Record<FindingSeverity, number>> = {
      discovered: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
      needs_verification: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
      verified: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
      false_positive: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
      inconclusive: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
      declined: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
    };

    for (const f of findings) {
      bySeverity[f.severity]++;
      byStatus[f.status]++;
      byStatusAndSeverity[f.status][f.severity]++;
    }

    return { bySeverity, byStatus, byStatusAndSeverity };
  }
}

function escapeHtml(str: string): string {
  return (str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

