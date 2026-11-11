import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import type { NormalizedFinding, FindingSeverity } from '../findings.js';

const execFileAsync = promisify(execFile);

export interface SemgrepResult {
  available: boolean;
  findings: NormalizedFinding[];
  error?: string;
}

export class SemgrepScannerAdapter {
  /**
   * Checks if Semgrep CLI is available on the host.
   */
  public static async isAvailable(): Promise<boolean> {
    try {
      await execFileAsync('semgrep', ['--version'], { timeout: 3000 });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Runs Semgrep static analysis on an authorized local directory and returns normalized findings.
   */
  public static async scan(
    targetDir: string,
    options: { timeoutMs?: number; signal?: AbortSignal } = {}
  ): Promise<SemgrepResult> {
    const timeout = options.timeoutMs ?? 60000;

    try {
      const { stdout } = await execFileAsync(
        'semgrep',
        ['scan', '--config', 'auto', '--json', targetDir],
        {
          timeout,
          signal: options.signal,
          maxBuffer: 10 * 1024 * 1024,
        }
      );

      const parsed = JSON.parse(stdout);
      const results: any[] = Array.isArray(parsed.results) ? parsed.results : [];

      const findings: NormalizedFinding[] = results.map((r) => {
        const severityMap: Record<string, FindingSeverity> = {
          ERROR: 'high',
          WARNING: 'medium',
          INFO: 'low',
        };

        const cweList: string[] = [];
        const rawCwe = r.extra?.metadata?.cwe;
        if (Array.isArray(rawCwe)) {
          cweList.push(...rawCwe.map(String));
        } else if (typeof rawCwe === 'string') {
          cweList.push(rawCwe);
        }

        return {
          id: randomUUID(),
          title: r.check_id || 'Static Code Analysis Finding',
          severity: severityMap[r.extra?.severity] || 'medium',
          status: 'needs_verification',
          target: targetDir,
          endpoint: `${r.path}:${r.start?.line || 1}`,
          method: 'STATIC_SOURCE',
          cwe: cweList.length > 0 ? cweList : ['CWE-798'],
          owasp_category: r.extra?.metadata?.owasp || 'A06:2021-Vulnerable and Outdated Components',
          description: r.extra?.message || 'Potential security weakness identified in source code.',
          evidence: [
            {
              file: r.path,
              startLine: r.start?.line,
              endLine: r.end?.line,
              codeSnippet: r.extra?.lines || '',
            },
          ],
          reproduction_steps: [
            `Inspect file ${r.path} around line ${r.start?.line || 1}`,
            `Review rule ${r.check_id}`,
          ],
          impact: r.extra?.metadata?.shortlink || 'Potential logic vulnerability or insecure pattern.',
          remediation: r.extra?.fix || 'Review and refactor code according to secure coding standards.',
          confidence: 80,
          source_agent: 'Agent 4 — Source Code Security',
          source_tool: 'semgrep',
          created_at: new Date().toISOString(),
          verified_at: null,
        };
      });

      return { available: true, findings };
    } catch (err: any) {
      if (err.code === 'ENOENT') {
        return {
          available: false,
          findings: [],
          error: 'Semgrep CLI is not installed or not in PATH.',
        };
      }
      return {
        available: true,
        findings: [],
        error: err.message || 'Semgrep scan failed.',
      };
    }
  }
}

