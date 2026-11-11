import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import { readFile, unlink } from 'node:fs/promises';
import { resolve } from 'node:path';
import { tmpdir } from 'node:os';
import type { NormalizedFinding } from '../findings.js';

const execFileAsync = promisify(execFile);

export interface GitleaksResult {
  available: boolean;
  findings: NormalizedFinding[];
  error?: string;
}

export class GitleaksScannerAdapter {
  /**
   * Checks if Gitleaks CLI is available on the host.
   */
  public static async isAvailable(): Promise<boolean> {
    try {
      await execFileAsync('gitleaks', ['version'], { timeout: 3000 });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Runs Gitleaks directory scan on an authorized local directory.
   * Strips/masks raw secret values to uphold zero secret leakage.
   */
  public static async scan(
    targetDir: string,
    options: { timeoutMs?: number; signal?: AbortSignal } = {}
  ): Promise<GitleaksResult> {
    const timeout = options.timeoutMs ?? 60000;
    const tempReportPath = resolve(tmpdir(), `gitleaks-${randomUUID()}.json`);

    try {
      // Gitleaks returns exit code 1 if leaks are found, which is normal behavior
      try {
        await execFileAsync(
          'gitleaks',
          [
            'dir',
            '--path',
            targetDir,
            '--report-format',
            'json',
            '--report-path',
            tempReportPath,
            '--no-git',
          ],
          {
            timeout,
            signal: options.signal,
          }
        );
      } catch (execErr: any) {
        if (execErr.code === 'ENOENT') {
          return {
            available: false,
            findings: [],
            error: 'Gitleaks CLI is not installed or not in PATH.',
          };
        }
        // Gitleaks exits with code 1 or 2 when leaks are found
      }

      let content = '[]';
      try {
        content = await readFile(tempReportPath, 'utf8');
      } catch {
        content = '[]';
      }

      const results: any[] = JSON.parse(content || '[]');
      const findings: NormalizedFinding[] = results.map((item) => {
        // Redact secret strictly: never persist raw exposed secrets
        const secretLength = typeof item.Secret === 'string' ? item.Secret.length : 0;
        const fingerprint = item.Fingerprint || 'unknown';

        return {
          id: randomUUID(),
          title: `Exposed Credential: ${item.Description || item.RuleID || 'Hardcoded Secret'}`,
          severity: 'critical',
          status: 'needs_verification',
          target: targetDir,
          endpoint: `${item.File}:${item.StartLine || 1}`,
          method: 'SECRET_SCAN',
          cwe: ['CWE-798', 'CWE-259'],
          owasp_category: 'A07:2021-Identification and Authentication Failures',
          description: `Hardcoded credential or API secret identified: ${item.Description || item.RuleID}`,
          evidence: [
            {
              file: item.File,
              startLine: item.StartLine,
              endLine: item.EndLine,
              ruleId: item.RuleID,
              fingerprint,
              secretLength,
              secretValue: '[REDACTED_BY_POLICY]',
            },
          ],
          reproduction_steps: [
            `Check file ${item.File} at line ${item.StartLine || 1}`,
            `Revoke and rotate the exposed secret immediately`,
          ],
          impact: 'Exposure of credentials may allow unauthorized access to APIs or databases.',
          remediation: 'Remove hardcoded secret from repository, invalidate the compromised credential, and use environment variables or a secrets manager.',
          confidence: 95,
          source_agent: 'Agent 4 — Source Code Security',
          source_tool: 'gitleaks',
          created_at: new Date().toISOString(),
          verified_at: null,
        };
      });

      return { available: true, findings };
    } catch (err: any) {
      return {
        available: true,
        findings: [],
        error: err.message || 'Gitleaks scan failed.',
      };
    } finally {
      await unlink(tempReportPath).catch(() => {});
    }
  }
}

