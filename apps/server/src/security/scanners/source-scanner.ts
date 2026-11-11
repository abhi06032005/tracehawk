import { existsSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { SemgrepScannerAdapter } from './semgrep.js';
import { TrivyScannerAdapter } from './trivy.js';
import { GitleaksScannerAdapter } from './gitleaks.js';
import { deduplicateFindings, type NormalizedFinding } from '../findings.js';

export interface SourceScanSummary {
  targetDir: string;
  scannersExecuted: Array<{
    name: 'semgrep' | 'trivy' | 'gitleaks';
    available: boolean;
    findingsCount: number;
    error?: string;
  }>;
  totalFindings: number;
  findings: NormalizedFinding[];
  durationMs: number;
}

export class SourceSecurityScanner {
  /**
   * Executes static application security testing (SAST), dependency scanning (SCA),
   * and secret detection across an authorized source code directory.
   */
  public static async scanDirectory(
    rawPath: string,
    options: {
      enableSemgrep?: boolean;
      enableTrivy?: boolean;
      enableGitleaks?: boolean;
      timeoutMs?: number;
      signal?: AbortSignal;
    } = {}
  ): Promise<SourceScanSummary> {
    const startTime = Date.now();
    const targetDir = resolve(rawPath);

    if (!existsSync(targetDir) || !statSync(targetDir).isDirectory()) {
      throw new Error(`Invalid source path: '${targetDir}' is not an accessible directory.`);
    }

    const {
      enableSemgrep = true,
      enableTrivy = true,
      enableGitleaks = true,
      timeoutMs = 60000,
      signal,
    } = options;

    const allFindings: NormalizedFinding[] = [];
    const executionSummaries: SourceScanSummary['scannersExecuted'] = [];

    // 1. Run Semgrep SAST
    if (enableSemgrep) {
      const res = await SemgrepScannerAdapter.scan(targetDir, { timeoutMs, signal });
      executionSummaries.push({
        name: 'semgrep',
        available: res.available,
        findingsCount: res.findings.length,
        error: res.error,
      });
      allFindings.push(...res.findings);
    }

    // 2. Run Trivy SCA
    if (enableTrivy) {
      const res = await TrivyScannerAdapter.scan(targetDir, { timeoutMs, signal });
      executionSummaries.push({
        name: 'trivy',
        available: res.available,
        findingsCount: res.findings.length,
        error: res.error,
      });
      allFindings.push(...res.findings);
    }

    // 3. Run Gitleaks Secret Detection
    if (enableGitleaks) {
      const res = await GitleaksScannerAdapter.scan(targetDir, { timeoutMs, signal });
      executionSummaries.push({
        name: 'gitleaks',
        available: res.available,
        findingsCount: res.findings.length,
        error: res.error,
      });
      allFindings.push(...res.findings);
    }

    const deduplicated = deduplicateFindings(allFindings);

    return {
      targetDir,
      scannersExecuted: executionSummaries,
      totalFindings: deduplicated.length,
      findings: deduplicated,
      durationMs: Date.now() - startTime,
    };
  }
}

