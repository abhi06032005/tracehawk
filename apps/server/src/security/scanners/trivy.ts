import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import type { NormalizedFinding, FindingSeverity } from '../findings.js';

const execFileAsync = promisify(execFile);

export interface TrivyResult {
  available: boolean;
  findings: NormalizedFinding[];
  error?: string;
}

export class TrivyScannerAdapter {
  /**
   * Checks if Trivy CLI is available on the host.
   */
  public static async isAvailable(): Promise<boolean> {
    try {
      await execFileAsync('trivy', ['--version'], { timeout: 3000 });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Runs Trivy filesystem scan on an authorized local directory.
   */
  public static async scan(
    targetDir: string,
    options: { timeoutMs?: number; signal?: AbortSignal } = {}
  ): Promise<TrivyResult> {
    const timeout = options.timeoutMs ?? 60000;

    try {
      const { stdout } = await execFileAsync(
        'trivy',
        ['fs', '--format', 'json', targetDir],
        {
          timeout,
          signal: options.signal,
          maxBuffer: 15 * 1024 * 1024,
        }
      );

      const parsed = JSON.parse(stdout);
      const results: any[] = Array.isArray(parsed.Results) ? parsed.Results : [];
      const findings: NormalizedFinding[] = [];

      for (const res of results) {
        const vulns: any[] = Array.isArray(res.Vulnerabilities) ? res.Vulnerabilities : [];

        for (const v of vulns) {
          const severityMap: Record<string, FindingSeverity> = {
            CRITICAL: 'critical',
            HIGH: 'high',
            MEDIUM: 'medium',
            LOW: 'low',
          };

          const cweList = Array.isArray(v.CweIDs) ? v.CweIDs : [];

          findings.push({
            id: randomUUID(),
            title: `${v.VulnerabilityID} in ${v.PkgName} (${v.InstalledVersion})`,
            severity: severityMap[v.Severity] || 'medium',
            status: 'needs_verification',
            target: targetDir,
            endpoint: `${res.Target}:${v.PkgName}`,
            method: 'DEPENDENCY_SCA',
            cwe: cweList.length > 0 ? cweList : ['CWE-1395'],
            owasp_category: 'A06:2021-Vulnerable and Outdated Components',
            description: v.Description || v.Title || 'Known dependency vulnerability.',
            evidence: [
              {
                package: v.PkgName,
                installedVersion: v.InstalledVersion,
                fixedVersion: v.FixedVersion || 'None available',
                primaryUrl: v.PrimaryURL,
                targetFile: res.Target,
              },
            ],
            reproduction_steps: [
              `Inspect dependency ${v.PkgName}@${v.InstalledVersion} declared in ${res.Target}`,
              `Refer to advisory: ${v.PrimaryURL || v.VulnerabilityID}`,
            ],
            impact: `Component contains known vulnerability ${v.VulnerabilityID}.`,
            remediation: v.FixedVersion
              ? `Upgrade ${v.PkgName} to version ${v.FixedVersion} or later.`
              : 'Monitor upstream advisory for patched release or evaluate replacement.',
            confidence: 90,
            source_agent: 'Agent 4 — Source Code Security',
            source_tool: 'trivy',
            created_at: new Date().toISOString(),
            verified_at: null,
          });
        }
      }

      return { available: true, findings };
    } catch (err: any) {
      if (err.code === 'ENOENT') {
        return {
          available: false,
          findings: [],
          error: 'Trivy CLI is not installed or not in PATH.',
        };
      }
      return {
        available: true,
        findings: [],
        error: err.message || 'Trivy scan failed.',
      };
    }
  }
}

