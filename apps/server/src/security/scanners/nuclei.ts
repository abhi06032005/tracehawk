import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import { SecurityPolicyGateway } from '../policy.js';
import type { NormalizedFinding, FindingSeverity } from '../findings.js';

const execFileAsync = promisify(execFile);

export interface NucleiOptions {
  allowedOrigins: string[];
  tags?: string[];
  severity?: Array<'critical' | 'high' | 'medium' | 'low' | 'info'>;
  rateLimit?: number; // requests per second
  timeoutMs?: number;
  signal?: AbortSignal;
}

export interface NucleiResult {
  available: boolean;
  findings: NormalizedFinding[];
  target: string;
  error?: string;
}

export class NucleiScannerAdapter {
  /**
   * Checks if Nuclei CLI is available on the host.
   */
  public static async isAvailable(): Promise<boolean> {
    try {
      await execFileAsync('nuclei', ['-version'], { timeout: 3000 });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Executes Nuclei vulnerability scanner with strict scope validation and rate limiting.
   */
  public static async scan(
    targetUrl: string,
    options: NucleiOptions
  ): Promise<NucleiResult> {
    // 1. Strict scope validation through SecurityPolicyGateway
    const scopeCheck = SecurityPolicyGateway.isTargetInScope(targetUrl, options.allowedOrigins);
    if (!scopeCheck.allowed) {
      throw new Error(`Nuclei target rejected by policy gateway: ${scopeCheck.reason}`);
    }

    const rateLimit = Math.min(options.rateLimit ?? 10, 25); // cap at 25 req/s max
    const timeout = options.timeoutMs ?? 120000;
    const tags = (options.tags && options.tags.length > 0) ? options.tags.join(',') : 'misconfig,exposure,cve';
    const severities = (options.severity && options.severity.length > 0) ? options.severity.join(',') : 'critical,high,medium,low';

    const args = [
      '-u', targetUrl,
      '-jsonl',
      '-duc', // disable update checks
      '-rate-limit', String(rateLimit),
      '-tags', tags,
      '-severity', severities,
      '-timeout', '10',
    ];

    try {
      const { stdout } = await execFileAsync('nuclei', args, {
        timeout,
        signal: options.signal,
        maxBuffer: 20 * 1024 * 1024,
      });

      const findings: NormalizedFinding[] = [];
      const lines = stdout.split('\n').filter((l) => l.trim().length > 0);

      for (const line of lines) {
        try {
          const item = JSON.parse(line);
          const info = item.info || {};
          const cweList: string[] = [];

          if (info.classification?.['cwe-id']) {
            const rawCwe = info.classification['cwe-id'];
            if (Array.isArray(rawCwe)) {
              cweList.push(...rawCwe.map(String));
            } else if (typeof rawCwe === 'string') {
              cweList.push(rawCwe);
            }
          }

          const severityMap: Record<string, FindingSeverity> = {
            critical: 'critical',
            high: 'high',
            medium: 'medium',
            low: 'low',
            info: 'informational',
          };

          findings.push({
            id: randomUUID(),
            title: info.name || item['template-id'] || 'Nuclei Vulnerability Finding',
            severity: severityMap[info.severity?.toLowerCase()] || 'medium',
            status: 'needs_verification',
            target: targetUrl,
            endpoint: item['matched-at'] || targetUrl,
            method: item.type?.toUpperCase() || 'GET',
            cwe: cweList.length > 0 ? cweList : ['CWE-693'],
            owasp_category: info.classification?.['owasp-top10']?.[0] || 'A05:2021-Security Misconfiguration',
            description: info.description || `Nuclei template ${item['template-id']} matched.`,
            evidence: [
              {
                templateId: item['template-id'],
                templateUrl: item['template-url'],
                matcherName: item['matcher-name'],
                extractedResults: item['extracted-results'] || [],
                curlCommand: item['curl-command'],
              },
            ],
            reproduction_steps: [
              `Target endpoint: ${item['matched-at'] || targetUrl}`,
              `Matched template: ${item['template-id']}`,
              item['curl-command'] ? `Reproduction curl: ${item['curl-command']}` : 'Inspect endpoint configuration',
            ],
            impact: info.reference ? `References: ${Array.isArray(info.reference) ? info.reference.join(', ') : info.reference}` : 'Potential vulnerability.',
            remediation: info.remediation || 'Apply vendor security patch or update service configuration.',
            confidence: 85,
            source_agent: 'Agent 2 — Web Security',
            source_tool: 'nuclei',
            created_at: item.timestamp || new Date().toISOString(),
            verified_at: null,
          });
        } catch {
          // ignore unparseable line
        }
      }

      return {
        available: true,
        findings,
        target: targetUrl,
      };
    } catch (err: any) {
      if (err.code === 'ENOENT') {
        return {
          available: false,
          findings: [],
          target: targetUrl,
          error: 'Nuclei CLI is not installed or not in PATH.',
        };
      }
      return {
        available: true,
        findings: [],
        target: targetUrl,
        error: err.message || 'Nuclei scan failed.',
      };
    }
  }
}

