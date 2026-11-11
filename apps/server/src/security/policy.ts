import { z } from 'zod';
import { Evidence, ToolName, ToolResult } from '../ai/contracts.js';

export type ToolRiskTier = 'READ_ONLY' | 'PASSIVE' | 'ACTIVE_SAFE' | 'MUTATING_APPROVAL';

export interface ToolSecurityMetadata {
  name: ToolName;
  version: string;
  description: string;
  risk: ToolRiskTier;
  timeoutMs: number;
  requiredPermissions: string[];
  enabled: boolean;
}

export interface PolicyContext {
  sessionId: string;
  investigationId: string;
  allowedOrigins: string[];
  authorized: boolean;
  activeTests: boolean;
  signal: AbortSignal;
  remainingRequests: number;
  reserveRequest: () => Promise<void>;
  approve: (description: Record<string, unknown>) => Promise<boolean>;
}

export interface PolicyAuditLogEntry {
  timestamp: string;
  investigationId: string;
  toolName: string;
  risk: ToolRiskTier;
  decision: 'ALLOWED' | 'DENIED' | 'APPROVED' | 'REJECTED_BY_OPERATOR' | 'BUDGET_EXHAUSTED' | 'OUT_OF_SCOPE';
  reason?: string;
  target?: string;
}

// Banned internal / cloud metadata targets to prevent SSRF or unauthorized internal scanning
const DISALLOWED_HOST_PATTERNS = [
  /^169\.254\./,              // AWS / GCP / Azure Link-Local Cloud Metadata
  /^100\.64\./,               // Carrier-Grade NAT
  /^0\.0\.0\.0$/,             // Unspecified address
  /\.internal$/,              // Internal cloud DNS suffixes
  /\.local$/,                 // mDNS
];

export class SecurityPolicyGateway {
  private static auditLogs: PolicyAuditLogEntry[] = [];

  /**
   * Validates whether a target URL is strictly within the authorized origin scope.
   */
  public static isTargetInScope(url: string, allowedOrigins: string[]): { allowed: boolean; reason?: string } {
    try {
      const parsed = new URL(url);

      if (!['http:', 'https:'].includes(parsed.protocol)) {
        return { allowed: false, reason: `Disallowed protocol '${parsed.protocol}'. Only http: and https: are permitted.` };
      }

      if (parsed.username || parsed.password) {
        return { allowed: false, reason: 'Credentials in target URLs are strictly prohibited.' };
      }

      // Check against disallowed host patterns (e.g. cloud metadata)
      for (const pattern of DISALLOWED_HOST_PATTERNS) {
        if (pattern.test(parsed.hostname)) {
          return { allowed: false, reason: `Host '${parsed.hostname}' is a reserved internal/metadata address and is prohibited.` };
        }
      }

      const normalizedOrigin = parsed.origin.toLowerCase();
      const isAllowed = allowedOrigins.some((origin) => {
        try {
          return new URL(origin).origin.toLowerCase() === normalizedOrigin;
        } catch {
          return false;
        }
      });

      if (!isAllowed) {
        return { allowed: false, reason: `Origin '${normalizedOrigin}' is not in the project's authorized allowlist: [${allowedOrigins.join(', ')}]` };
      }

      return { allowed: true };
    } catch {
      return { allowed: false, reason: 'Invalid or unparseable target URL.' };
    }
  }

  /**
   * Pre-execution policy check: validates authorization, scope, risk tier, request budget, and approvals.
   */
  public static async authorizeToolExecution(
    tool: ToolSecurityMetadata,
    rawArgs: unknown,
    ctx: PolicyContext,
    targetUrl?: string
  ): Promise<{ authorized: boolean; denialSummary?: string }> {
    ctx.signal.throwIfAborted();

    // 1. Tool enabled check
    if (!tool.enabled) {
      this.log({
        timestamp: new Date().toISOString(),
        investigationId: ctx.investigationId,
        toolName: tool.name,
        risk: tool.risk,
        decision: 'DENIED',
        reason: 'Tool is currently disabled by configuration',
      });
      return { authorized: false, denialSummary: `Tool '${tool.name}' is currently disabled.` };
    }

    // 2. Explicit target authorization check
    if (!ctx.authorized) {
      this.log({
        timestamp: new Date().toISOString(),
        investigationId: ctx.investigationId,
        toolName: tool.name,
        risk: tool.risk,
        decision: 'DENIED',
        reason: 'Explicit target authorization is missing',
      });
      return { authorized: false, denialSummary: 'Explicit target authorization is required.' };
    }

    // 3. Target URL scope validation (if an explicit target URL is involved)
    if (targetUrl) {
      const scopeCheck = this.isTargetInScope(targetUrl, ctx.allowedOrigins);
      if (!scopeCheck.allowed) {
        this.log({
          timestamp: new Date().toISOString(),
          investigationId: ctx.investigationId,
          toolName: tool.name,
          risk: tool.risk,
          decision: 'OUT_OF_SCOPE',
          reason: scopeCheck.reason,
          target: targetUrl,
        });
        return { authorized: false, denialSummary: `Scope policy violation: ${scopeCheck.reason}` };
      }
    }

    // 4. Policy enforcement by risk tier
    switch (tool.risk) {
      case 'READ_ONLY':
      case 'PASSIVE':
        // Read-only and passive inspection tools do not generate active network requests to the target
        this.log({
          timestamp: new Date().toISOString(),
          investigationId: ctx.investigationId,
          toolName: tool.name,
          risk: tool.risk,
          decision: 'ALLOWED',
        });
        return { authorized: true };

      case 'ACTIVE_SAFE':
        // Active non-mutating testing requires operator consent for active testing
        if (!ctx.activeTests) {
          this.log({
            timestamp: new Date().toISOString(),
            investigationId: ctx.investigationId,
            toolName: tool.name,
            risk: tool.risk,
            decision: 'DENIED',
            reason: 'Active testing was not authorized for this investigation',
          });
          return { authorized: false, denialSummary: 'Active tests were not authorized for this investigation.' };
        }
        if (ctx.remainingRequests <= 0) {
          this.log({
            timestamp: new Date().toISOString(),
            investigationId: ctx.investigationId,
            toolName: tool.name,
            risk: tool.risk,
            decision: 'BUDGET_EXHAUSTED',
            reason: 'Investigation request budget exhausted',
          });
          return { authorized: false, denialSummary: 'Investigation request budget exhausted.' };
        }
        this.log({
          timestamp: new Date().toISOString(),
          investigationId: ctx.investigationId,
          toolName: tool.name,
          risk: tool.risk,
          decision: 'ALLOWED',
        });
        return { authorized: true };

      case 'MUTATING_APPROVAL':
        // Mutating/state-changing requests require: active consent + remaining budget + human approval
        if (!ctx.activeTests) {
          this.log({
            timestamp: new Date().toISOString(),
            investigationId: ctx.investigationId,
            toolName: tool.name,
            risk: tool.risk,
            decision: 'DENIED',
            reason: 'Active testing was not authorized for this investigation',
          });
          return { authorized: false, denialSummary: 'Active tests were not authorized for this investigation.' };
        }
        if (ctx.remainingRequests <= 0) {
          this.log({
            timestamp: new Date().toISOString(),
            investigationId: ctx.investigationId,
            toolName: tool.name,
            risk: tool.risk,
            decision: 'BUDGET_EXHAUSTED',
            reason: 'Investigation request budget exhausted',
          });
          return { authorized: false, denialSummary: 'Investigation request budget exhausted.' };
        }

        // Request interactive human approval
        const approved = await ctx.approve({
          tool: tool.name,
          risk: tool.risk,
          args: rawArgs,
          target: targetUrl || 'Authorized target endpoint',
          warning: 'This action is potentially state-changing or intrusive.',
        });

        if (!approved) {
          this.log({
            timestamp: new Date().toISOString(),
            investigationId: ctx.investigationId,
            toolName: tool.name,
            risk: tool.risk,
            decision: 'REJECTED_BY_OPERATOR',
            reason: 'Human operator denied or timed out the approval request',
          });
          return { authorized: false, denialSummary: 'State-changing test was not approved by the operator.' };
        }

        this.log({
          timestamp: new Date().toISOString(),
          investigationId: ctx.investigationId,
          toolName: tool.name,
          risk: tool.risk,
          decision: 'APPROVED',
        });
        return { authorized: true };
    }
  }

  /**
   * Retrieves recorded audit logs for an investigation.
   */
  public static getAuditLogs(investigationId?: string): PolicyAuditLogEntry[] {
    if (investigationId) {
      return this.auditLogs.filter((l) => l.investigationId === investigationId);
    }
    return [...this.auditLogs];
  }

  /**
   * Clears audit logs (primarily for testing).
   */
  public static clearAuditLogs(): void {
    this.auditLogs = [];
  }

  private static log(entry: PolicyAuditLogEntry): void {
    this.auditLogs.push(entry);
    if (this.auditLogs.length > 1000) {
      this.auditLogs.shift();
    }
  }
}

