import { describe, expect, it, vi, beforeEach } from 'vitest';
import { SecurityPolicyGateway, ToolSecurityMetadata, PolicyContext } from './policy.js';
import { ToolRegistry } from '../ai/tools.js';

describe('SecurityPolicyGateway', () => {
  const allowedOrigins = ['http://127.0.0.1:3000', 'https://example.com'];

  beforeEach(() => {
    SecurityPolicyGateway.clearAuditLogs();
  });

  describe('isTargetInScope', () => {
    it('allows URLs strictly within allowed origins', () => {
      expect(SecurityPolicyGateway.isTargetInScope('http://127.0.0.1:3000/rest/user/login', allowedOrigins).allowed).toBe(true);
      expect(SecurityPolicyGateway.isTargetInScope('https://example.com/api/v1', allowedOrigins).allowed).toBe(true);
    });

    it('rejects targets outside allowed origins', () => {
      const res = SecurityPolicyGateway.isTargetInScope('https://malicious.evil.com/test', allowedOrigins);
      expect(res.allowed).toBe(false);
      expect(res.reason).toContain('not in the project\'s authorized allowlist');
    });

    it('rejects non-http/https protocols like file: or javascript:', () => {
      expect(SecurityPolicyGateway.isTargetInScope('file:///etc/passwd', allowedOrigins).allowed).toBe(false);
      expect(SecurityPolicyGateway.isTargetInScope('javascript:alert(1)', allowedOrigins).allowed).toBe(false);
    });

    it('rejects URLs containing embedded credentials', () => {
      const res = SecurityPolicyGateway.isTargetInScope('http://admin:password@127.0.0.1:3000/', allowedOrigins);
      expect(res.allowed).toBe(false);
      expect(res.reason).toContain('Credentials in target URLs are strictly prohibited');
    });

    it('rejects cloud metadata and internal link-local IP addresses (SSRF prevention)', () => {
      const res = SecurityPolicyGateway.isTargetInScope('http://169.254.169.254/latest/meta-data/', allowedOrigins);
      expect(res.allowed).toBe(false);
      expect(res.reason).toContain('reserved internal/metadata address');
    });
  });

  describe('authorizeToolExecution', () => {
    const mockTool: ToolSecurityMetadata = {
      name: 'inspect_http_exchange',
      version: '1.0.0',
      description: 'inspect',
      risk: 'READ_ONLY',
      timeoutMs: 5000,
      requiredPermissions: [],
      enabled: true,
    };

    const makeCtx = (overrides: Partial<PolicyContext> = {}): PolicyContext => ({
      sessionId: 'session-123',
      investigationId: 'inv-456',
      allowedOrigins,
      authorized: true,
      activeTests: false,
      signal: new AbortController().signal,
      remainingRequests: 5,
      reserveRequest: vi.fn(),
      approve: vi.fn().mockResolvedValue(true),
      ...overrides,
    });

    it('denies execution if tool is disabled', async () => {
      const res = await SecurityPolicyGateway.authorizeToolExecution(
        { ...mockTool, enabled: false },
        {},
        makeCtx()
      );
      expect(res.authorized).toBe(false);
      expect(res.denialSummary).toContain('currently disabled');
    });

    it('denies execution if explicit target authorization is missing', async () => {
      const res = await SecurityPolicyGateway.authorizeToolExecution(
        mockTool,
        {},
        makeCtx({ authorized: false })
      );
      expect(res.authorized).toBe(false);
      expect(res.denialSummary).toContain('Explicit target authorization is required');
    });

    it('permits READ_ONLY and PASSIVE tools without active tests or request budget', async () => {
      const readRes = await SecurityPolicyGateway.authorizeToolExecution(
        { ...mockTool, risk: 'READ_ONLY' },
        {},
        makeCtx({ activeTests: false, remainingRequests: 0 })
      );
      expect(readRes.authorized).toBe(true);

      const passiveRes = await SecurityPolicyGateway.authorizeToolExecution(
        { ...mockTool, risk: 'PASSIVE' },
        {},
        makeCtx({ activeTests: false, remainingRequests: 0 })
      );
      expect(passiveRes.authorized).toBe(true);
    });

    it('denies ACTIVE_SAFE tools if active tests are disabled', async () => {
      const res = await SecurityPolicyGateway.authorizeToolExecution(
        { ...mockTool, risk: 'ACTIVE_SAFE' },
        {},
        makeCtx({ activeTests: false })
      );
      expect(res.authorized).toBe(false);
      expect(res.denialSummary).toContain('Active tests were not authorized');
    });

    it('denies ACTIVE_SAFE tools if request budget is exhausted', async () => {
      const res = await SecurityPolicyGateway.authorizeToolExecution(
        { ...mockTool, risk: 'ACTIVE_SAFE' },
        {},
        makeCtx({ activeTests: true, remainingRequests: 0 })
      );
      expect(res.authorized).toBe(false);
      expect(res.denialSummary).toContain('budget exhausted');
    });

    it('triggers human approval for MUTATING_APPROVAL tools and denies if operator rejects', async () => {
      const approveMock = vi.fn().mockResolvedValue(false);
      const res = await SecurityPolicyGateway.authorizeToolExecution(
        { ...mockTool, risk: 'MUTATING_APPROVAL' },
        { action: 'delete' },
        makeCtx({ activeTests: true, remainingRequests: 5, approve: approveMock })
      );
      expect(approveMock).toHaveBeenCalled();
      expect(res.authorized).toBe(false);
      expect(res.denialSummary).toContain('not approved by the operator');
    });

    it('records and returns audit logs', async () => {
      await SecurityPolicyGateway.authorizeToolExecution(mockTool, {}, makeCtx());
      const logs = SecurityPolicyGateway.getAuditLogs('inv-456');
      expect(logs.length).toBeGreaterThan(0);
      expect(logs[0].decision).toBe('ALLOWED');
    });
  });

  describe('ToolRegistry extensions', () => {
    it('lists registered tools with risk tiers and metadata', () => {
      const tools = ToolRegistry.listTools();
      expect(tools.length).toBe(8);
      const zapTool = tools.find((t) => t.name === 'run_zap_passive_analysis');
      expect(zapTool).toBeDefined();
      expect(zapTool?.risk).toBe('PASSIVE');
    });

    it('can disable and re-enable tools dynamically', () => {
      ToolRegistry.setToolEnabled('inspect_console_errors', false);
      expect(ToolRegistry.getMetadata('inspect_console_errors').enabled).toBe(false);
      ToolRegistry.setToolEnabled('inspect_console_errors', true);
      expect(ToolRegistry.getMetadata('inspect_console_errors').enabled).toBe(true);
    });
  });
});

