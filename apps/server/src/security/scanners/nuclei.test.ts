import { describe, expect, it, vi } from 'vitest';
import { NucleiScannerAdapter } from './nuclei.js';

describe('NucleiScannerAdapter', () => {
  const allowedOrigins = ['http://127.0.0.1:3000'];

  it('rejects targets that violate SecurityPolicyGateway scope', async () => {
    await expect(
      NucleiScannerAdapter.scan('https://unauthorized-evil.com', {
        allowedOrigins,
      })
    ).rejects.toThrow(/policy gateway/);
  });

  it('handles missing binary gracefully without crashing', async () => {
    const res = await NucleiScannerAdapter.scan('http://127.0.0.1:3000', {
      allowedOrigins,
      timeoutMs: 2000,
    });

    expect(res.target).toBe('http://127.0.0.1:3000');
    if (!res.available) {
      expect(res.error).toMatch(/not installed/);
    }
  });
});

