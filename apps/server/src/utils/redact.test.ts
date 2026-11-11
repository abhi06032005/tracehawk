import { describe, it, expect } from "vitest";
import {
  sanitizeHeaders,
  sanitizeUrl,
  sanitizeBody,
  sanitizeStorageValue,
  redactJsonObject,
  stripNullBytes,
  stripNullBytesDeep,
} from "./redact.js";

describe("Redaction Utilities", () => {
  it("should redact Bearer and Basic authorization headers", () => {
    const headers = {
      Authorization: "Bearer secret-jwt-token-xyz-123456",
      "Proxy-Authorization": "Basic dXNlcjpwYXNzd29yZA==",
      Accept: "application/json",
      "X-Api-Key": "my-secret-api-key",
    };

    const sanitized = sanitizeHeaders(headers);

    expect(sanitized["Authorization"]).toBe("Bearer [REDACTED_TOKEN]");
    expect(sanitized["Proxy-Authorization"]).toBe("Basic [REDACTED_CREDENTIALS]");
    expect(sanitized["X-Api-Key"]).toBe("[REDACTED_AUTH]");
    expect(sanitized["Accept"]).toBe("application/json");
  });

  it("should mask sensitive cookie values while preserving names", () => {
    const headers = {
      Cookie: "sessionid=1234567890abcdef; token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9; theme=dark",
    };

    const sanitized = sanitizeHeaders(headers);
    const cookieHeader = sanitized["Cookie"] as string;

    expect(cookieHeader).toContain("sessionid=[REDACTED]");
    expect(cookieHeader).toContain("token=[REDACTED]");
    expect(cookieHeader).toContain("theme=");
  });

  it("should sanitize query parameters in URLs", () => {
    const rawUrl = "https://app.local/api/search?q=test&token=secret123&api_key=key456&page=2";
    const { sanitizedUrl, hasSensitiveParams } = sanitizeUrl(rawUrl);

    expect(hasSensitiveParams).toBe(true);
    expect(sanitizedUrl).toContain("token=%5BREDACTED%5D");
    expect(sanitizedUrl).toContain("api_key=%5BREDACTED%5D");
    expect(sanitizedUrl).toContain("q=test");
    expect(sanitizedUrl).toContain("page=2");
    expect(sanitizedUrl).not.toContain("secret123");
  });

  it("should recursively redact sensitive JSON body fields", () => {
    const payload = {
      user: {
        username: "testuser",
        password: "SuperSecretPassword!123",
        nested: {
          creditCard: "4111111111111111",
          apiKey: "sk-live-12345",
        },
      },
      status: "active",
    };

    const redacted = redactJsonObject(payload) as any;

    expect(redacted.user.username).toBe("testuser");
    expect(redacted.user.password).toBe("[REDACTED]");
    expect(redacted.user.nested.creditCard).toBe("[REDACTED]");
    expect(redacted.user.nested.apiKey).toBe("[REDACTED]");
    expect(redacted.status).toBe("active");
  });

  it("should redact sensitive storage values such as JWTs and passwords", () => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozG4B_T_D3_signature";
    const maskedJwt = sanitizeStorageValue("token", jwt);
    expect(maskedJwt).toContain("[REDACTED_SIGNATURE]");

    const maskedPwd = sanitizeStorageValue("password", "plaintextSecret");
    expect(maskedPwd).toBe("[REDACTED_15_CHARS]");

    const safeTheme = sanitizeStorageValue("theme", "midnight-dark");
    expect(safeTheme).toBe("midnight-dark");
  });

  it("should enforce maximum size limits on body strings", () => {
    const bigString = "A".repeat(300 * 1024);
    const sanitized = sanitizeBody(bigString, "text/plain", 10 * 1024);
    expect(sanitized).not.toBeNull();
    expect(sanitized!.length).toBeLessThanOrEqual(10 * 1024);
  });

  it("should strip PostgreSQL-incompatible null bytes (0x00) from strings and deep objects", () => {
    const rawString = "Hello\0World\u0000!";
    expect(stripNullBytes(rawString)).toBe("HelloWorld!");
    expect(stripNullBytes(null)).toBeNull();
    expect(stripNullBytes(undefined)).toBeNull();

    const nestedObj = {
      "key\0": "val\0ue",
      arr: ["item\0_1", "item_2"],
      num: 42,
    };
    const cleaned = stripNullBytesDeep(nestedObj);
    expect(cleaned).toEqual({
      key: "value",
      arr: ["item_1", "item_2"],
      num: 42,
    });
  });

  it("should strip null bytes in sanitizeBody, sanitizeHeaders, and sanitizeUrl", () => {
    const bodyWithNull = "{\"data\": \"test\\u0000payload\"}";
    const sanitizedBody = sanitizeBody(bodyWithNull, "application/json");
    expect(sanitizedBody).not.toContain("\0");

    const headersWithNull = {
      "X-Custom\0": "val\0ue",
      Authorization: "Bearer token\0secret",
    };
    const sanitizedHeaders = sanitizeHeaders(headersWithNull);
    expect(sanitizedHeaders["X-Custom"]).toBe("value");
    expect(sanitizedHeaders["Authorization"]).toBe("Bearer [REDACTED_TOKEN]");

    const { sanitizedUrl } = sanitizeUrl("https://example.com/api\0/users?q=test\0");
    expect(sanitizedUrl).not.toContain("\0");
  });
});
