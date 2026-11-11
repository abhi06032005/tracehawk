import { describe, it, expect } from "vitest";
import {
  checkMissingSecurityHeaders,
  checkInsecureCookies,
  checkExposedTokensInStorage,
  checkSensitiveDataInUrlQuery,
  checkPermissiveCors,
  checkVerboseErrorsAndStackTraces,
  checkVersionDisclosureHeaders,
  checkMixedContent,
  checkRepeatedServerErrors,
} from "./rules.js";
import { HttpExchange, StorageObservation, BrowserEvent } from "@prisma/client";

function mockExchange(partial: Partial<HttpExchange>): HttpExchange {
  return {
    id: "ex-1",
    sessionId: "sess-1",
    timestamp: new Date(),
    method: "GET",
    url: "https://example.com/dashboard",
    statusCode: 200,
    requestHeaders: {},
    responseHeaders: {},
    sanitizedRequestBody: null,
    sanitizedResponseBody: null,
    contentType: "text/html",
    duration: 45,
    resourceType: "document",
    failureReason: null,
    pageUrl: "https://example.com/dashboard",
    ...partial,
  };
}

describe("Passive Security Rules", () => {
  it("should detect missing security headers (CSP, HSTS, X-Content-Type-Options, Frame-Options)", () => {
    const exchange = mockExchange({
      url: "https://app.local/",
      responseHeaders: {},
    });

    const findings = checkMissingSecurityHeaders([exchange], [], []);
    const titles = findings.map((f) => f.title);

    expect(titles).toContain("Missing Content Security Policy (CSP) Header");
    expect(titles).toContain("Missing HTTP Strict Transport Security (HSTS) Header");
    expect(titles).toContain("Missing or Invalid X-Content-Type-Options Header");
    expect(titles).toContain("Missing Anti-Clickjacking Protection (X-Frame-Options)");
  });

  it("should NOT create findings when headers are securely configured", () => {
    const exchange = mockExchange({
      url: "https://secure.local/",
      responseHeaders: {
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "strict-origin-when-cross-origin",
      },
    });

    const findings = checkMissingSecurityHeaders([exchange], [], []);
    expect(findings.length).toBe(0);
  });

  it("should detect sensitive session cookies stored in insecure contexts", () => {
    const storage: StorageObservation = {
      id: "st-1",
      sessionId: "sess-1",
      origin: "https://example.com",
      storageType: "COOKIE",
      key: "session_token",
      sanitizedValue: "[REDACTED]",
      timestamp: new Date(),
    };

    const findings = checkInsecureCookies([], [storage], []);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].category).toBe("COOKIES");
    expect(findings[0].cweId).toBe("CWE-614");
  });

  it("should flag authentication tokens stored in localStorage or sessionStorage", () => {
    const storage: StorageObservation = {
      id: "st-2",
      sessionId: "sess-1",
      origin: "https://example.com",
      storageType: "LOCAL_STORAGE",
      key: "authToken",
      sanitizedValue: "eyJhbGciOiJIUzI1NiJ9...[REDACTED_SIGNATURE]",
      timestamp: new Date(),
    };

    const findings = checkExposedTokensInStorage([], [storage], []);
    expect(findings.length).toBe(1);
    expect(findings[0].title).toContain("Authentication Token / Credential Stored in LOCAL_STORAGE");
    expect(findings[0].cweId).toBe("CWE-922");
  });

  it("should detect sensitive parameters exposed in URL query strings", () => {
    const exchange = mockExchange({
      url: "https://example.com/api/user?token=xyz123&api_key=key999",
    });

    const findings = checkSensitiveDataInUrlQuery([exchange], [], []);
    expect(findings.length).toBe(1);
    expect(findings[0].cweId).toBe("CWE-598");
    expect(findings[0].evidence.sensitiveParameters).toEqual(["token", "api_key"]);
  });

  it("should flag permissive CORS with credentials or wildcards", () => {
    const exchange = mockExchange({
      url: "https://example.com/api/data",
      resourceType: "fetch",
      responseHeaders: {
        "access-control-allow-origin": "*",
        "access-control-allow-credentials": "true",
      },
    });

    const findings = checkPermissiveCors([exchange], [], []);
    expect(findings.some((f) => f.severity === "HIGH")).toBe(true);
  });

  it("should detect verbose error messages and stack traces in 500 responses", () => {
    const exchange = mockExchange({
      statusCode: 500,
      sanitizedResponseBody: "Internal Error: SequelizeDatabaseError: relation 'users' does not exist at /app/node_modules/sequelize/lib/dialects/postgres/query.js:73:25",
    });

    const findings = checkVerboseErrorsAndStackTraces([exchange], [], []);
    expect(findings.length).toBe(1);
    expect(findings[0].cweId).toBe("CWE-209");
    expect(findings[0].severity).toBe("HIGH");
  });

  it("should identify framework and server version disclosure headers", () => {
    const exchange = mockExchange({
      responseHeaders: {
        Server: "Apache/2.4.41 (Ubuntu)",
        "X-Powered-By": "Express",
      },
    });

    const findings = checkVersionDisclosureHeaders([exchange], [], []);
    expect(findings.length).toBe(2);
    expect(findings.map((f) => f.evidence.header)).toContain("server");
    expect(findings.map((f) => f.evidence.header)).toContain("x-powered-by");
  });

  it("should detect mixed content HTTP resources on HTTPS pages", () => {
    const exchange = mockExchange({
      pageUrl: "https://secure.example.com/account",
      url: "http://insecure.example.com/avatar.jpg",
      resourceType: "image",
    });

    const findings = checkMixedContent([exchange], [], []);
    expect(findings.length).toBe(1);
    expect(findings[0].category).toBe("MIXED_CONTENT");
    expect(findings[0].cweId).toBe("CWE-311");
  });

  it("should flag repeated 5xx errors on the same route", () => {
    const exchanges = [
      mockExchange({ url: "https://example.com/api/checkout", statusCode: 500 }),
      mockExchange({ url: "https://example.com/api/checkout", statusCode: 502 }),
      mockExchange({ url: "https://example.com/api/checkout", statusCode: 503 }),
    ];

    const findings = checkRepeatedServerErrors(exchanges, [], []);
    expect(findings.length).toBe(1);
    expect(findings[0].title).toContain("Repeated Server Errors (5xx)");
  });
});
