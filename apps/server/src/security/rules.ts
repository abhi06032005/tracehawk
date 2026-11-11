import { HttpExchange, StorageObservation, BrowserEvent } from "@prisma/client";

export interface FindingDraft {
  title: string;
  category: "HEADERS" | "COOKIES" | "STORAGE" | "INFORMATION_DISCLOSURE" | "CORS" | "ERROR_LEAK" | "AUTH" | "MIXED_CONTENT";
  cweId: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  confidence: "CERTAIN" | "HIGH" | "MEDIUM" | "LOW";
  verificationStatus: "CONFIRMED_CONFIG" | "POTENTIAL_VULNERABILITY" | "INFORMATIONAL";
  description: string;
  evidence: Record<string, unknown>;
  impact: string;
  remediation: string;
}

export type PassiveRule = (
  exchanges: HttpExchange[],
  storage: StorageObservation[],
  events: BrowserEvent[]
) => FindingDraft[];

/**
 * Rule 1: Missing or Ineffective Security Headers
 */
export const checkMissingSecurityHeaders: PassiveRule = (exchanges) => {
  const findings: FindingDraft[] = [];
  const checkedOrigins = new Set<string>();

  // Only check HTML document responses or top-level API responses
  const docExchanges = exchanges.filter(
    (e) =>
      e.statusCode &&
      e.statusCode >= 200 &&
      e.statusCode < 400 &&
      (e.resourceType === "document" ||
        e.contentType?.includes("text/html") ||
        e.contentType?.includes("application/json"))
  );

  for (const ex of docExchanges) {
    let origin: string;
    try {
      origin = new URL(ex.url).origin;
    } catch {
      continue;
    }

    if (checkedOrigins.has(origin)) continue;
    checkedOrigins.add(origin);

    const headers = (ex.responseHeaders as Record<string, string | string[]>) || {};
    const lowerHeaders: Record<string, string> = {};
    for (const [k, v] of Object.entries(headers)) {
      lowerHeaders[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : String(v);
    }

    // 1. Content-Security-Policy
    if (!lowerHeaders["content-security-policy"]) {
      findings.push({
        title: "Missing Content Security Policy (CSP) Header",
        category: "HEADERS",
        cweId: "CWE-693", // Protection Mechanism Failure
        severity: "MEDIUM",
        confidence: "CERTAIN",
        verificationStatus: "CONFIRMED_CONFIG",
        description: `The origin ${origin} does not send a Content-Security-Policy response header on document requests. CSP restricts sources of executable scripts, stylesheets, and frames, reducing the blast radius of Cross-Site Scripting (XSS) and clickjacking.`,
        evidence: {
          httpExchangeId: ex.id,
          url: ex.url,
          method: ex.method,
          statusCode: ex.statusCode,
          missingHeader: "Content-Security-Policy",
        },
        impact: "If an XSS flaw exists anywhere on this origin, attackers can execute arbitrary JavaScript, exfiltrate session data, and perform actions on behalf of the user.",
        remediation: "Deploy a Content-Security-Policy header. Start with a report-only policy (Content-Security-Policy-Report-Only) before enforcing directives like default-src 'self'; script-src 'self'; object-src 'none'.",
      });
    }

    // 2. Strict-Transport-Security (for HTTPS origins)
    if (ex.url.startsWith("https://") && !lowerHeaders["strict-transport-security"]) {
      findings.push({
        title: "Missing HTTP Strict Transport Security (HSTS) Header",
        category: "HEADERS",
        cweId: "CWE-319", // Cleartext Transmission of Sensitive Information
        severity: "MEDIUM",
        confidence: "CERTAIN",
        verificationStatus: "CONFIRMED_CONFIG",
        description: `The HTTPS origin ${origin} does not return a Strict-Transport-Security header. HSTS ensures that browsers only communicate with the origin over encrypted TLS connections, preventing SSL-stripping attacks.`,
        evidence: {
          httpExchangeId: ex.id,
          url: ex.url,
          missingHeader: "Strict-Transport-Security",
        },
        impact: "Network-level adversaries (e.g. on public Wi-Fi) can downgrade HTTPS connections to HTTP and intercept or alter communications.",
        remediation: "Add the Strict-Transport-Security header to all HTTPS responses: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload.",
      });
    }

    // 3. X-Content-Type-Options
    if (lowerHeaders["x-content-type-options"]?.toLowerCase() !== "nosniff") {
      findings.push({
        title: "Missing or Invalid X-Content-Type-Options Header",
        category: "HEADERS",
        cweId: "CWE-706",
        severity: "LOW",
        confidence: "CERTAIN",
        verificationStatus: "CONFIRMED_CONFIG",
        description: `The response from ${origin} lacks 'X-Content-Type-Options: nosniff'. Without this header, legacy browsers may attempt MIME-sniffing, treating user-supplied files as executable JavaScript or HTML.`,
        evidence: {
          httpExchangeId: ex.id,
          url: ex.url,
          currentValue: lowerHeaders["x-content-type-options"] || "None",
        },
        impact: "MIME confusion attacks could allow uploaded images or text files containing HTML/script tags to be interpreted as executable code.",
        remediation: "Configure the web server or reverse proxy to return 'X-Content-Type-Options: nosniff' on all HTTP responses.",
      });
    }

    // 4. X-Frame-Options or CSP frame-ancestors
    const hasFrameOptions = Boolean(lowerHeaders["x-frame-options"]);
    const hasCspFrameAncestors = lowerHeaders["content-security-policy"]?.includes("frame-ancestors");
    if (!hasFrameOptions && !hasCspFrameAncestors) {
      findings.push({
        title: "Missing Anti-Clickjacking Protection (X-Frame-Options)",
        category: "HEADERS",
        cweId: "CWE-1021", // Restriction of Rendered UI Layers or Frames
        severity: "LOW",
        confidence: "CERTAIN",
        verificationStatus: "CONFIRMED_CONFIG",
        description: `Neither X-Frame-Options nor CSP 'frame-ancestors' directive was detected on ${origin}. This permits the application to be embedded in an <iframe> on third-party domains.`,
        evidence: {
          httpExchangeId: ex.id,
          url: ex.url,
        },
        impact: "Malicious websites can embed sensitive pages in transparent iframes to trick users into executing unintentional clicks or submitting sensitive forms.",
        remediation: "Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN', and include 'frame-ancestors self;' in your Content-Security-Policy.",
      });
    }

    // 5. Referrer-Policy
    if (!lowerHeaders["referrer-policy"]) {
      findings.push({
        title: "Missing Referrer-Policy Header",
        category: "HEADERS",
        cweId: "CWE-200",
        severity: "LOW",
        confidence: "HIGH",
        verificationStatus: "CONFIRMED_CONFIG",
        description: `The origin ${origin} does not specify a Referrer-Policy header. Browsers may leak full URL paths and query parameters to third-party domains when users follow links or load cross-origin assets.`,
        evidence: {
          httpExchangeId: ex.id,
          url: ex.url,
        },
        impact: "URL parameters containing session tokens, reset tokens, or confidential identifiers may be exposed in the HTTP Referer header to external servers.",
        remediation: "Add 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
      });
    }
  }

  return findings;
};

/**
 * Rule 2: Insecure Cookie Configurations
 */
export const checkInsecureCookies: PassiveRule = (_, storage) => {
  const findings: FindingDraft[] = [];
  const cookies = storage.filter((s) => s.storageType === "COOKIE");

  for (const c of cookies) {
    const meta = (c.sanitizedValue ? {} : {}) as any;
    // Inspect key name for session-like characteristics
    const lowerKey = c.key.toLowerCase();
    const isSessionCookie =
      lowerKey.includes("sess") ||
      lowerKey.includes("token") ||
      lowerKey.includes("auth") ||
      lowerKey.includes("jwt") ||
      lowerKey.includes("id");

    // In a storage observation, we can verify key names and origins
    if (isSessionCookie && c.origin.startsWith("https://")) {
      findings.push({
        title: `Sensitive Session Cookie Detected: '${c.key}'`,
        category: "COOKIES",
        cweId: "CWE-614", // Sensitive Cookie Without 'Secure' or 'HttpOnly'
        severity: "MEDIUM",
        confidence: "HIGH",
        verificationStatus: "POTENTIAL_VULNERABILITY",
        description: `The application stores authentication/session state in cookie '${c.key}'. Session cookies must enforce HttpOnly (to prevent JavaScript theft via XSS), Secure (to prevent cleartext transmission), and SameSite=Lax/Strict (to protect against CSRF).`,
        evidence: {
          cookieName: c.key,
          origin: c.origin,
          sanitizedValue: c.sanitizedValue,
          storageObservationId: c.id,
        },
        impact: "If HttpOnly is omitted, an XSS vulnerability allows instant session hijacking. If Secure is omitted, network sniffers can capture the cookie. If SameSite is missing or None, the cookie is vulnerable to CSRF.",
        remediation: "Configure the server session manager to set HttpOnly; Secure; SameSite=Lax (or Strict) on all session cookies.",
      });
    }
  }

  return findings;
};

/**
 * Rule 3: Exposed Tokens / Credentials in Browser Storage
 */
export const checkExposedTokensInStorage: PassiveRule = (_, storage) => {
  const findings: FindingDraft[] = [];
  const webStorage = storage.filter(
    (s) => s.storageType === "LOCAL_STORAGE" || s.storageType === "SESSION_STORAGE"
  );

  for (const item of webStorage) {
    const lowerKey = item.key.toLowerCase();
    const isSensitiveKey =
      lowerKey.includes("token") ||
      lowerKey.includes("auth") ||
      lowerKey.includes("jwt") ||
      lowerKey.includes("secret") ||
      lowerKey.includes("password");

    const looksLikeJwt =
      typeof item.sanitizedValue === "string" &&
      (item.sanitizedValue.includes("eyJ") || item.sanitizedValue.includes("REDACTED"));

    if (isSensitiveKey || looksLikeJwt) {
      findings.push({
        title: `Authentication Token / Credential Stored in ${item.storageType}`,
        category: "STORAGE",
        cweId: "CWE-922", // Insecure Storage of Sensitive Information
        severity: "MEDIUM",
        confidence: "HIGH",
        verificationStatus: "POTENTIAL_VULNERABILITY",
        description: `Sensitive credential or session token '${item.key}' was found stored in HTML5 ${item.storageType}. Unlike HttpOnly cookies, Web Storage is accessible to any JavaScript running in the origin's context.`,
        evidence: {
          storageObservationId: item.id,
          storageType: item.storageType,
          key: item.key,
          origin: item.origin,
          sanitizedValue: item.sanitizedValue,
        },
        impact: "Any Cross-Site Scripting (XSS) vulnerability or compromised third-party script can read the stored token directly via window.localStorage or window.sessionStorage and hijack the user session.",
        remediation: "Store sensitive session credentials in HttpOnly, Secure, SameSite cookies rather than localStorage or sessionStorage whenever feasible.",
      });
    }
  }

  return findings;
};

/**
 * Rule 4: Sensitive Data in URL Query Strings
 */
export const checkSensitiveDataInUrlQuery: PassiveRule = (exchanges) => {
  const findings: FindingDraft[] = [];
  const sensitiveParamNames = [
    "token",
    "access_token",
    "api_key",
    "apikey",
    "password",
    "secret",
    "auth",
  ];

  for (const ex of exchanges) {
    try {
      const parsed = new URL(ex.url);
      const params = parsed.searchParams;
      const matchedParams: string[] = [];

      for (const p of sensitiveParamNames) {
        if (params.has(p)) {
          matchedParams.push(p);
        }
      }

      if (matchedParams.length > 0) {
        findings.push({
          title: `Sensitive Parameters in URL Query: [${matchedParams.join(", ")}]`,
          category: "INFORMATION_DISCLOSURE",
          cweId: "CWE-598", // Information Exposure Through Query Strings in GET Request
          severity: "MEDIUM",
          confidence: "CERTAIN",
          verificationStatus: "CONFIRMED_CONFIG",
          description: `The request to '${parsed.pathname}' contains sensitive credentials (${matchedParams.join(
            ", "
          )}) directly in the URL query string. Query parameters are stored in plaintext in browser history, proxy logs, server access logs, and leaked via the Referer header.`,
          evidence: {
            httpExchangeId: ex.id,
            url: ex.url,
            method: ex.method,
            sensitiveParameters: matchedParams,
          },
          impact: "Credentials can be harvested from server logs, proxy inspection tools, browser history, or external sites via the Referer header.",
          remediation: "Transmit credentials and session tokens inside standard HTTP Authorization headers or POST request bodies rather than GET query parameters.",
        });
      }
    } catch {
      // Ignore URL parsing errors
    }
  }

  return findings;
};

/**
 * Rule 5: Permissive CORS Configuration
 */
export const checkPermissiveCors: PassiveRule = (exchanges) => {
  const findings: FindingDraft[] = [];

  for (const ex of exchanges) {
    const headers = (ex.responseHeaders as Record<string, string | string[]>) || {};
    const lowerHeaders: Record<string, string> = {};
    for (const [k, v] of Object.entries(headers)) {
      lowerHeaders[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : String(v);
    }

    const acao = lowerHeaders["access-control-allow-origin"];
    const acac = lowerHeaders["access-control-allow-credentials"];

    if (acao === "*" && (ex.resourceType === "fetch" || ex.resourceType === "xhr")) {
      // Wildcard on API endpoint
      findings.push({
        title: "Permissive Wildcard Access-Control-Allow-Origin on API Endpoint",
        category: "CORS",
        cweId: "CWE-942", // Permissive Cross-Domain Policy with Untrusted Domains
        severity: "LOW",
        confidence: "CERTAIN",
        verificationStatus: "INFORMATIONAL",
        description: `The endpoint '${ex.url}' returns 'Access-Control-Allow-Origin: *'. While acceptable for public unauthenticated content, wildcards on private or internal API endpoints allow any website to read response data.`,
        evidence: {
          httpExchangeId: ex.id,
          url: ex.url,
          method: ex.method,
          accessControlAllowOrigin: acao,
        },
        impact: "Third-party domains can perform cross-origin XMLHttpRequests to this endpoint and access its response body.",
        remediation: "Restrict Access-Control-Allow-Origin to trusted application domains only.",
      });
    }

    if (acac === "true" && acao && acao.includes("*")) {
      findings.push({
        title: "Insecure CORS Policy: Credentials Allowed with Wildcard Origin",
        category: "CORS",
        cweId: "CWE-942",
        severity: "HIGH",
        confidence: "CERTAIN",
        verificationStatus: "CONFIRMED_CONFIG",
        description: `The response from '${ex.url}' enables credentials ('Access-Control-Allow-Credentials: true') while allowing wildcard origins.`,
        evidence: {
          httpExchangeId: ex.id,
          url: ex.url,
          accessControlAllowOrigin: acao,
          accessControlAllowCredentials: acac,
        },
        impact: "Malicious third-party sites can issue authenticated requests with the victim's cookies and read the response.",
        remediation: "Never allow arbitrary or wildcard origins when Access-Control-Allow-Credentials is true. Validate origins against a strict whitelist.",
      });
    }
  }

  return findings;
};

/**
 * Rule 6: Verbose Error Messages and Stack Traces
 */
export const checkVerboseErrorsAndStackTraces: PassiveRule = (exchanges) => {
  const findings: FindingDraft[] = [];
  const stackTraceKeywords = [
    "at Module._compile",
    "at Generator.next",
    "SequelizeDatabaseError",
    "MongoServerError",
    "SQLSTATE",
    "Traceback (most recent call last)",
    "NullPointerException",
    "Fatal error:",
    "stack trace:",
    "node_modules",
  ];

  for (const ex of exchanges) {
    if (ex.statusCode && ex.statusCode >= 500 && ex.sanitizedResponseBody) {
      const body = ex.sanitizedResponseBody;
      const matched = stackTraceKeywords.filter((kw) => body.includes(kw));

      if (matched.length > 0) {
        findings.push({
          title: `Verbose Server Error / Stack Trace Disclosed (${ex.statusCode})`,
          category: "ERROR_LEAK",
          cweId: "CWE-209", // Generation of Error Message Containing Sensitive Information
          severity: "HIGH",
          confidence: "CERTAIN",
          verificationStatus: "CONFIRMED_CONFIG",
          description: `The server returned an HTTP ${ex.statusCode} error containing internal technical details and stack traces (${matched.join(
            ", "
          )}). Detailed error messages reveal internal directory structures, library versions, database technologies, and source code lines.`,
          evidence: {
            httpExchangeId: ex.id,
            url: ex.url,
            statusCode: ex.statusCode,
            matchedSignatures: matched,
            snippet: body.substring(0, 300),
          },
          impact: "Attackers can map backend filepaths, database queries, and vulnerable library versions to craft targeted exploits.",
          remediation: "Disable verbose error reporting in production. Implement centralized exception handlers that log details internally and return generic error messages to clients.",
        });
      }
    }
  }

  return findings;
};

/**
 * Rule 7: Server and Framework Version Disclosure Headers
 */
export const checkVersionDisclosureHeaders: PassiveRule = (exchanges) => {
  const findings: FindingDraft[] = [];
  const disclosureHeaders = ["server", "x-powered-by", "x-aspnet-version", "x-generator"];
  const checkedOrigins = new Set<string>();

  for (const ex of exchanges) {
    let origin: string;
    try {
      origin = new URL(ex.url).origin;
    } catch {
      continue;
    }

    if (checkedOrigins.has(origin)) continue;

    const headers = (ex.responseHeaders as Record<string, string | string[]>) || {};
    const lowerHeaders: Record<string, string> = {};
    for (const [k, v] of Object.entries(headers)) {
      lowerHeaders[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : String(v);
    }

    for (const headerName of disclosureHeaders) {
      const val = lowerHeaders[headerName];
      // Check if header contains version numbers or technology disclosures
      if (val && (/\d+\.\d+/.test(val) || val.toLowerCase().includes("express") || val.toLowerCase().includes("apache") || val.toLowerCase().includes("nginx"))) {
        checkedOrigins.add(origin);
        findings.push({
          title: `Technology & Version Disclosure via '${headerName}' Header`,
          category: "INFORMATION_DISCLOSURE",
          cweId: "CWE-200", // Exposure of Sensitive Information to an Unauthorized Actor
          severity: "LOW",
          confidence: "CERTAIN",
          verificationStatus: "CONFIRMED_CONFIG",
          description: `The server discloses its underlying software and version in the '${headerName}' header: '${val}'. Fingerprinting exact server versions assists attackers in identifying publicly known CVEs.`,
          evidence: {
            httpExchangeId: ex.id,
            url: ex.url,
            header: headerName,
            value: val,
          },
          impact: "Attackers can look up known vulnerabilities matching the exact software version disclosed by the server.",
          remediation: `Configure your web server or Express application to remove the '${headerName}' header (e.g. app.disable('x-powered-by') or server_tokens off in Nginx).`,
        });
      }
    }
  }

  return findings;
};

/**
 * Rule 8: Mixed Content Issues
 */
export const checkMixedContent: PassiveRule = (exchanges) => {
  const findings: FindingDraft[] = [];

  for (const ex of exchanges) {
    if (ex.pageUrl && ex.pageUrl.startsWith("https://") && ex.url.startsWith("http://")) {
      findings.push({
        title: `Mixed Content: Insecure HTTP Asset on HTTPS Page`,
        category: "MIXED_CONTENT",
        cweId: "CWE-311", // Missing Encryption of Sensitive Data
        severity: "MEDIUM",
        confidence: "CERTAIN",
        verificationStatus: "CONFIRMED_CONFIG",
        description: `The HTTPS page '${ex.pageUrl}' loaded an unencrypted subresource over HTTP: '${ex.url}'. Mixed content weakens HTTPS protections by allowing network adversaries to intercept or tamper with the resource.`,
        evidence: {
          httpExchangeId: ex.id,
          pageUrl: ex.pageUrl,
          insecureResourceUrl: ex.url,
          resourceType: ex.resourceType,
        },
        impact: "Active network attackers can perform man-in-the-middle attacks to modify unencrypted scripts, stylesheets, or data loaded on a secure page.",
        remediation: "Ensure all subresources (scripts, stylesheets, APIs, images) are loaded using relative paths or explicit https:// protocols.",
      });
    }
  }

  return findings;
};

/**
 * Rule 9: Repeated Server Errors (Potential Stability / DoS Anomalies)
 */
export const checkRepeatedServerErrors: PassiveRule = (exchanges) => {
  const findings: FindingDraft[] = [];
  const errorsByEndpoint = new Map<string, HttpExchange[]>();

  for (const ex of exchanges) {
    if (ex.statusCode && ex.statusCode >= 500) {
      try {
        const parsed = new URL(ex.url);
        const key = `${ex.method} ${parsed.pathname}`;
        const list = errorsByEndpoint.get(key) || [];
        list.push(ex);
        errorsByEndpoint.set(key, list);
      } catch {}
    }
  }

  for (const [endpoint, errorList] of errorsByEndpoint.entries()) {
    if (errorList.length >= 3) {
      findings.push({
        title: `Repeated Server Errors (5xx) on Endpoint: ${endpoint}`,
        category: "ERROR_LEAK",
        cweId: "CWE-754", // Improper Check for Unusual or Exceptional Conditions
        severity: "LOW",
        confidence: "HIGH",
        verificationStatus: "POTENTIAL_VULNERABILITY",
        description: `The endpoint '${endpoint}' triggered ${errorList.length} internal server errors during normal navigation and testing. Repeated 5xx errors often indicate unhandled edge cases, input validation gaps, or potential denial of service conditions.`,
        evidence: {
          endpoint,
          errorCount: errorList.length,
          exchangeIds: errorList.map((e) => e.id),
          sampleStatus: errorList[0].statusCode,
        },
        impact: "Uncaught exceptions can lead to server crashes, database connection pool exhaustion, or service downtime.",
        remediation: "Implement strict input validation and robust error handling for this route. Check server logs to fix the root cause of the unhandled exception.",
      });
    }
  }

  return findings;
};

export const ALL_PASSIVE_RULES: PassiveRule[] = [
  checkMissingSecurityHeaders,
  checkInsecureCookies,
  checkExposedTokensInStorage,
  checkSensitiveDataInUrlQuery,
  checkPermissiveCors,
  checkVerboseErrorsAndStackTraces,
  checkVersionDisclosureHeaders,
  checkMixedContent,
  checkRepeatedServerErrors,
];
