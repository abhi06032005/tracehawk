/**
* Redaction utilities for sensitive data in TraceHawk
* Ensures secrets, tokens, credentials, and PII are redacted before storage or display.
*/

/**
 * Strips PostgreSQL-incompatible null bytes (\0 / 0x00) from a string
 */
export function stripNullBytes(str: string): string;
export function stripNullBytes(str: null | undefined): null;
export function stripNullBytes(str: string | null | undefined): string | null;
export function stripNullBytes(str: string | null | undefined): string | null {
  if (str === null || str === undefined) return null;
  return str.replace(/\0/g, "");
}

/**
 * Recursively strips null bytes from strings, objects, arrays, and JSON structures
 */
export function stripNullBytesDeep<T>(val: T): T {
  if (val === null || val === undefined) return val;
  if (typeof val === "string") return val.replace(/\0/g, "") as unknown as T;
  if (Array.isArray(val)) return val.map(stripNullBytesDeep) as unknown as T;
  if (typeof val === "object") {
    const cleaned: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(val as Record<string, unknown>)) {
      cleaned[k.replace(/\0/g, "")] = stripNullBytesDeep(v);
    }
    return cleaned as unknown as T;
  }
  return val;
}

const SENSITIVE_HEADER_NAMES = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "x-api-key",
  "x-auth-token",
  "x-access-token",
  "x-session-token",
  "api-key",
  "apikey",
  "secret",
  "private-key",
]);

const SENSITIVE_PARAM_NAMES = new Set([
  "token",
  "access_token",
  "auth_token",
  "refresh_token",
  "api_key",
  "apikey",
  "key",
  "secret",
  "client_secret",
  "password",
  "passwd",
  "pwd",
  "session",
  "sessionid",
  "auth",
  "jwt",
]);

const SENSITIVE_JSON_KEYS = new Set([
  "email", "phone", "telephone", "address", "firstname", "lastname", "fullname", "dateofbirth", "dob", "sessionid", "accesstoken", "refreshtoken", "sessiontoken", "idtoken", "id_token",
  "password",
  "password_confirmation",
  "passwd",
  "pwd",
  "secret",
  "client_secret",
  "api_key",
  "apikey",
  "token",
  "access_token",
  "refresh_token",
  "auth_token",
  "session_token",
  "private_key",
  "credit_card",
  "creditcard",
  "card_number",
  "cvv",
  "cvc",
  "ssn",
]);

/**
 * Sanitizes headers object, masking sensitive values while preserving structure
 */
export function sanitizeHeaders(
  headers: Record<string, string | string[] | undefined> | undefined
): Record<string, string | string[]> {
  if (!headers) return {};
  const sanitized: Record<string, string | string[]> = {};

  for (const [key, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    const cleanKey = key.replace(/\0/g, "");
    const lowerKey = cleanKey.toLowerCase();

    if (SENSITIVE_HEADER_NAMES.has(lowerKey)) {
      if (typeof value === "string") {
        sanitized[cleanKey] = maskSensitiveString(value.replace(/\0/g, ""), lowerKey);
      } else if (Array.isArray(value)) {
        sanitized[cleanKey] = value.map((v) => maskSensitiveString(v.replace(/\0/g, ""), lowerKey));
      }
    } else {
      if (typeof value === "string") {
        sanitized[cleanKey] = value.replace(/\0/g, "");
      } else if (Array.isArray(value)) {
        sanitized[cleanKey] = value.map((v) => (typeof v === "string" ? v.replace(/\0/g, "") : v));
      } else {
        sanitized[cleanKey] = value;
      }
    }
  }

  return sanitized;
}

/**
 * Masks a sensitive string based on type
 */
function maskSensitiveString(val: string, type: string): string {
  if (!val) return "";
  const cleanVal = val.replace(/\0/g, "");
  if (
    type.includes("authorization") ||
    type.includes("token") ||
    type.includes("auth") ||
    type.includes("key")
  ) {
    if (cleanVal.startsWith("Bearer ")) {
      return "Bearer [REDACTED_TOKEN]";
    }
    if (cleanVal.startsWith("Basic ")) {
      return "Basic [REDACTED_CREDENTIALS]";
    }
    return "[REDACTED_AUTH]";
  }
  if (type === "cookie" || type === "set-cookie") {
    // Redact cookie values but keep cookie names
    return cleanVal
      .split(";")
      .map((pair) => {
        const idx = pair.indexOf("=");
        if (idx === -1) return pair.trim();
        const k = pair.substring(0, idx).trim();
        const isSensitive =
          SENSITIVE_PARAM_NAMES.has(k.toLowerCase()) ||
          k.toLowerCase().includes("sess") ||
          k.toLowerCase().includes("token") ||
          k.toLowerCase().includes("auth");
        return `${k}=[REDACTED]`;
      })
      .join("; ");
  }
  return "[REDACTED]";
}

/**
 * Sanitizes a URL query string, masking sensitive parameter values
 */
export function sanitizeUrl(rawUrl: string): { sanitizedUrl: string; hasSensitiveParams: boolean } {
  try {
    const cleanRawUrl = (rawUrl || '').replace(/\0/g, "");
    const urlObj = new URL(cleanRawUrl);
    urlObj.username = '';
    urlObj.password = '';
    urlObj.hash = '';
    let hasSensitive = false;

    const params = new URLSearchParams(urlObj.search);
    for (const [key] of Array.from(params.entries())) {
      const cleanKey = key.replace(/\0/g, "");
      if (SENSITIVE_PARAM_NAMES.has(cleanKey.toLowerCase()) || cleanKey.toLowerCase().includes("token")) {
        hasSensitive = true;
        params.set(cleanKey, "[REDACTED]");
      }
    }

    urlObj.search = params.toString();
    return { sanitizedUrl: urlObj.toString(), hasSensitiveParams: hasSensitive };
  } catch {
    return { sanitizedUrl: (rawUrl || '').replace(/\0/g, ""), hasSensitiveParams: false };
  }
}

/**
 * Sanitizes request/response body text (JSON or plain text)
 * Enforces maximum size limits, strips PostgreSQL null bytes, and redacts sensitive fields
 */
export function sanitizeBody(
  body: string | null | undefined,
  contentType?: string,
  maxBytes: number = 256 * 1024
): string | null {
  if (!body) return null;

  // Clean PostgreSQL-incompatible null bytes (0x00) immediately
  const cleanBody = body.includes('\0') ? body.replace(/\0/g, '') : body;

  // Enforce size truncation
  const buffer = Buffer.from(cleanBody);
  const truncated = buffer.length > maxBytes ? buffer.subarray(0, maxBytes).toString("utf-8").replace(/\0/g, '') : cleanBody;
  if (contentType?.includes('application/x-www-form-urlencoded')) {
    const params = new URLSearchParams(truncated);
    for (const key of Array.from(params.keys())) params.set(key, '[REDACTED]');
    return params.toString();
  }
  if (contentType?.includes('multipart/form-data')) return '[MULTIPART_BODY_OMITTED]';

  const isJson =
    contentType?.includes("application/json") ||
    (truncated.trim().startsWith("{") && truncated.trim().endsWith("}")) ||
    (truncated.trim().startsWith("[") && truncated.trim().endsWith("]"));

  if (isJson) {
    try {
      const parsed = JSON.parse(truncated);
      const sanitized = redactJsonObject(parsed);
      return JSON.stringify(sanitized, null, 2);
    } catch {
      // Return as text if parse fails
      return '[INVALID_OR_TRUNCATED_JSON_OMITTED]';
    }
  }

  return truncated
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g, '[REDACTED_TOKEN]')
    .replace(/((?:password|passwd|secret|token|cookie|api[_-]?key)\s*[=:]\s*)[^\s&;,"}]+/gi, '$1[REDACTED]')
    .replace(/\b(?:Bearer|Basic)\s+[^\s"',;]+/gi, '[REDACTED_AUTH]')
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[REDACTED_EMAIL]');
}

/**
 * Recursively redacts sensitive keys from an object and strips null bytes
 */
export function redactJsonObject(obj: unknown): unknown {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj === "string") return obj.replace(/\0/g, "");
  if (typeof obj !== "object") return obj;

  if (Array.isArray(obj)) {
    return obj.map((item) => redactJsonObject(item));
  }

  const result: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
    const cleanKey = k.replace(/\0/g, "");
    const lowerKey = cleanKey.toLowerCase();
    if (SENSITIVE_JSON_KEYS.has(lowerKey)) {
      result[cleanKey] = "[REDACTED]";
    } else if (typeof v === "object" && v !== null) {
      result[cleanKey] = redactJsonObject(v);
    } else if (typeof v === "string") {
      result[cleanKey] = v.replace(/\0/g, "");
    } else {
      result[cleanKey] = v;
    }
  }
  return result;
}

/**
 * Sanitizes storage observation values (e.g. JWT tokens or cookie values)
 */
export function sanitizeStorageValue(key: string, value: string): string {
  if (!value) return "";
  const lowerKey = key.toLowerCase();

  const isSensitive =
    SENSITIVE_PARAM_NAMES.has(lowerKey) ||
    lowerKey.includes("token") ||
    lowerKey.includes("auth") ||
    lowerKey.includes("secret") ||
    lowerKey.includes("jwt") ||
    lowerKey.includes("pass");

  if (isSensitive || /^eyJ[\w-]+\.[\w-]+\.[\w-]*$/.test(value)) {
    // If it looks like a JWT
    if (value.startsWith("eyJ") && value.split(".").length === 3) {
      return '[REDACTED_SIGNATURE]';
    }
    return `[REDACTED_${value.length}_CHARS]`;
  }

  if (/^[\[{]/.test(value.trim())) return sanitizeBody(value, 'application/json', 4096) || '[OMITTED]';

  // Cap value length for safe storage
  return value.length > 500 ? `${value.substring(0, 500)}...[TRUNCATED]` : value;
}
