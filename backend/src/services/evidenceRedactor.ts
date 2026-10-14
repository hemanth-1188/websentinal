/**
 * Evidence Redaction & Normalization Service
 *
 * Ensures that technically verifiable evidence can be collected, persisted,
 * and exported in compliance with strict privacy and security standards
 * without retaining raw session secrets, tokens, credentials, or PII.
 */

export class EvidenceRedactor {
  /**
   * Redacts sensitive cookies, session tokens, passwords, and authorization headers from evidence strings.
   */
  public static redact(text: string): string {
    if (!text || typeof text !== 'string') return '';

    let sanitized = text;

    // 1. Redact Set-Cookie session token values
    // e.g. Set-Cookie: session_token=insecure_token_123456789; Path=/
    sanitized = sanitized.replace(
      /(Set-Cookie:\s*[\w\-\.]+)=([^;,\s]+)/gi,
      (match, cookieKey) => `${cookieKey}=[REDACTED_COOKIE_VALUE]`
    );

    // 2. Redact Authorization Bearer & Basic Tokens
    sanitized = sanitized.replace(
      /(Authorization:\s*(?:Bearer|Basic)\s+)([^\r\n,\s]+)/gi,
      '$1[REDACTED_AUTH_TOKEN]'
    );

    // 3. Redact JWT tokens (header.payload.signature)
    sanitized = sanitized.replace(
      /eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]+/g,
      '[REDACTED_JWT_TOKEN]'
    );

    // 4. Redact Passwords / Secrets in URLs or Config key-values (skip already redacted tokens)
    sanitized = sanitized.replace(
      /((?:password|passwd|secret|api_key|apikey|access_token|private_key|token)[\s=:'"]+)(?!\[REDACTED_)(["']?[^"'\s,;&]+["']?)/gi,
      '$1"[REDACTED_SECRET]"'
    );

    // 5. Redact Database Connection Strings with Passwords
    sanitized = sanitized.replace(
      /(postgres(?:ql)?:\/\/[^:]+:)([^@]+)(@)/gi,
      '$1[REDACTED_DB_PASS]$3'
    );
    sanitized = sanitized.replace(
      /(mysql:\/\/[^:]+:)([^@]+)(@)/gi,
      '$1[REDACTED_DB_PASS]$3'
    );

    // 6. Redact AWS Access Keys
    sanitized = sanitized.replace(
      /AKIA[0-9A-Z]{16}/g,
      '[REDACTED_AWS_ACCESS_KEY]'
    );

    // Bound maximum length to 1500 characters to prevent log injection or database bloat
    if (sanitized.length > 1500) {
      sanitized = sanitized.substring(0, 1500) + '... [TRUNCATED_FOR_SAFETY]';
    }

    return sanitized;
  }
}
