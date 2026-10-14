import { ScanContext } from '../core/ScanContext';
import { EvidenceRedactor } from '../../services/evidenceRedactor';

export class CookieScanner {
  public async scan(context: ScanContext): Promise<void> {
    const rawSetCookie = context.rawHeaders['set-cookie'];
    if (!rawSetCookie) return;

    context.totalChecksExecuted += 3;

    // Split multiple cookies safely
    const cookieStrings = rawSetCookie.split(/,\s*(?=[a-zA-Z0-9_\-\.]+=)/);

    for (const cookieStr of cookieStrings) {
      const parts = cookieStr.split(';').map(p => p.trim());
      const nameValue = parts[0] || '';
      const cookieName = nameValue.split('=')[0];

      // Identify if this looks like a session or auth token cookie
      const isLikelySession = /(session|sess|token|jwt|auth|sid|id|login)/i.test(cookieName);

      const hasHttpOnly = parts.some(p => p.toLowerCase() === 'httponly');
      const hasSecure = parts.some(p => p.toLowerCase() === 'secure');
      const sameSitePart = parts.find(p => p.toLowerCase().startsWith('samesite='));
      const sameSiteValue = sameSitePart ? sameSitePart.split('=')[1]?.toLowerCase() : null;

      // Sanitized evidence without exposing the actual session token value
      const sanitizedEvidence = EvidenceRedactor.redact(`Set-Cookie: ${cookieStr}`);

      // 1. Missing HttpOnly
      // Mapped to A07:2025 (Authentication Failures / Session Management)
      if (!hasHttpOnly) {
        context.addFinding({
          rule_id: 'SEC-CK-HTTPONLY-MISSING',
          title: `Cookie Missing HttpOnly Attribute: "${cookieName}"`,
          description: `The cookie "${cookieName}" was issued without the HttpOnly flag, permitting client-side scripts to read its value via document.cookie.`,
          severity: isLikelySession ? 'MEDIUM' : 'LOW',
          confidence: 'HIGH',
          status: 'CONFIRMED',
          check_status: 'FINDING',
          owasp_category: 'A07',
          owasp_version: '2025',
          cwe: 'CWE-1004',
          affected_url: context.targetUrl,
          evidence: sanitizedEvidence,
          impact: isLikelySession
            ? 'Critical session tokens can be exfiltrated by injected JavaScript if an XSS flaw exists.'
            : 'Non-sensitive client state is readable by scripts running on the page.',
          remediation: 'Append "; HttpOnly" to the Set-Cookie response header when creating cookies.',
          references: 'https://owasp.org/www-project-top-ten/2025/A07_Authentication_Failures/',
        });
      }

      // 2. Missing Secure Flag on HTTPS
      // Mapped to A04:2025 (Cryptographic Failures)
      if (context.isHttps && !hasSecure) {
        context.addFinding({
          rule_id: 'SEC-CK-SECURE-MISSING',
          title: `Cookie Missing Secure Flag over HTTPS: "${cookieName}"`,
          description: `The cookie "${cookieName}" was sent over an encrypted channel but lacks the Secure directive.`,
          severity: isLikelySession ? 'MEDIUM' : 'LOW',
          confidence: 'HIGH',
          status: 'CONFIRMED',
          check_status: 'FINDING',
          owasp_category: 'A04',
          owasp_version: '2025',
          cwe: 'CWE-614',
          affected_url: context.targetUrl,
          evidence: sanitizedEvidence,
          impact: 'Browsers may transmit this cookie over unencrypted HTTP requests if a user clicks an unencrypted link.',
          remediation: 'Append "; Secure" to the Set-Cookie response header.',
          references: 'https://owasp.org/www-project-top-ten/2025/A04_Cryptographic_Failures/',
        });
      }

      // 3. Missing or Permissive SameSite Flag
      // Mapped to A02:2025 (Security Misconfiguration)
      if (!sameSiteValue || sameSiteValue === 'none') {
        context.addFinding({
          rule_id: 'SEC-CK-SAMESITE-MISSING',
          title: `Cookie Missing or Permissive SameSite: "${cookieName}"`,
          description: `The cookie "${cookieName}" does not specify SameSite=Lax or SameSite=Strict protection.`,
          severity: isLikelySession ? 'MEDIUM' : 'LOW',
          confidence: 'HIGH',
          status: 'CONFIRMED',
          check_status: 'FINDING',
          owasp_category: 'A02',
          owasp_version: '2025',
          cwe: 'CWE-1275',
          affected_url: context.targetUrl,
          evidence: sanitizedEvidence,
          impact: 'Increases susceptibility to Cross-Site Request Forgery (CSRF) on authenticated endpoints.',
          remediation: 'Configure SameSite=Lax (default for modern flows) or SameSite=Strict.',
          references: 'https://owasp.org/www-project-top-ten/2025/A02_Security_Misconfiguration/',
        });
      }
    }
  }
}
