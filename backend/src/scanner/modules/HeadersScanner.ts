import { ScanContext } from '../core/ScanContext';
import { EvidenceRedactor } from '../../services/evidenceRedactor';

export class HeadersScanner {
  public async scan(context: ScanContext): Promise<void> {
    const headers = context.rawHeaders;
    const targetUrl = context.targetUrl;

    context.totalChecksExecuted += 7;

    // 1. Content-Security-Policy (CSP)
    const csp = headers['content-security-policy'];
    if (!csp) {
      context.addFinding({
        rule_id: 'SEC-HDR-CSP-MISSING',
        title: 'Missing Content-Security-Policy (CSP) Header',
        description: 'Content-Security-Policy restricts resource loading origins, mitigating Cross-Site Scripting (XSS), clickjacking, and data injection vectors.',
        severity: 'HIGH',
        confidence: 'HIGH',
        status: 'CONFIRMED',
        check_status: 'FINDING',
        owasp_category: 'A02',
        owasp_version: '2025',
        cwe: 'CWE-693',
        affected_url: targetUrl,
        evidence: 'Response headers inspected; "content-security-policy" header was absent.',
        impact: 'Without CSP, client browsers lack defense-in-depth restrictions against malicious script execution and unauthorized framing.',
        remediation: 'Implement a Content-Security-Policy header, for example: default-src \'self\'; script-src \'self\'; object-src \'none\'; base-uri \'self\';',
        references: 'https://owasp.org/www-project-top-ten/2025/A02_Security_Misconfiguration/',
      });
    } else {
      // Check for weak CSP directives
      const lowerCsp = csp.toLowerCase();
      if (lowerCsp.includes('unsafe-inline') || lowerCsp.includes('unsafe-eval') || lowerCsp.includes('*')) {
        context.addFinding({
          rule_id: 'SEC-HDR-CSP-WEAK',
          title: 'Weak Content-Security-Policy Directives Detected',
          description: 'The Content-Security-Policy contains permissive keywords (unsafe-inline, unsafe-eval, or wildcards) that weaken script execution isolation.',
          severity: 'MEDIUM',
          confidence: 'HIGH',
          status: 'CONFIRMED',
          check_status: 'FINDING',
          owasp_category: 'A02',
          owasp_version: '2025',
          cwe: 'CWE-1021',
          affected_url: targetUrl,
          evidence: EvidenceRedactor.redact(`Observed Content-Security-Policy: "${csp.substring(0, 300)}"`),
          impact: 'Allows inline scripts or arbitrary origins to execute, reducing the efficacy of XSS mitigations.',
          remediation: 'Refactor inline scripts to external bundles or adopt cryptographic nonces / hashes (e.g., \'nonce-...\'). Avoid wildcard origins.',
          references: 'https://content-security-policy.com/',
        });
      }
    }

    // 2. Strict-Transport-Security (HSTS)
    // Only applies to HTTPS endpoints; mapped to A04:2025 (Cryptographic Failures)
    if (context.isHttps) {
      const hsts = headers['strict-transport-security'];
      if (!hsts) {
        context.addFinding({
          rule_id: 'SEC-HDR-HSTS-MISSING',
          title: 'Missing Strict-Transport-Security (HSTS) Header',
          description: 'HTTP Strict Transport Security (HSTS) instructs modern web browsers to interact exclusively over HTTPS, preventing SSL stripping and downgrade attacks.',
          severity: 'MEDIUM',
          confidence: 'HIGH',
          status: 'CONFIRMED',
          check_status: 'FINDING',
          owasp_category: 'A04',
          owasp_version: '2025',
          cwe: 'CWE-523',
          affected_url: targetUrl,
          evidence: 'HTTPS response inspected; "strict-transport-security" header was absent.',
          impact: 'Users requesting http:// variants may be susceptible to man-in-the-middle (MITM) attacks and certificate bypasses.',
          remediation: 'Configure: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
          references: 'https://owasp.org/www-project-top-ten/2025/A04_Cryptographic_Failures/',
        });
      } else {
        const match = hsts.match(/max-age=(\d+)/i);
        if (match && parseInt(match[1], 10) < 10368000) {
          context.addFinding({
            rule_id: 'SEC-HDR-HSTS-SHORT',
            title: 'Suboptimal HSTS max-age Duration',
            description: 'The Strict-Transport-Security max-age directive is set below the recommended 120 days (10,368,000 seconds).',
            severity: 'LOW',
            confidence: 'HIGH',
            status: 'CONFIRMED',
            check_status: 'FINDING',
            owasp_category: 'A04',
            owasp_version: '2025',
            cwe: 'CWE-523',
            affected_url: targetUrl,
            evidence: `Observed Strict-Transport-Security: "${hsts}"`,
            impact: 'Short HSTS duration expires quickly, opening a window for protocol downgrade.',
            remediation: 'Increase max-age to at least 31536000 (1 year) and consider includeSubDomains.',
            references: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
          });
        }
      }
    }

    // 3. X-Frame-Options or CSP frame-ancestors (Clickjacking Protection)
    const xfo = headers['x-frame-options'];
    const hasFrameAncestors = csp && csp.toLowerCase().includes('frame-ancestors');
    if (!xfo && !hasFrameAncestors) {
      context.addFinding({
        rule_id: 'SEC-HDR-XFO-MISSING',
        title: 'Missing Clickjacking Defense (X-Frame-Options / frame-ancestors)',
        description: 'Neither X-Frame-Options nor CSP frame-ancestors directive was detected to restrict framing of the target page.',
        severity: 'MEDIUM',
        confidence: 'HIGH',
        status: 'CONFIRMED',
        check_status: 'FINDING',
        owasp_category: 'A02',
        owasp_version: '2025',
        cwe: 'CWE-1021',
        affected_url: targetUrl,
        evidence: 'Neither "x-frame-options" nor CSP "frame-ancestors" was present in HTTP response headers.',
        impact: 'An attacker can overlay an invisible iframe on a malicious website to trick users into unintended actions (Clickjacking).',
        remediation: 'Configure X-Frame-Options: DENY (or SAMEORIGIN), or CSP: frame-ancestors \'none\';',
        references: 'https://owasp.org/www-community/attacks/Clickjacking',
      });
    }

    // 4. X-Content-Type-Options
    const xcto = headers['x-content-type-options'];
    if (!xcto || xcto.toLowerCase() !== 'nosniff') {
      context.addFinding({
        rule_id: 'SEC-HDR-XCTO-MISSING',
        title: 'Missing or Improper X-Content-Type-Options Header',
        description: 'The X-Content-Type-Options header instructs browsers to strictly respect declared MIME types and disable MIME-sniffing.',
        severity: 'LOW',
        confidence: 'HIGH',
        status: 'CONFIRMED',
        check_status: 'FINDING',
        owasp_category: 'A02',
        owasp_version: '2025',
        cwe: 'CWE-79',
        affected_url: targetUrl,
        evidence: `X-Content-Type-Options value: "${xcto || 'NOT_SET'}"`,
        impact: 'Browsers may interpret non-executable text or image uploads as executable HTML or script, enabling stored XSS.',
        remediation: 'Add header: X-Content-Type-Options: nosniff',
        references: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options',
      });
    }

    // 5. Referrer-Policy — CORRECTLY mapped to A02:2025 (Security Misconfiguration)
    const rp = headers['referrer-policy'];
    if (!rp) {
      context.addFinding({
        rule_id: 'SEC-HDR-RP-MISSING',
        title: 'Missing Referrer-Policy Header',
        description: 'The Referrer-Policy HTTP header governs how much referrer metadata is transmitted with outgoing navigation and subresource requests.',
        severity: 'LOW',
        confidence: 'HIGH',
        status: 'CONFIRMED',
        check_status: 'FINDING',
        owasp_category: 'A02',
        owasp_version: '2025',
        cwe: 'CWE-200',
        affected_url: targetUrl,
        evidence: 'Referrer-Policy header was omitted from HTTP response headers.',
        impact: 'Browsers may transmit full target URLs including confidential query parameters or path IDs to third-party domains.',
        remediation: 'Set: Referrer-Policy: strict-origin-when-cross-origin or no-referrer',
        references: 'https://owasp.org/www-project-top-ten/2025/A02_Security_Misconfiguration/',
      });
    } else if (rp.toLowerCase().includes('unsafe-url')) {
      context.addFinding({
        rule_id: 'SEC-HDR-RP-UNSAFE',
        title: 'Insecure Referrer-Policy Configuration (unsafe-url)',
        description: 'Referrer-Policy is set to "unsafe-url", which leaks full URLs over both HTTPS and unencrypted HTTP connections.',
        severity: 'MEDIUM',
        confidence: 'HIGH',
        status: 'CONFIRMED',
        check_status: 'FINDING',
        owasp_category: 'A02',
        owasp_version: '2025',
        cwe: 'CWE-200',
        affected_url: targetUrl,
        evidence: `Observed Referrer-Policy: "${rp}"`,
        impact: 'Leads to sensitive path and parameter leaks across unencrypted network segments.',
        remediation: 'Change Referrer-Policy to strict-origin-when-cross-origin.',
        references: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy',
      });
    }

    // 6. Permissions-Policy
    const permPolicy = headers['permissions-policy'] || headers['feature-policy'];
    if (!permPolicy) {
      context.addFinding({
        rule_id: 'SEC-HDR-PERM-MISSING',
        title: 'Missing Permissions-Policy Header',
        description: 'Permissions-Policy allows developers to explicitly restrict access to browser hardware features such as camera, microphone, geolocation, and payment APIs.',
        severity: 'INFORMATIONAL',
        confidence: 'HIGH',
        status: 'CONFIRMED',
        check_status: 'FINDING',
        owasp_category: 'A02',
        owasp_version: '2025',
        cwe: 'CWE-693',
        affected_url: targetUrl,
        evidence: 'Permissions-Policy header was absent from server response.',
        impact: 'Embedded third-party scripts or iframes may request sensitive device capabilities without origin restrictions.',
        remediation: 'Configure: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()',
        references: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy',
      });
    }

    // 7. Server & Technology Banner Disclosure
    const serverBanner = headers['server'];
    const xPoweredBy = headers['x-powered-by'];
    if (serverBanner || xPoweredBy) {
      const bannerEvidence = [
        serverBanner ? `Server: ${serverBanner}` : '',
        xPoweredBy ? `X-Powered-By: ${xPoweredBy}` : '',
      ].filter(Boolean).join(' | ');

      context.addFinding({
        rule_id: 'SEC-HDR-SERVER-LEAK',
        title: 'Server Banner & Technology Version Disclosure',
        description: 'The server discloses internal software engine and version details via HTTP response headers.',
        severity: 'LOW',
        confidence: 'HIGH',
        status: 'CONFIRMED',
        check_status: 'FINDING',
        owasp_category: 'A02',
        owasp_version: '2025',
        cwe: 'CWE-200',
        affected_url: targetUrl,
        evidence: EvidenceRedactor.redact(`Disclosed Headers: ${bannerEvidence}`),
        impact: 'Assists attackers in fingerprinting exact versions to cross-reference against public CVE advisories.',
        remediation: 'Disable Server tokens and remove X-Powered-By (e.g. app.disable(\'x-powered-by\') in Express, or server_tokens off in Nginx).',
        references: 'https://owasp.org/www-project-top-ten/2025/A02_Security_Misconfiguration/',
      });
    }
  }
}
