import { ScanContext } from '../core/ScanContext';
import { RequestManager } from '../core/RequestManager';
import { EvidenceRedactor } from '../../services/evidenceRedactor';

export class InjectionScanner {
  private requestManager = new RequestManager();

  public async scan(context: ScanContext): Promise<void> {
    const baseUrl = context.targetUrl;
    context.totalChecksExecuted += 2;

    // Safe, non-destructive probe string designed to verify reflection without attacking the database
    const probeToken = 'ws_probe_xss_test_7f9';
    const safeProbe = `<b id="${probeToken}">test</b>`;

    try {
      const probeUrl = `${baseUrl}${baseUrl.includes('?') ? '&' : '?'}q=${encodeURIComponent(safeProbe)}`;
      const res = await this.requestManager.fetchUrl(probeUrl, { maxBodyBytes: 150 * 1024 });

      // 1. Check for unescaped reflection of HTML tags in response
      if (res.body.includes(safeProbe)) {
        context.addFinding({
          rule_id: 'SEC-INJ-REFLECTED-XSS',
          title: 'Unescaped Query Parameter Reflection (Potential XSS)',
          description: 'User-supplied query parameter input was reflected verbatim in the HTML body without contextual entity encoding.',
          severity: 'HIGH',
          confidence: 'HIGH',
          status: 'CONFIRMED',
          check_status: 'FINDING',
          owasp_category: 'A05',
          owasp_version: '2025',
          cwe: 'CWE-79',
          affected_url: probeUrl,
          evidence: EvidenceRedactor.redact(`Parameter reflection observed: "${safeProbe}" found unencoded in response HTML.`),
          impact: 'An attacker can craft malicious links that execute arbitrary client-side JavaScript in victims\' sessions.',
          remediation: 'Sanitize and encode all untrusted inputs using context-aware HTML entity encoders (e.g., DOMPurify or framework auto-escaping).',
          references: 'https://owasp.org/www-project-top-ten/2025/A05_Injection/',
        });
      }

      // 2. Check for detailed SQL database error signatures
      const sqlErrorSignatures = [
        'you have an error in your sql syntax',
        'unclosed quotation mark after the character string',
        'warning: mysql_',
        'pg_query(): query failed:',
        'sqlite3::queryexec()',
        'microsoft ole db provider for sql server',
      ];

      const lowerBody = res.body.toLowerCase();
      const matchedSig = sqlErrorSignatures.find(sig => lowerBody.includes(sig));

      if (matchedSig) {
        context.addFinding({
          rule_id: 'SEC-INJ-DB-ERROR-LEAK',
          title: 'Database Engine Error Message Disclosure',
          description: 'The server disclosed low-level database error signatures, suggesting vulnerable query formatting or unhandled database exceptions.',
          severity: 'HIGH',
          confidence: 'HIGH',
          status: 'CONFIRMED',
          check_status: 'FINDING',
          owasp_category: 'A05',
          owasp_version: '2025',
          cwe: 'CWE-89',
          affected_url: probeUrl,
          evidence: EvidenceRedactor.redact(`Detected database error signature: "${matchedSig}" in response text.`),
          impact: 'Assists attackers in discovering backend SQL engine types and structuring targeted SQL injection attacks.',
          remediation: 'Enforce parameterized queries or ORM abstractions and disable raw database error propagation in user responses.',
          references: 'https://owasp.org/www-project-top-ten/2025/A05_Injection/',
        });
      }
    } catch (e) {
      // Non-destructive probe ignored on error
    }
  }
}
