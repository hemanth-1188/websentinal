import { URL } from 'url';
import { ScanContext } from '../core/ScanContext';
import { RequestManager } from '../core/RequestManager';
import { EvidenceRedactor } from '../../services/evidenceRedactor';

export class AccessControlScanner {
  private requestManager = new RequestManager();

  public async scan(context: ScanContext): Promise<void> {
    const origin = new URL(context.targetUrl).origin;
    const adminUrl = `${origin}/admin`;
    context.totalChecksExecuted += 1;

    try {
      const res = await this.requestManager.fetchUrl(adminUrl, { maxBodyBytes: 50 * 1024 });

      if (
        res.statusCode === 200 &&
        (res.body.toLowerCase().includes('admin panel') || res.body.toLowerCase().includes('administrative portal'))
      ) {
        context.addFinding({
          rule_id: 'SEC-ACC-ADMIN-UNAUTH',
          title: 'Exposed Administrative Portal Without Enforced Authentication',
          description: 'The administrative interface at /admin was publicly accessible with HTTP 200 OK without requiring authentication challenge headers.',
          severity: 'CRITICAL',
          confidence: 'HIGH',
          status: 'CONFIRMED',
          check_status: 'FINDING',
          owasp_category: 'A01',
          owasp_version: '2025',
          cwe: 'CWE-306',
          affected_url: adminUrl,
          evidence: EvidenceRedactor.redact(`HTTP 200 OK received at ${adminUrl}. Content contains administrative portal elements without 401/403/302 challenge.`),
          impact: 'Unauthenticated attackers may access sensitive management controls and compromise administrative functions.',
          remediation: 'Place administrative routes behind strong multi-factor authentication and strict IP allowlisting.',
          references: 'https://owasp.org/www-project-top-ten/2025/A01_Broken_Access_Control/',
        });
      }
    } catch (e) {
      // Access control probe ignored
    }
  }
}
