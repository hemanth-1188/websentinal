import { URL } from 'url';
import { ScanContext } from '../core/ScanContext';
import { RequestManager } from '../core/RequestManager';
import { EvidenceRedactor } from '../../services/evidenceRedactor';

export class InformationDisclosureScanner {
  private requestManager = new RequestManager();

  public async scan(context: ScanContext): Promise<void> {
    const baseUrl = new URL(context.targetUrl).origin;
    context.totalChecksExecuted += 4;

    // 1. Robots.txt Sensitive Path Disclosure
    try {
      const robotsUrl = `${baseUrl}/robots.txt`;
      const res = await this.requestManager.fetchUrl(robotsUrl, { maxBodyBytes: 50 * 1024 });
      if (res.statusCode === 200 && res.body.toLowerCase().includes('disallow')) {
        const sensitiveKeywords = ['admin', 'backup', 'internal', 'private', 'config', 'secret', 'api/v'];
        const lines = res.body.split('\n');
        const matchedPaths: string[] = [];

        for (const line of lines) {
          if (line.toLowerCase().startsWith('disallow:')) {
            const pathVal = line.split(':')[1]?.trim();
            if (pathVal && sensitiveKeywords.some(kw => pathVal.toLowerCase().includes(kw))) {
              matchedPaths.push(pathVal);
            }
          }
        }

        if (matchedPaths.length > 0) {
          context.addFinding({
            rule_id: 'SEC-EXP-ROBOTS-SENSITIVE',
            title: 'Sensitive Endpoint Paths Disclosed in robots.txt',
            description: 'The robots.txt file publicly advertises sensitive internal administrative or backup directories.',
            severity: 'LOW',
            confidence: 'HIGH',
            status: 'CONFIRMED',
            check_status: 'FINDING',
            owasp_category: 'A01',
            owasp_version: '2025',
            cwe: 'CWE-200',
            affected_url: robotsUrl,
            evidence: `Disallowed paths detected: ${matchedPaths.slice(0, 5).join(', ')}`,
            impact: 'Attackers scan robots.txt to discover hidden application areas that may lack authentication.',
            remediation: 'Do not rely on robots.txt for security obscurity. Implement robust RBAC on all endpoints.',
            references: 'https://owasp.org/www-project-top-ten/2025/A01_Broken_Access_Control/',
          });
        }
      }
    } catch (e) {
      // Safe probe ignored on network error
    }

    // 2. Exposed Environment File (.env.example or .env)
    try {
      const envUrl = `${baseUrl}/.env.example`;
      const res = await this.requestManager.fetchUrl(envUrl, { maxBodyBytes: 30 * 1024 });
      if (
        res.statusCode === 200 &&
        (res.body.includes('PORT=') || res.body.includes('DATABASE_URL=') || res.body.includes('SECRET=') || res.body.includes('JWT_'))
      ) {
        context.addFinding({
          rule_id: 'SEC-EXP-ENV-LEAK',
          title: 'Publicly Accessible Environment Configuration File (.env.example)',
          description: 'An environment configuration template file was served over HTTP with internal infrastructure variable definitions.',
          severity: 'HIGH',
          confidence: 'HIGH',
          status: 'CONFIRMED',
          check_status: 'FINDING',
          owasp_category: 'A02',
          owasp_version: '2025',
          cwe: 'CWE-538',
          affected_url: envUrl,
          evidence: EvidenceRedactor.redact(`HTTP 200 OK received at ${envUrl}. Content snippet: "${res.body.substring(0, 160)}..."`),
          impact: 'Exposes internal database connection formats, service names, and configuration schemas to attackers.',
          remediation: 'Configure the web server to deny access to all dotfiles (location ~ /\\. { deny all; }).',
          references: 'https://owasp.org/www-project-top-ten/2025/A02_Security_Misconfiguration/',
        });
      }
    } catch (e) {
      // Safe probe ignored
    }

    // 3. Exposed Database Backup File
    try {
      const backupUrl = `${baseUrl}/backup/database.sql`;
      const res = await this.requestManager.fetchUrl(backupUrl, { maxBodyBytes: 30 * 1024 });
      if (
        res.statusCode === 200 &&
        (res.body.includes('CREATE TABLE') || res.body.includes('INSERT INTO') || res.body.includes('PostgreSQL database dump'))
      ) {
        context.addFinding({
          rule_id: 'SEC-EXP-BACKUP-LEAK',
          title: 'Exposed Database Backup Archive',
          description: 'A database SQL dump or backup file was discovered in a publicly accessible directory without authentication.',
          severity: 'CRITICAL',
          confidence: 'HIGH',
          status: 'CONFIRMED',
          check_status: 'FINDING',
          owasp_category: 'A01',
          owasp_version: '2025',
          cwe: 'CWE-530',
          affected_url: backupUrl,
          evidence: EvidenceRedactor.redact(`HTTP 200 OK received at ${backupUrl}. Content snippet: "${res.body.substring(0, 160)}..."`),
          impact: 'Complete compromise of data confidentiality; attackers can download the complete schema and records.',
          remediation: 'Remove public accessibility to backup paths immediately and store backups off-web-root.',
          references: 'https://owasp.org/www-project-top-ten/2025/A01_Broken_Access_Control/',
        });
      }
    } catch (e) {
      // Safe probe ignored
    }

    // 4. Exposed Debug Information / Stack Trace Endpoint
    try {
      const debugUrl = `${baseUrl}/debug/info`;
      const res = await this.requestManager.fetchUrl(debugUrl, { maxBodyBytes: 30 * 1024 });
      if (
        res.statusCode === 200 &&
        (res.body.includes('stack_trace') || res.body.includes('node_version') || res.body.includes('DEBUG_ACTIVE'))
      ) {
        context.addFinding({
          rule_id: 'SEC-EXP-DEBUG-ENDPOINT',
          title: 'Exposed Debug & Stack Trace Endpoint',
          description: 'A development or debugging endpoint exposing internal system versions, heap usage, and stack traces was accessible.',
          severity: 'HIGH',
          confidence: 'HIGH',
          status: 'CONFIRMED',
          check_status: 'FINDING',
          owasp_category: 'A10',
          owasp_version: '2025',
          cwe: 'CWE-215',
          affected_url: debugUrl,
          evidence: EvidenceRedactor.redact(`HTTP 200 OK at ${debugUrl}. Detected debug indicators in response.`),
          impact: 'Assists attackers in discovering exact code paths, exceptions, and memory structures.',
          remediation: 'Disable development routes in production and gate diagnostic endpoints behind authentication.',
          references: 'https://owasp.org/www-project-top-ten/2025/A10_Mishandling_of_Exceptional_Conditions/',
        });
      }
    } catch (e) {
      // Safe probe ignored
    }
  }
}
