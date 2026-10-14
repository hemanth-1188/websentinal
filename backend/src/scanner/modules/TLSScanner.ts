import tls from 'tls';
import http from 'http';
import { URL } from 'url';
import { ScanContext } from '../core/ScanContext';

export class TLSScanner {
  public async scan(context: ScanContext): Promise<void> {
    const targetUrl = context.targetUrl;
    const parsed = new URL(targetUrl);
    context.totalChecksExecuted += 3;

    // 1. Check Plaintext HTTP Transport Usage
    if (!context.isHttps) {
      context.addFinding({
        rule_id: 'SEC-TLS-PLAINTEXT-HTTP',
        title: 'Unencrypted HTTP Transport in Use',
        description: 'The target application is being accessed over plaintext HTTP, transmitting requests and responses without cryptographic encapsulation.',
        severity: 'HIGH',
        confidence: 'HIGH',
        status: 'CONFIRMED',
        check_status: 'FINDING',
        owasp_category: 'A04',
        owasp_version: '2025',
        cwe: 'CWE-319',
        affected_url: targetUrl,
        evidence: `URL scheme is unencrypted: ${targetUrl}`,
        impact: 'Network eavesdroppers can capture authentication tokens, passwords, and sensitive business data.',
        remediation: 'Migrate to HTTPS with valid TLS certificates and enforce automated HTTP-to-HTTPS redirects.',
        references: 'https://owasp.org/www-project-top-ten/2025/A04_Cryptographic_Failures/',
      });
      return;
    }

    // 2. Test HTTP to HTTPS Redirection Behavior
    try {
      const httpVariant = `http://${parsed.hostname}${parsed.port === '443' ? '' : parsed.port ? `:${parsed.port}` : ''}/`;
      const redirectState = await this.checkHttpToHttpsRedirect(parsed.hostname, 80);
      if (redirectState && !redirectState.redirectsToHttps) {
        context.addFinding({
          rule_id: 'SEC-TLS-NO-REDIRECT',
          title: 'Missing Automatic HTTP-to-HTTPS Redirection',
          description: 'Port 80 (HTTP) does not automatically redirect visitors to the secure HTTPS interface.',
          severity: 'MEDIUM',
          confidence: 'HIGH',
          status: 'CONFIRMED',
          check_status: 'FINDING',
          owasp_category: 'A04',
          owasp_version: '2025',
          cwe: 'CWE-319',
          affected_url: httpVariant,
          evidence: `HTTP port 80 response code: ${redirectState.statusCode}. Location header: "${redirectState.location || 'NONE'}"`,
          impact: 'Users typing the domain without https:// will remain in plaintext communication if they do not manually switch schemes.',
          remediation: 'Configure the web server or reverse proxy to return a 301 Permanent Redirect to https://.',
          references: 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html',
        });
      }
    } catch (e) {
      // Port 80 connection error indicates port 80 might be closed or unreachable; not a confirmed vulnerability
    }

    // 3. Inspect TLS Socket & Certificate
    try {
      const port = parsed.port ? parseInt(parsed.port, 10) : 443;
      const socketDetails = await this.inspectTlsSocket(parsed.hostname, port);

      if (socketDetails.daysRemaining < 30) {
        context.addFinding({
          rule_id: 'SEC-TLS-CERT-EXPIRING',
          title: socketDetails.daysRemaining <= 0 ? 'TLS Certificate Has Expired' : 'TLS Certificate Nearing Expiration',
          description: `The SSL/TLS certificate for ${parsed.hostname} ${socketDetails.daysRemaining <= 0 ? 'expired' : `expires in ${socketDetails.daysRemaining} days`}.`,
          severity: socketDetails.daysRemaining <= 7 ? 'HIGH' : 'MEDIUM',
          confidence: 'HIGH',
          status: 'CONFIRMED',
          check_status: 'FINDING',
          owasp_category: 'A04',
          owasp_version: '2025',
          cwe: 'CWE-295',
          affected_url: targetUrl,
          evidence: `Certificate Valid To: ${socketDetails.validTo}. Issuer: ${socketDetails.issuer}. Days Remaining: ${socketDetails.daysRemaining}`,
          impact: 'Expired certificates break cryptographic trust and prompt severe browser security warnings that block user traffic.',
          remediation: 'Renew the SSL/TLS certificate immediately and configure automated renewal (e.g. ACME / certbot).',
          references: 'https://owasp.org/www-project-top-ten/2025/A04_Cryptographic_Failures/',
        });
      }
    } catch (err: any) {
      // Differentiate genuine handshake error vs connection timeout
      if (!err.message.includes('timeout')) {
        context.addFinding({
          rule_id: 'SEC-TLS-HANDSHAKE-WARN',
          title: 'TLS/SSL Certificate Validation Warning',
          description: 'A certificate or handshake anomaly occurred when establishing a TLS connection to the host.',
          severity: 'LOW',
          confidence: 'MEDIUM',
          status: 'CONFIRMED',
          check_status: 'FINDING',
          owasp_category: 'A04',
          owasp_version: '2025',
          cwe: 'CWE-295',
          affected_url: targetUrl,
          evidence: `TLS Handshake note: ${err.message}`,
          impact: 'Clients may reject the connection if the root CA is unverified or intermediate certificates are missing.',
          remediation: 'Ensure complete certificate chain of trust is installed on the web server.',
          references: 'https://owasp.org/www-project-top-ten/2025/A04_Cryptographic_Failures/',
        });
      }
    }
  }

  private checkHttpToHttpsRedirect(hostname: string, port: number): Promise<{ statusCode: number; location: string | null; redirectsToHttps: boolean }> {
    return new Promise((resolve, reject) => {
      const req = http.request(
        {
          hostname,
          port,
          path: '/',
          method: 'GET',
          timeout: 4000,
          headers: { 'User-Agent': 'WebShield-TLS-Checker/1.0' },
        },
        (res) => {
          const location = (res.headers['location'] as string) || null;
          const redirectsToHttps = Boolean(
            (res.statusCode === 301 || res.statusCode === 302 || res.statusCode === 307 || res.statusCode === 308) &&
            location &&
            location.toLowerCase().startsWith('https://')
          );
          resolve({ statusCode: res.statusCode || 200, location, redirectsToHttps });
        }
      );

      req.on('timeout', () => {
        req.destroy();
        reject(new Error('HTTP Port 80 connection timeout'));
      });
      req.on('error', (err) => reject(err));
      req.end();
    });
  }

  private inspectTlsSocket(hostname: string, port: number): Promise<{ validTo: string; daysRemaining: number; issuer: string }> {
    return new Promise((resolve, reject) => {
      const socket = tls.connect(port, hostname, { servername: hostname, rejectUnauthorized: false }, () => {
        const cert = socket.getPeerCertificate();
        socket.end();

        if (!cert || !cert.valid_to) {
          return reject(new Error('Unable to retrieve TLS peer certificate.'));
        }

        const validToDate = new Date(cert.valid_to);
        const now = new Date();
        const diffTime = validToDate.getTime() - now.getTime();
        const daysRemaining = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

        const getSingleString = (val: string | string[] | undefined): string => Array.isArray(val) ? val[0] : val || 'Unknown';
        resolve({
          validTo: cert.valid_to,
          daysRemaining,
          issuer: typeof cert.issuer === 'object' ? getSingleString(cert.issuer.O) || getSingleString(cert.issuer.CN) : 'Unknown',
        });
      });

      socket.setTimeout(5000, () => {
        socket.destroy();
        reject(new Error('TLS Socket connection timeout.'));
      });

      socket.on('error', (err) => {
        reject(err);
      });
    });
  }
}
