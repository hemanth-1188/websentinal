import { HeadersScanner } from '../src/scanner/modules/HeadersScanner';
import { ScanContext } from '../src/scanner/core/ScanContext';

describe('HTTP Security Headers Scanner Unit Tests', () => {
  const scanner = new HeadersScanner();

  test('Flags missing CSP as High severity mapped to A02:2025', async () => {
    const context = new ScanContext({
      scanId: 'h-1',
      targetUrl: 'https://example.com',
      scanType: 'STANDARD',
    });
    context.rawHeaders = {
      'content-type': 'text/html',
    };

    await scanner.scan(context);

    const cspFinding = context.findings.find(f => f.rule_id === 'SEC-HDR-CSP-MISSING');
    expect(cspFinding).toBeDefined();
    expect(cspFinding?.severity).toBe('HIGH');
    expect(cspFinding?.owasp_category).toBe('A02');
    expect(cspFinding?.owasp_version).toBe('2025');
  });

  test('Correctly maps Referrer-Policy to A02:2025 (Security Misconfiguration)', async () => {
    const context = new ScanContext({
      scanId: 'h-2',
      targetUrl: 'https://example.com',
      scanType: 'STANDARD',
    });
    context.rawHeaders = {};

    await scanner.scan(context);

    const rpFinding = context.findings.find(f => f.rule_id === 'SEC-HDR-RP-MISSING');
    expect(rpFinding).toBeDefined();
    expect(rpFinding?.owasp_category).toBe('A02'); // Required: Must be A02:2025, NOT A05
    expect(rpFinding?.severity).toBe('LOW');
  });

  test('Maps missing HSTS on HTTPS to A04:2025 (Cryptographic Failures)', async () => {
    const context = new ScanContext({
      scanId: 'h-3',
      targetUrl: 'https://example.com',
      scanType: 'STANDARD',
    });
    context.rawHeaders = {};

    await scanner.scan(context);

    const hstsFinding = context.findings.find(f => f.rule_id === 'SEC-HDR-HSTS-MISSING');
    expect(hstsFinding).toBeDefined();
    expect(hstsFinding?.owasp_category).toBe('A04');
    expect(hstsFinding?.owasp_version).toBe('2025');
  });

  test('Detects weak CSP directives containing unsafe-inline', async () => {
    const context = new ScanContext({
      scanId: 'h-4',
      targetUrl: 'https://example.com',
      scanType: 'STANDARD',
    });
    context.rawHeaders = {
      'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline'",
    };

    await scanner.scan(context);

    const weakCsp = context.findings.find(f => f.rule_id === 'SEC-HDR-CSP-WEAK');
    expect(weakCsp).toBeDefined();
    expect(weakCsp?.severity).toBe('MEDIUM');
    expect(weakCsp?.evidence).toContain('unsafe-inline');
  });

  test('Verifies fully hardened security headers produce zero header findings', async () => {
    const context = new ScanContext({
      scanId: 'h-5',
      targetUrl: 'https://example.com',
      scanType: 'STANDARD',
    });
    context.rawHeaders = {
      'content-security-policy': "default-src 'self'; script-src 'self'; frame-ancestors 'none'",
      'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
      'x-frame-options': 'DENY',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'strict-origin-when-cross-origin',
      'permissions-policy': 'camera=(), microphone=(), geolocation=()',
    };

    await scanner.scan(context);

    // Filter only header-related findings
    const headerFindings = context.findings.filter(f => f.rule_id.startsWith('SEC-HDR-'));
    expect(headerFindings.length).toBe(0);
  });
});
