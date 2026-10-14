import { OWASP_2025_CATEGORIES } from '../src/scanner/owasp/OWASPRegistry';
import { OWASPEngine } from '../src/scanner/owasp/OWASPEngine';
import { ScanContext } from '../src/scanner/core/ScanContext';

describe('OWASP Top 10:2025 Centralized Registry & Mapping Engine Tests', () => {
  test('Defines all 10 official OWASP Top 10:2025 categories', () => {
    const keys = Object.keys(OWASP_2025_CATEGORIES);
    expect(keys).toEqual(['A01', 'A02', 'A03', 'A04', 'A05', 'A06', 'A07', 'A08', 'A09', 'A10']);

    expect(OWASP_2025_CATEGORIES.A01.title).toBe('Broken Access Control');
    expect(OWASP_2025_CATEGORIES.A02.title).toBe('Security Misconfiguration');
    expect(OWASP_2025_CATEGORIES.A03.title).toBe('Software Supply Chain Failures');
    expect(OWASP_2025_CATEGORIES.A04.title).toBe('Cryptographic Failures');
    expect(OWASP_2025_CATEGORIES.A05.title).toBe('Injection');
    expect(OWASP_2025_CATEGORIES.A06.title).toBe('Insecure Design');
    expect(OWASP_2025_CATEGORIES.A07.title).toBe('Authentication Failures');
    expect(OWASP_2025_CATEGORIES.A08.title).toBe('Software or Data Integrity Failures');
    expect(OWASP_2025_CATEGORIES.A09.title).toBe('Security Logging and Alerting Failures');
    expect(OWASP_2025_CATEGORIES.A10.title).toBe('Mishandling of Exceptional Conditions');
  });

  test('Never marks Insecure Design (A06) or Logging/Alerting (A09) as fake PASS', () => {
    const engine = new OWASPEngine();
    const context = new ScanContext({
      scanId: 'test-scan-1',
      targetUrl: 'https://example.com',
      scanType: 'STANDARD',
    });

    const results = engine.mapResults(context);

    const a06 = results.find(r => r.category === 'A06');
    const a09 = results.find(r => r.category === 'A09');

    expect(a06).toBeDefined();
    expect(a06?.status).toBe('NOT_TESTED');
    expect(a06?.applicable_checks_planned).toBe(0);

    expect(a09).toBeDefined();
    expect(a09?.status).toBe('NOT_TESTED');
    expect(a09?.applicable_checks_planned).toBe(0);
  });

  test('Marks category with detected finding as FINDING status', () => {
    const engine = new OWASPEngine();
    const context = new ScanContext({
      scanId: 'test-scan-2',
      targetUrl: 'https://example.com',
      scanType: 'STANDARD',
    });

    context.addFinding({
      rule_id: 'SEC-HDR-CSP-MISSING',
      title: 'Missing CSP',
      description: 'Test description',
      severity: 'HIGH',
      confidence: 'HIGH',
      status: 'CONFIRMED',
      owasp_category: 'A02',
      affected_url: 'https://example.com',
      evidence: 'Header absent',
      impact: 'XSS mitigation missing',
      remediation: 'Add CSP',
    });

    const results = engine.mapResults(context);
    const a02 = results.find(r => r.category === 'A02');

    expect(a02).toBeDefined();
    expect(a02?.status).toBe('FINDING');
    expect(a02?.findings_count).toBe(1);
    expect(a02?.score).toBeLessThan(100);
  });
});
