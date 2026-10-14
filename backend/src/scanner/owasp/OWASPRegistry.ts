/**
 * OWASP Top 10:2025 Centralized Classification & Versioned Registry
 *
 * Official OWASP Top 10:2025 Category Identifiers:
 * - A01: Broken Access Control
 * - A02: Security Misconfiguration
 * - A03: Software Supply Chain Failures
 * - A04: Cryptographic Failures
 * - A05: Injection
 * - A06: Insecure Design
 * - A07: Authentication Failures
 * - A08: Software or Data Integrity Failures
 * - A09: Security Logging and Alerting Failures
 * - A10: Mishandling of Exceptional Conditions
 */

export interface OWASPCategoryDefinition {
  code: string; // e.g. 'A01:2025' or 'A01'
  id: string; // 'A01'
  version: '2025';
  title: string;
  description: string;
  evaluableByUrlScan: boolean;
  notes: string;
}

export const OWASP_2025_CATEGORIES: Record<string, OWASPCategoryDefinition> = {
  A01: {
    code: 'A01:2025',
    id: 'A01',
    version: '2025',
    title: 'Broken Access Control',
    description: 'Failures in enforcing restrictions on what authenticated or unauthenticated users can access or execute.',
    evaluableByUrlScan: true,
    notes: 'Partial assessment via unauthenticated administrative endpoints and sensitive path probing.',
  },
  A02: {
    code: 'A02:2025',
    id: 'A02',
    version: '2025',
    title: 'Security Misconfiguration',
    description: 'Missing security hardening, default configurations, open cloud storage, misconfigured HTTP headers, and verbose error messages.',
    evaluableByUrlScan: true,
    notes: 'Directly evaluated via HTTP response headers, Referrer-Policy, CORS, exposed configs, and banners.',
  },
  A03: {
    code: 'A03:2025',
    id: 'A03',
    version: '2025',
    title: 'Software Supply Chain Failures',
    description: 'Vulnerabilities introduced through third-party libraries, unpinned dependencies, compromised components, or untrusted build artifacts.',
    evaluableByUrlScan: true,
    notes: 'Evaluated via client-side library fingerprinting and exposed generator metadata.',
  },
  A04: {
    code: 'A04:2025',
    id: 'A04',
    version: '2025',
    title: 'Cryptographic Failures',
    description: 'Failures related to data in transit and at rest encryption, weak cipher suites, missing TLS/HTTPS, and missing HSTS protection.',
    evaluableByUrlScan: true,
    notes: 'Directly evaluated via transport protocol check, TLS certificate validation, and HSTS headers.',
  },
  A05: {
    code: 'A05:2025',
    id: 'A05',
    version: '2025',
    title: 'Injection',
    description: 'User-supplied data sent to an interpreter as part of a command or query (SQL, NoSQL, OS commands, LDAP, XSS reflection).',
    evaluableByUrlScan: true,
    notes: 'Evaluated via safe non-destructive reflection probes and database error disclosures.',
  },
  A06: {
    code: 'A06:2025',
    id: 'A06',
    version: '2025',
    title: 'Insecure Design',
    description: 'Risks related to architectural deficiencies, missing threat modeling, and business logic flaws.',
    evaluableByUrlScan: false,
    notes: 'Requires threat modeling and architecture review. Cannot be evaluated by passive external URL scanning.',
  },
  A07: {
    code: 'A07:2025',
    id: 'A07',
    version: '2025',
    title: 'Authentication Failures',
    description: 'Confirmation of identity, credential stuffing defenses, session token management, and cookie HttpOnly attributes.',
    evaluableByUrlScan: true,
    notes: 'Evaluated via cookie attributes (HttpOnly), session flags, and basic authentication prompts.',
  },
  A08: {
    code: 'A08:2025',
    id: 'A08',
    version: '2025',
    title: 'Software or Data Integrity Failures',
    description: 'Assumptions regarding software updates, sensitive data, and CI/CD pipelines without verifying integrity (e.g., Subresource Integrity).',
    evaluableByUrlScan: true,
    notes: 'Evaluated via script tag integrity attributes (SRI) on external scripts where present.',
  },
  A09: {
    code: 'A09:2025',
    id: 'A09',
    version: '2025',
    title: 'Security Logging and Alerting Failures',
    description: 'Insufficient logging and monitoring to detect and respond to active intrusions and suspicious activities.',
    evaluableByUrlScan: false,
    notes: 'Internal architectural capability. Cannot be evaluated from black-box HTTP probing.',
  },
  A10: {
    code: 'A10:2025',
    id: 'A10',
    version: '2025',
    title: 'Mishandling of Exceptional Conditions',
    description: 'Improper error handling, failing open, crash states, and unhandled exception traces.',
    evaluableByUrlScan: true,
    notes: 'Partially evaluated via debug endpoint disclosure and stack trace detection.',
  },
};

export type CheckExecutionStatus = 'PASS' | 'FINDING' | 'NOT_TESTED' | 'ERROR' | 'MANUAL_REVIEW';

export interface OWASP2025Result {
  category: string; // 'A01' - 'A10'
  code: string; // 'A01:2025'
  title: string;
  status: CheckExecutionStatus;
  score: number;
  findings_count: number;
  applicable_checks_executed: number;
  applicable_checks_planned: number;
  explanation: string;
}
