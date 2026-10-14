import { OWASP2025Result } from '../owasp/OWASPRegistry';

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
export type ConfidenceLevel = 'HIGH' | 'MEDIUM' | 'LOW';
export type FindingLifecycleStatus = 'OPEN' | 'CONFIRMED' | 'FALSE_POSITIVE' | 'ACCEPTED_RISK' | 'RESOLVED';
export type CheckStatus = 'PASS' | 'FINDING' | 'NOT_TESTED' | 'ERROR' | 'INCONCLUSIVE';

export interface Finding {
  id?: string;
  scan_id?: string;
  rule_id: string; // Stable rule identifier for cross-scan tracking & remediation
  title: string;
  description: string;
  target_url?: string;
  severity: SeverityLevel;
  confidence: ConfidenceLevel;
  status: FindingLifecycleStatus;
  check_status?: CheckStatus;
  owasp_category: string; // e.g. 'A01' - 'A10'
  owasp_version?: string; // '2025'
  cwe?: string;
  affected_url: string;
  evidence: string;
  impact: string;
  remediation: string;
  references?: string;
  first_seen_at?: string;
  last_seen_at?: string;
  resolved_at?: string | null;
  created_at?: string;
}

export interface Technology {
  id?: string;
  scan_id?: string;
  name: string;
  version?: string;
  category: string;
  confidence: ConfidenceLevel;
}

export interface OWASPResult {
  category: string;
  code?: string;
  title?: string;
  status: 'PASS' | 'FAIL' | 'WARNING' | 'NOT_TESTED' | 'MANUAL_REVIEW' | 'FINDING';
  score: number;
  findings_count: number;
  applicable_checks_executed?: number;
  applicable_checks_planned?: number;
  explanation?: string;
}

export interface ScanOptions {
  scanId: string;
  targetUrl: string;
  scanType: 'QUICK' | 'STANDARD' | 'DEEP';
  maxDurationSeconds?: number;
  maxRequests?: number;
  timeoutMs?: number;
  maxRedirects?: number;
}

export class ScanContext {
  public scanId: string;
  public targetUrl: string;
  public scanType: 'QUICK' | 'STANDARD' | 'DEEP';
  public findings: Finding[] = [];
  public technologies: Technology[] = [];
  public owaspResults: OWASPResult[] = [];
  public rawHeaders: Record<string, string> = {};
  public rawCookies: string[] = [];
  public statusCode: number = 0;
  public htmlContent: string = '';
  public isHttps: boolean = false;
  public securityScore: number = 100;
  public startTime: Date = new Date();
  public endTime?: Date;
  public totalChecksPlanned: number = 18;
  public totalChecksExecuted: number = 0;
  public failedChecks: number = 0;

  constructor(options: ScanOptions) {
    this.scanId = options.scanId;
    this.targetUrl = options.targetUrl;
    this.scanType = options.scanType;
    this.isHttps = options.targetUrl.startsWith('https://');
  }

  public addFinding(finding: Finding) {
    // Default OWASP version to 2025 if omitted
    if (!finding.owasp_version) {
      finding.owasp_version = '2025';
    }
    if (!finding.target_url) {
      finding.target_url = this.targetUrl;
    }
    if (!finding.status) {
      finding.status = 'CONFIRMED';
    }
    if (!finding.check_status) {
      finding.check_status = 'FINDING';
    }
    this.findings.push(finding);
  }

  public addTechnology(tech: Technology) {
    if (!this.technologies.some(t => t.name.toLowerCase() === tech.name.toLowerCase())) {
      this.technologies.push(tech);
    }
  }
}
