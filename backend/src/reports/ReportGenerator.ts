import PDFDocument from 'pdfkit';
import fs from 'fs';
import path from 'path';
import { EvidenceRedactor } from '../services/evidenceRedactor';

export interface ReportData {
  scan: any;
  findings: any[];
  technologies: any[];
  owaspResults: any[];
}

export class ReportGenerator {
  public async generatePdfReport(data: ReportData, outputPath: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const doc = new PDFDocument({ margin: 40, size: 'A4' });
      const dir = path.dirname(outputPath);

      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      const stream = fs.createWriteStream(outputPath);
      doc.pipe(stream);

      // --- Header / Title Banner ---
      doc.fillColor('#0B0F19').rect(0, 0, doc.page.width, 100).fill();
      doc.fillColor('#E11D48').fontSize(22).text('WEBSENTINEL', 40, 26);
      doc.fillColor('#FFFFFF').fontSize(14).text('Automated Web Security Assessment Report', 40, 52);
      doc.fillColor('#94A3B8').fontSize(9).text(
        `Generated: ${new Date().toUTCString()} | Scanner v2.0.0 | Rule-set: OWASP 2025.1`,
        40,
        74
      );

      doc.moveDown(4);

      // --- 1. Target Information & Score Overview ---
      doc.fillColor('#0F172A').fontSize(14).text('1. Target & Assessment Metadata', { underline: true });
      doc.moveDown(0.4);

      doc.fontSize(10).fillColor('#334155');
      doc.text(`Target URL: ${data.scan.target_url}`);
      doc.text(`Scan ID: ${data.scan.id}`);
      doc.text(`Scan Type: ${data.scan.scan_type}`);
      doc.text(`Scan Started: ${data.scan.started_at ? new Date(data.scan.started_at).toUTCString() : 'N/A'}`);
      doc.text(`Scan Completed: ${data.scan.completed_at ? new Date(data.scan.completed_at).toUTCString() : 'N/A'}`);
      doc.text(`Automated Check Coverage: ${data.scan.coverage_score || 100}%`);
      doc.text(`Security Score: ${data.scan.security_score} / 100`);

      let riskColor = '#10B981';
      if (data.scan.security_score < 40) riskColor = '#EF4444';
      else if (data.scan.security_score < 75) riskColor = '#F59E0B';

      doc.fillColor(riskColor).fontSize(12).text(
        `Overall Posture: ${data.scan.security_score >= 90 ? 'Excellent (Low Risk)' : data.scan.security_score >= 75 ? 'Good (Moderate Risk)' : data.scan.security_score >= 60 ? 'Fair (Elevated Risk)' : 'Critical Attention Required'}`
      );

      doc.moveDown(1.2);

      // --- 2. Scope & Technical Limitations ---
      doc.fillColor('#0F172A').fontSize(14).text('2. Assessment Scope & Limitations', { underline: true });
      doc.moveDown(0.4);
      doc.fontSize(9).fillColor('#475569').text(
        'This assessment was executed via controlled, bounded, non-destructive external HTTP probing. ' +
        'URL-only scanning evaluates observable transport security, security headers, cookie attributes, exposed public resources, and safe reflections. ' +
        'It cannot evaluate complex business logic, backend authentication controls, database queries, or unauthenticated internal APIs. ' +
        'A high score indicates sound perimeter hygiene but does not guarantee the absence of all vulnerabilities.'
      );

      doc.moveDown(1.2);

      // --- 3. OWASP Top 10:2025 Compliance Matrix ---
      doc.fillColor('#0F172A').fontSize(14).text('3. OWASP Top 10:2025 Assessment Matrix', { underline: true });
      doc.moveDown(0.4);

      if (data.owaspResults && data.owaspResults.length > 0) {
        data.owaspResults.forEach((owasp: any) => {
          let statusColor = '#10B981';
          if (owasp.status === 'FAIL' || owasp.status === 'FINDING') statusColor = '#EF4444';
          else if (owasp.status === 'NOT_TESTED' || owasp.status === 'MANUAL_REVIEW') statusColor = '#64748B';
          else if (owasp.status === 'WARNING') statusColor = '#F59E0B';

          doc.fillColor('#0F172A').fontSize(10).text(`• ${owasp.category}: ${owasp.title || owasp.code || ''}`, { continued: true });
          doc.fillColor(statusColor).text(`  [${owasp.status}]  —  ${owasp.findings_count || 0} finding(s)`);
        });
      }

      doc.moveDown(1.2);

      // --- 4. Detailed Findings with Redacted Evidence ---
      doc.fillColor('#0F172A').fontSize(14).text(`4. Detailed Findings (${data.findings.length} Discovered)`, { underline: true });
      doc.moveDown(0.4);

      if (data.findings.length === 0) {
        doc.fontSize(10).fillColor('#10B981').text('✓ No vulnerabilities or misconfigurations discovered during automated baseline checks.');
      } else {
        data.findings.forEach((finding: any, idx: number) => {
          let sevColor = '#3B82F6';
          if (finding.severity === 'CRITICAL') sevColor = '#EF4444';
          else if (finding.severity === 'HIGH') sevColor = '#F97316';
          else if (finding.severity === 'MEDIUM') sevColor = '#F59E0B';

          doc.fillColor(sevColor).fontSize(11).text(`${idx + 1}. [${finding.severity}] ${finding.title}`);
          doc.fontSize(9).fillColor('#475569');
          doc.text(`Rule ID: ${finding.rule_id || 'N/A'} | OWASP: ${finding.owasp_category} (${finding.owasp_version || '2025'}) | Confidence: ${finding.confidence}`);
          doc.text(`Status: ${finding.status || 'CONFIRMED'}${finding.resolved_at ? ' (RESOLVED)' : ''}`);
          doc.text(`Affected Endpoint: ${finding.affected_url}`);
          doc.fillColor('#334155').text(`Description: ${finding.description}`);
          
          // Technical evidence (strictly redacted)
          const redactedEvidence = EvidenceRedactor.redact(finding.evidence || 'None provided');
          doc.fillColor('#0F172A').text(`Technical Evidence: ${redactedEvidence}`);
          doc.fillColor('#1E293B').text(`Remediation: ${finding.remediation}`);
          if (finding.references) {
            doc.fillColor('#2563EB').text(`Reference: ${finding.references}`);
          }
          doc.moveDown(0.8);
        });
      }

      doc.moveDown(1);

      // --- 5. Identified Technologies ---
      doc.fillColor('#0F172A').fontSize(14).text('5. Identified Component Stack', { underline: true });
      doc.moveDown(0.4);
      if (data.technologies && data.technologies.length > 0) {
        data.technologies.forEach((tech: any) => {
          doc.fontSize(9).fillColor('#334155').text(`• ${tech.name} ${tech.version ? `v${tech.version}` : ''} (${tech.category})`);
        });
      } else {
        doc.fontSize(9).fillColor('#64748B').text('No definitive framework or server signatures fingerprinted.');
      }

      doc.moveDown(1.5);

      // --- 6. Legal & Responsible Testing Disclaimer ---
      doc.fillColor('#0F172A').fontSize(12).text('6. Security & Legal Disclaimer');
      doc.moveDown(0.3);
      doc.fontSize(8).fillColor('#64748B').text(
        'This assessment report is generated solely for defensive and authorized cybersecurity posture evaluation. ' +
        'All session tokens, cookies, and sensitive environment variables have been redacted. ' +
        'Any automated assessment must be complemented by manual code review and penetration testing for production environments.'
      );

      doc.end();

      stream.on('finish', () => resolve(outputPath));
      stream.on('error', reject);
    });
  }
}
