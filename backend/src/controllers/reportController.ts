import { Response } from 'express';
import path from 'path';
import fs from 'fs';
import { query } from '../database/db';
import { AuthenticatedRequest } from '../middleware/auth';
import { ReportGenerator } from '../reports/ReportGenerator';

const generator = new ReportGenerator();

export async function createReport(req: AuthenticatedRequest, res: Response) {
  try {
    const scanId = req.params.id;
    const userId = req.user!.id;

    const scanRes = await query('SELECT * FROM scans WHERE id = $1 AND user_id = $2', [scanId, userId]);
    if (scanRes.rows.length === 0) {
      return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Scan not found.' } });
    }

    const scan = scanRes.rows[0];
    const findings = (await query('SELECT * FROM findings WHERE scan_id = $1', [scanId])).rows;
    const technologies = (await query('SELECT * FROM technologies WHERE scan_id = $1', [scanId])).rows;
    const owaspResults = (await query('SELECT * FROM owasp_results WHERE scan_id = $1', [scanId])).rows;

    const reportsDir = path.join(process.cwd(), 'temp_reports');
    const filePath = path.join(reportsDir, `WebShield_Report_${scanId}.pdf`);

    await generator.generatePdfReport({ scan, findings, technologies, owaspResults }, filePath);

    const dbReport = await query(
      'INSERT INTO reports (scan_id, file_path) VALUES ($1, $2) RETURNING *',
      [scanId, filePath]
    );

    return res.status(201).json({
      success: true,
      data: { report: dbReport.rows[0] },
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: { code: 'SERVER_ERROR', message: 'Failed to generate PDF report.' },
    });
  }
}

export async function downloadReport(req: AuthenticatedRequest, res: Response) {
  try {
    const reportId = req.params.id;
    const reportRes = await query('SELECT * FROM reports WHERE id = $1', [reportId]);

    if (reportRes.rows.length === 0) {
      return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Report not found.' } });
    }

    const report = reportRes.rows[0];
    if (!fs.existsSync(report.file_path)) {
      return res.status(404).json({ success: false, error: { code: 'FILE_NOT_FOUND', message: 'Report file missing from server storage.' } });
    }

    return res.download(report.file_path, `WebShield_Security_Report_${report.scan_id}.pdf`);
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: { code: 'SERVER_ERROR', message: 'Failed to download report.' },
    });
  }
}
