import { Response } from 'express';
import { query } from '../database/db';
import { AuthenticatedRequest } from '../middleware/auth';

export async function getDashboardSummary(req: AuthenticatedRequest, res: Response) {
  try {
    const userId = req.user!.id;

    // Total Scans & Average Score
    const scanStats = await query(
      `SELECT 
        COUNT(*) as total_scans,
        COALESCE(AVG(security_score), 100) as avg_score,
        COUNT(*) FILTER (WHERE status = 'COMPLETED') as completed_scans,
        COUNT(*) FILTER (WHERE status = 'RUNNING') as active_scans,
        COALESCE(AVG(coverage_score), 100) as avg_coverage
       FROM scans WHERE user_id = $1`,
      [userId]
    );

    // Finding Counts by Severity
    const findingStats = await query(
      `SELECT 
        COUNT(*) FILTER (WHERE f.severity = 'CRITICAL' AND f.status != 'RESOLVED') as critical_count,
        COUNT(*) FILTER (WHERE f.severity = 'HIGH' AND f.status != 'RESOLVED') as high_count,
        COUNT(*) FILTER (WHERE f.severity = 'MEDIUM' AND f.status != 'RESOLVED') as medium_count,
        COUNT(*) FILTER (WHERE f.severity = 'LOW' AND f.status != 'RESOLVED') as low_count,
        COUNT(*) FILTER (WHERE f.severity = 'INFORMATIONAL' AND f.status != 'RESOLVED') as info_count,
        COUNT(*) FILTER (WHERE f.status = 'RESOLVED') as resolved_count,
        COUNT(*) as total_findings
       FROM findings f
       JOIN scans s ON f.scan_id = s.id
       WHERE s.user_id = $1`,
      [userId]
    );

    // Latest Scan
    const latestScanRes = await query(
      `SELECT * FROM scans WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1`,
      [userId]
    );

    const latestScan = latestScanRes.rows[0] || null;

    const rowScan = scanStats.rows[0] || {};
    const rowFind = findingStats.rows[0] || {};

    return res.json({
      success: true,
      data: {
        summary: {
          totalScans: parseInt(rowScan.total_scans || '0', 10),
          averageScore: Math.round(parseFloat(rowScan.avg_score || '100')),
          averageCoverage: Math.round(parseFloat(rowScan.avg_coverage || '100')),
          completedScans: parseInt(rowScan.completed_scans || '0', 10),
          activeScans: parseInt(rowScan.active_scans || '0', 10),
        },
        findings: {
          critical: parseInt(rowFind.critical_count || '0', 10),
          high: parseInt(rowFind.high_count || '0', 10),
          medium: parseInt(rowFind.medium_count || '0', 10),
          low: parseInt(rowFind.low_count || '0', 10),
          info: parseInt(rowFind.info_count || '0', 10),
          resolved: parseInt(rowFind.resolved_count || '0', 10),
          total: parseInt(rowFind.total_findings || '0', 10),
        },
        latestScan,
      },
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: { code: 'SERVER_ERROR', message: 'Failed to fetch dashboard metrics.' },
    });
  }
}

export async function getDashboardTrends(req: AuthenticatedRequest, res: Response) {
  try {
    const userId = req.user!.id;
    const result = await query(
      `SELECT id, target_url, security_score, coverage_score, created_at, completed_at
       FROM scans WHERE user_id = $1 AND status = 'COMPLETED'
       ORDER BY created_at ASC LIMIT 10`,
      [userId]
    );

    return res.json({
      success: true,
      data: { trends: result.rows },
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: { code: 'SERVER_ERROR', message: 'Failed to fetch trends.' },
    });
  }
}
