import { Response } from 'express';
import { query } from '../database/db';
import { AuthenticatedRequest } from '../middleware/auth';

export async function getAdminSummary(req: AuthenticatedRequest, res: Response) {
  try {
    const userCount = await query('SELECT COUNT(*) FROM users');
    const scanCount = await query('SELECT COUNT(*) FROM scans');
    const scansToday = await query('SELECT COUNT(*) FROM scans WHERE created_at >= CURRENT_DATE');
    const avgScore = await query('SELECT COALESCE(AVG(security_score), 100) FROM scans');

    const topFindings = await query(`
      SELECT title, owasp_category, severity, COUNT(*) as count 
      FROM findings 
      GROUP BY title, owasp_category, severity 
      ORDER BY count DESC LIMIT 5
    `);

    return res.json({
      success: true,
      data: {
        totalUsers: parseInt(userCount.rows[0].count, 10),
        totalScans: parseInt(scanCount.rows[0].count, 10),
        scansToday: parseInt(scansToday.rows[0].count, 10),
        averageScore: Math.round(parseFloat(avgScore.rows[0].coalesce)),
        topVulnerabilities: topFindings.rows,
      },
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: { code: 'SERVER_ERROR', message: 'Failed to fetch admin metrics.' },
    });
  }
}

export async function getUsers(req: AuthenticatedRequest, res: Response) {
  try {
    const result = await query('SELECT id, name, email, role, created_at FROM users ORDER BY created_at DESC');
    return res.json({ success: true, data: { users: result.rows } });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: { code: 'SERVER_ERROR', message: 'Failed to fetch users.' } });
  }
}

export async function getAuditLogs(req: AuthenticatedRequest, res: Response) {
  try {
    const result = await query(`
      SELECT a.*, u.email as user_email 
      FROM audit_logs a 
      LEFT JOIN users u ON a.user_id = u.id 
      ORDER BY a.created_at DESC LIMIT 50
    `);
    return res.json({ success: true, data: { auditLogs: result.rows } });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: { code: 'SERVER_ERROR', message: 'Failed to fetch audit logs.' } });
  }
}
