import { Response } from 'express';
import { z } from 'zod';
import { query } from '../database/db';
import { AuthenticatedRequest } from '../middleware/auth';
import { validateTargetUrl } from '../security/ssrfGuardian';
import { scanQueueManager } from '../jobs/scanQueue';
import { redisStore } from '../services/redis';

const createScanSchema = z.object({
  target_url: z.string(),
  scan_type: z.enum(['QUICK', 'STANDARD', 'DEEP']).default('STANDARD'),
  is_authorized: z.literal(true, {
    errorMap: () => ({ message: 'You must confirm authorization before initiating a scan.' }),
  }),
});

export async function createScan(req: AuthenticatedRequest, res: Response) {
  try {
    const parse = createScanSchema.safeParse(req.body);
    if (!parse.success) {
      return res.status(400).json({
        success: false,
        error: { code: 'INVALID_INPUT', message: parse.error.errors[0].message },
      });
    }

    const { target_url, scan_type } = parse.data;
    const userId = req.user!.id;

    // Validate SSRF & Format Target
    const validation = await validateTargetUrl(target_url);
    if (!validation.isValid) {
      return res.status(400).json({
        success: false,
        error: { code: 'SSRF_PROTECTION_BLOCKED', message: validation.error },
      });
    }

    const normalizedUrl = validation.normalizedUrl || target_url;

    // Insert Scan Record into Database
    const dbRes = await query(
      `INSERT INTO scans (user_id, target_url, status, scan_type, security_score, coverage_score)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [userId, normalizedUrl, 'PENDING', scan_type, 100, 100]
    );

    const scan = dbRes.rows[0];

    // Enqueue Scan Job
    await scanQueueManager.addJob('execute-scan', {
      scanId: scan.id,
      targetUrl: normalizedUrl,
      scanType: scan_type,
      userId,
    });

    // Create Audit Log
    await query(
      `INSERT INTO audit_logs (user_id, action, metadata) VALUES ($1, $2, $3)`,
      [userId, 'CREATE_SCAN', JSON.stringify({ scanId: scan.id, targetUrl: normalizedUrl })]
    );

    return res.status(201).json({
      success: true,
      data: { scan },
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: { code: 'SERVER_ERROR', message: err.message || 'Failed to queue security scan.' },
    });
  }
}

export async function getScans(req: AuthenticatedRequest, res: Response) {
  try {
    const userId = req.user!.id;
    const result = await query(
      `SELECT s.*, 
        COUNT(f.id) FILTER (WHERE f.severity = 'CRITICAL') as critical_count,
        COUNT(f.id) FILTER (WHERE f.severity = 'HIGH') as high_count,
        COUNT(f.id) FILTER (WHERE f.severity = 'MEDIUM') as medium_count,
        COUNT(f.id) FILTER (WHERE f.severity = 'LOW') as low_count,
        COUNT(f.id) FILTER (WHERE f.severity = 'INFORMATIONAL') as info_count
       FROM scans s
       LEFT JOIN findings f ON s.id = f.scan_id
       WHERE s.user_id = $1
       GROUP BY s.id
       ORDER BY s.created_at DESC`,
      [userId]
    );

    return res.json({
      success: true,
      data: { scans: result.rows },
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: { code: 'SERVER_ERROR', message: 'Failed to fetch scans.' },
    });
  }
}

export async function getScanById(req: AuthenticatedRequest, res: Response) {
  try {
    const scanId = req.params.id;
    const userId = req.user!.id;

    // Fetch scan by ID
    const scanRes = await query('SELECT * FROM scans WHERE id = $1', [scanId]);
    if (scanRes.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: { code: 'NOT_FOUND', message: 'Scan not found.' },
      });
    }

    const scan = scanRes.rows[0];

    // Verify scan ownership or admin role
    if (scan.user_id !== userId && req.user!.role !== 'ADMIN') {
      return res.status(403).json({
        success: false,
        error: { code: 'FORBIDDEN', message: 'Access denied to this scan report.' },
      });
    }

    const findingsRes = await query(
      `SELECT * FROM findings WHERE scan_id = $1 
       ORDER BY CASE severity 
         WHEN 'CRITICAL' THEN 1 
         WHEN 'HIGH' THEN 2 
         WHEN 'MEDIUM' THEN 3 
         WHEN 'LOW' THEN 4 
         ELSE 5 
       END`,
      [scanId]
    );
    const owaspRes = await query('SELECT * FROM owasp_results WHERE scan_id = $1 ORDER BY category ASC', [scanId]);
    const techRes = await query('SELECT * FROM technologies WHERE scan_id = $1', [scanId]);

    return res.json({
      success: true,
      data: {
        scan,
        findings: findingsRes.rows,
        owaspResults: owaspRes.rows,
        technologies: techRes.rows,
      },
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: { code: 'SERVER_ERROR', message: 'Failed to fetch scan details.' },
    });
  }
}

export async function getFindings(req: AuthenticatedRequest, res: Response) {
  try {
    const scanId = req.params.id;
    const userId = req.user!.id;

    const scanRes = await query('SELECT * FROM scans WHERE id = $1', [scanId]);
    if (scanRes.rows.length === 0) {
      return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Scan not found.' } });
    }

    if (scanRes.rows[0].user_id !== userId && req.user!.role !== 'ADMIN') {
      return res.status(403).json({ success: false, error: { code: 'FORBIDDEN', message: 'Access denied.' } });
    }

    const findingsRes = await query('SELECT * FROM findings WHERE scan_id = $1', [scanId]);
    let findings = findingsRes.rows;

    // Optional query parameter filtering
    const { severity, confidence, owasp_category, status } = req.query;
    if (severity) findings = findings.filter(f => f.severity === String(severity).toUpperCase());
    if (confidence) findings = findings.filter(f => f.confidence === String(confidence).toUpperCase());
    if (owasp_category) findings = findings.filter(f => f.owasp_category === String(owasp_category).toUpperCase());
    if (status) findings = findings.filter(f => f.status === String(status).toUpperCase());

    return res.json({
      success: true,
      data: { findings, total: findings.length },
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: { code: 'SERVER_ERROR', message: 'Failed to fetch findings.' },
    });
  }
}

export async function getScanProgress(req: AuthenticatedRequest, res: Response) {
  try {
    const scanId = req.params.id;
    const progressData = await redisStore.get(`scan:progress:${scanId}`);

    if (!progressData) {
      const dbRes = await query('SELECT status, security_score FROM scans WHERE id = $1', [scanId]);
      if (dbRes.rows.length === 0) {
        return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Scan not found.' } });
      }
      const scan = dbRes.rows[0];
      return res.json({
        success: true,
        data: {
          step: scan.status === 'COMPLETED' ? 'Scan Completed' : scan.status,
          percent: scan.status === 'COMPLETED' ? 100 : 0,
        },
      });
    }

    return res.json({
      success: true,
      data: JSON.parse(progressData),
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: { code: 'SERVER_ERROR', message: 'Failed to fetch scan progress.' },
    });
  }
}

export async function cancelScan(req: AuthenticatedRequest, res: Response) {
  try {
    const scanId = req.params.id;
    await redisStore.setex(`scan:cancel:${scanId}`, 3600, 'true');
    await query(`UPDATE scans SET status = 'CANCELLED' WHERE id = $1`, [scanId]);

    return res.json({
      success: true,
      data: { message: 'Scan cancellation signal sent.' },
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: { code: 'SERVER_ERROR', message: 'Failed to cancel scan.' },
    });
  }
}

export async function rescanTarget(req: AuthenticatedRequest, res: Response) {
  try {
    const scanId = req.params.id;
    const userId = req.user!.id;

    const scanRes = await query('SELECT * FROM scans WHERE id = $1', [scanId]);
    if (scanRes.rows.length === 0) {
      return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Scan not found.' } });
    }

    const originalScan = scanRes.rows[0];
    if (originalScan.user_id !== userId && req.user!.role !== 'ADMIN') {
      return res.status(403).json({ success: false, error: { code: 'FORBIDDEN', message: 'Access denied.' } });
    }

    // Insert new scan
    const dbRes = await query(
      `INSERT INTO scans (user_id, target_url, status, scan_type, security_score, coverage_score)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [userId, originalScan.target_url, 'PENDING', originalScan.scan_type, 100, 100]
    );

    const newScan = dbRes.rows[0];

    // Enqueue
    await scanQueueManager.addJob('execute-scan', {
      scanId: newScan.id,
      targetUrl: originalScan.target_url,
      scanType: originalScan.scan_type,
      userId,
    });

    return res.status(201).json({
      success: true,
      data: {
        message: 'Re-scan successfully queued to verify finding remediation.',
        newScan,
      },
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: { code: 'SERVER_ERROR', message: 'Failed to trigger re-scan.' },
    });
  }
}

export async function getReportJson(req: AuthenticatedRequest, res: Response) {
  try {
    const scanId = req.params.id;
    const userId = req.user!.id;

    const scanRes = await query('SELECT * FROM scans WHERE id = $1', [scanId]);
    if (scanRes.rows.length === 0) {
      return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Scan not found.' } });
    }

    const scan = scanRes.rows[0];
    if (scan.user_id !== userId && req.user!.role !== 'ADMIN') {
      return res.status(403).json({ success: false, error: { code: 'FORBIDDEN', message: 'Access denied.' } });
    }

    const findings = (await query('SELECT * FROM findings WHERE scan_id = $1', [scanId])).rows;
    const owaspResults = (await query('SELECT * FROM owasp_results WHERE scan_id = $1', [scanId])).rows;
    const technologies = (await query('SELECT * FROM technologies WHERE scan_id = $1', [scanId])).rows;

    const severityCounts = {
      critical: findings.filter(f => f.severity === 'CRITICAL').length,
      high: findings.filter(f => f.severity === 'HIGH').length,
      medium: findings.filter(f => f.severity === 'MEDIUM').length,
      low: findings.filter(f => f.severity === 'LOW').length,
      informational: findings.filter(f => f.severity === 'INFORMATIONAL').length,
    };

    const report = {
      metadata: {
        scanner: 'WebShield / SIEGEPAL Security Engine',
        scanner_version: '2.0.0',
        ruleset_version: '2025.1.0',
        generated_at: new Date().toISOString(),
        scan_id: scan.id,
        target_url: scan.target_url,
        scan_type: scan.scan_type,
        started_at: scan.started_at,
        completed_at: scan.completed_at,
        security_score: scan.security_score,
        coverage_score: scan.coverage_score || 100,
        scope_and_limitations: 'Automated non-destructive assessment. Complex authentication flows require manual review.',
      },
      summary: {
        total_findings: findings.length,
        severity_distribution: severityCounts,
      },
      owasp_top_10_2025: owaspResults,
      findings,
      technologies,
    };

    return res.json({ success: true, data: { report } });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: { code: 'SERVER_ERROR', message: 'Failed to retrieve report data.' },
    });
  }
}

export async function compareScans(req: AuthenticatedRequest, res: Response) {
  try {
    const scan1Id = (req.query.base || req.query.scan1Id) as string;
    const scan2Id = (req.query.target || req.query.scan2Id) as string;

    if (!scan1Id || !scan2Id) {
      return res.status(400).json({
        success: false,
        error: { code: 'INVALID_INPUT', message: 'Both baseline and target scan IDs are required.' },
      });
    }

    const userId = req.user!.id;
    const scan1Res = await query('SELECT * FROM scans WHERE id = $1 AND user_id = $2', [scan1Id, userId]);
    const scan2Res = await query('SELECT * FROM scans WHERE id = $1 AND user_id = $2', [scan2Id, userId]);

    if (scan1Res.rows.length === 0 || scan2Res.rows.length === 0) {
      return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'One or both scans not found.' } });
    }

    const baselineScan = scan1Res.rows[0];
    const currentScan = scan2Res.rows[0];

    const f1Rows = (await query('SELECT * FROM findings WHERE scan_id = $1', [scan1Id])).rows;
    const f2Rows = (await query('SELECT * FROM findings WHERE scan_id = $1', [scan2Id])).rows;

    // Stable matching by rule_id and affected_url
    const keyFor = (f: any) => `${f.rule_id || f.title}_${f.affected_url}`;

    const baseKeys = new Map(f1Rows.map(f => [keyFor(f), f]));
    const currKeys = new Map(f2Rows.map(f => [keyFor(f), f]));

    const newFindings: any[] = [];
    const persistentFindings: any[] = [];
    const resolvedFindings: any[] = [];

    // Find new and persistent
    for (const [key, currFinding] of currKeys.entries()) {
      if (baseKeys.has(key)) {
        persistentFindings.push(currFinding);
      } else {
        newFindings.push(currFinding);
      }
    }

    // Find resolved (in baseline, but not in current)
    for (const [key, baseFinding] of baseKeys.entries()) {
      if (!currKeys.has(key)) {
        resolvedFindings.push({
          ...baseFinding,
          status: 'RESOLVED',
          resolved_at: currentScan.completed_at || new Date().toISOString(),
        });
      }
    }

    const scoreDiff = currentScan.security_score - baselineScan.security_score;

    return res.json({
      success: true,
      data: {
        baselineScan,
        currentScan,
        previousScan: baselineScan, // backwards compatibility
        scoreDiff,
        newFindings,
        persistentFindings,
        resolvedFindings,
        remediatedCount: resolvedFindings.length,
        previousFindingsCount: f1Rows.length,
        currentFindingsCount: f2Rows.length,
      },
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: { code: 'SERVER_ERROR', message: 'Scan comparison failed.' },
    });
  }
}

export async function remediateDemoTarget(req: AuthenticatedRequest, res: Response) {
  try {
    const scanId = req.params.id;
    const userId = req.user!.id;

    const scanRes = await query('SELECT * FROM scans WHERE id = $1', [scanId]);
    if (scanRes.rows.length === 0) {
      return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Scan not found.' } });
    }

    const scan = scanRes.rows[0];

    // Trigger toggle remediation on demo target
    try {
      const http = require('http');
      const reqDemo = http.request('http://localhost:8080/api/demo/toggle', { method: 'POST' }, () => {});
      reqDemo.on('error', () => {});
      reqDemo.end();
    } catch (e) {
      // Ignore network error if target is down
    }

    // Queue verification scan
    const dbRes = await query(
      `INSERT INTO scans (user_id, target_url, status, scan_type, security_score, coverage_score)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [userId, scan.target_url, 'PENDING', scan.scan_type, 100, 100]
    );

    const newScan = dbRes.rows[0];

    await scanQueueManager.addJob('execute-scan', {
      scanId: newScan.id,
      targetUrl: scan.target_url,
      scanType: scan.scan_type,
      userId,
    });

    return res.status(201).json({
      success: true,
      data: {
        message: 'Automated remediation applied on Local Training Target! Verification re-scan initiated.',
        newScan,
      },
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: { code: 'SERVER_ERROR', message: 'Failed to trigger automated remediation.' },
    });
  }
}
