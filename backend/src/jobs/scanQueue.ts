import { Queue, Worker, Job } from 'bullmq';
import { EventEmitter } from 'events';
import { redisClient } from '../services/redis';
import { Scanner } from '../scanner/core/Scanner';
import { query } from '../database/db';

const QUEUE_NAME = 'webshield-scan-queue';
const scanner = new Scanner();
const localQueueEmitter = new EventEmitter();

let isBullQueueActive = false;
let scanQueue: Queue | null = null;

try {
  scanQueue = new Queue(QUEUE_NAME, { connection: redisClient });
  scanQueue.on('error', () => {
    isBullQueueActive = false;
  });

  const worker = new Worker(
    QUEUE_NAME,
    async (job: Job) => {
      await processScanJob(job.data);
    },
    { connection: redisClient, concurrency: 5 }
  );
  worker.on('error', () => {
    isBullQueueActive = false;
  });

  isBullQueueActive = true;
} catch (e) {
  isBullQueueActive = false;
}

localQueueEmitter.on('process-job', async (data) => {
  try {
    await processScanJob(data);
  } catch (err: any) {
    console.error('[Local Queue] Job execution error:', err.message);
  }
});

async function processScanJob(data: { scanId: string; targetUrl: string; scanType: string; userId: string }) {
  const { scanId, targetUrl, scanType, userId } = data;
  console.log(`[Scan Queue] Processing job for scan ${scanId} (target: ${targetUrl})`);

  await query(`UPDATE scans SET status = 'RUNNING', started_at = CURRENT_TIMESTAMP WHERE id = $1`, [scanId]);

  try {
    const scanContext = await scanner.executeScan({
      scanId,
      targetUrl,
      scanType: (scanType as any) || 'STANDARD',
    });

    // 1. Fetch Previous Scan for same target to track finding lifecycles & resolution
    const prevScanRes = await query(
      `SELECT id FROM scans WHERE user_id = $1 AND target_url = $2 AND id != $3 AND status = 'COMPLETED' ORDER BY created_at DESC LIMIT 1`,
      [userId, targetUrl, scanId]
    );

    let previousFindings: any[] = [];
    if (prevScanRes.rows.length > 0) {
      const prevScanId = prevScanRes.rows[0].id;
      previousFindings = (await query(`SELECT * FROM findings WHERE scan_id = $1`, [prevScanId])).rows;
    }

    // 2. Persist Discovered Findings with First/Last Seen Timestamps
    for (const finding of scanContext.findings) {
      const prevMatch = previousFindings.find(
        pf => pf.rule_id === finding.rule_id && pf.affected_url === finding.affected_url
      );

      const firstSeen = prevMatch ? (prevMatch.first_seen_at || prevMatch.created_at) : new Date().toISOString();
      const lastSeen = new Date().toISOString();

      await query(
        `INSERT INTO findings (
           scan_id, rule_id, title, description, severity, confidence, status,
           owasp_category, owasp_version, cwe, affected_url, evidence, impact,
           remediation, references, first_seen_at, last_seen_at, resolved_at
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)`,
        [
          scanId,
          finding.rule_id,
          finding.title,
          finding.description,
          finding.severity,
          finding.confidence,
          finding.status || 'CONFIRMED',
          finding.owasp_category,
          finding.owasp_version || '2025',
          finding.cwe || null,
          finding.affected_url,
          finding.evidence,
          finding.impact,
          finding.remediation,
          finding.references || null,
          firstSeen,
          lastSeen,
          null,
        ]
      );
    }

    // 3. Persist Identified Technologies
    for (const tech of scanContext.technologies) {
      await query(
        `INSERT INTO technologies (scan_id, name, version, category, confidence) VALUES ($1, $2, $3, $4, $5)`,
        [scanId, tech.name, tech.version || null, tech.category, tech.confidence]
      );
    }

    // 4. Persist OWASP 2025 Assessment Results
    for (const owasp of scanContext.owaspResults) {
      await query(
        `INSERT INTO owasp_results (scan_id, category, status, score, findings_count) VALUES ($1, $2, $3, $4, $5)`,
        [scanId, owasp.category, owasp.status, owasp.score, owasp.findings_count]
      );
    }

    // 5. Update Scan Status, Security Score, and Coverage
    const coverageScore = Math.min(100, Math.round((scanContext.totalChecksExecuted / 18) * 100));

    await query(
      `UPDATE scans SET status = 'COMPLETED', security_score = $1, coverage_score = $2, completed_at = CURRENT_TIMESTAMP WHERE id = $3`,
      [scanContext.securityScore, coverageScore, scanId]
    );

    await query(
      `INSERT INTO audit_logs (user_id, action, metadata) VALUES ($1, $2, $3)`,
      [userId, 'SCAN_COMPLETED', JSON.stringify({ scanId, targetUrl, score: scanContext.securityScore, coverage: coverageScore })]
    );

    console.log(`[Scan Queue] Scan ${scanId} completed with score ${scanContext.securityScore} (Coverage: ${coverageScore}%)`);
  } catch (err: any) {
    console.error(`[Scan Queue] Scan ${scanId} failed:`, err.message);
    await query(`UPDATE scans SET status = 'FAILED', completed_at = CURRENT_TIMESTAMP WHERE id = $1`, [scanId]);
    await query(
      `INSERT INTO audit_logs (user_id, action, metadata) VALUES ($1, $2, $3)`,
      [userId, 'SCAN_FAILED', JSON.stringify({ scanId, targetUrl, error: err.message })]
    );
    throw err;
  }
}

export const scanQueueManager = {
  async addJob(jobName: string, data: { scanId: string; targetUrl: string; scanType: string; userId: string }): Promise<void> {
    if (isBullQueueActive && scanQueue) {
      try {
        await scanQueue.add(jobName, data);
        return;
      } catch (e) {
        isBullQueueActive = false;
      }
    }
    // Fallback: Dispatch via in-memory Event Queue
    setImmediate(() => {
      localQueueEmitter.emit('process-job', data);
    });
  }
};
