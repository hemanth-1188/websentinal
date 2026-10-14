import { Pool } from 'pg';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';

dotenv.config();

const connectionString = process.env.DATABASE_URL || 'postgresql://webshield_user:webshield_pass@localhost:5432/webshield_db';

export const pool = new Pool({
  connectionString,
  max: 10,
  idleTimeoutMillis: 10000,
  connectionTimeoutMillis: 2000,
});

let isPostgresAvailable = false;

const dbFilePath = path.join(process.cwd(), 'data', 'webshield_dev_db.json');

// In-Memory Data Store Fallback with local file persistence
let memoryDb: Record<string, any[]> = {
  users: [],
  scans: [],
  findings: [],
  technologies: [],
  owasp_results: [],
  reports: [],
  audit_logs: [],
};

// Load persisted data if exists
try {
  if (fs.existsSync(dbFilePath)) {
    const raw = fs.readFileSync(dbFilePath, 'utf-8');
    memoryDb = { ...memoryDb, ...JSON.parse(raw) };
    console.log(`[DB] Loaded ${memoryDb.users.length} users and ${memoryDb.scans.length} scans from dev persistence.`);
  }
} catch (e) {
  console.error('[DB] Failed to load dev persistence:', e);
}

function saveMemoryDb() {
  try {
    const dir = path.dirname(dbFilePath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(dbFilePath, JSON.stringify(memoryDb, null, 2));
  } catch (e) {
    console.error('[DB] Failed to save dev persistence:', e);
  }
}

export async function testDbConnection(): Promise<boolean> {
  try {
    const client = await pool.connect();
    await client.query('SELECT 1');
    client.release();
    isPostgresAvailable = true;
    console.log('[DB] Connected to PostgreSQL Database');
    return true;
  } catch (err) {
    isPostgresAvailable = false;
    console.log('[DB] PostgreSQL unavailable. Using Persisted In-Memory Database Fallback for local execution.');
    return false;
  }
}

export async function query(text: string, params: any[] = []): Promise<{ rows: any[]; rowCount: number }> {
  if (isPostgresAvailable) {
    try {
      const res = await pool.query(text, params);
      return { rows: res.rows, rowCount: res.rowCount || 0 };
    } catch (e) {
      isPostgresAvailable = false;
    }
  }

  // --- Robust In-Memory Query Engine ---
  const trimmed = text.trim();
  const lower = trimmed.toLowerCase();

  // DDL Queries
  if (lower.startsWith('create table') || lower.startsWith('create extension') || lower.startsWith('create index')) {
    return { rows: [], rowCount: 0 };
  }

  // INSERT INTO users
  if (lower.startsWith('insert into users')) {
    const user = {
      id: crypto.randomUUID(),
      name: params[0],
      email: params[1],
      password_hash: params[2],
      role: params[3] || 'USER',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    memoryDb.users.push(user);
    saveMemoryDb();
    return { rows: [user], rowCount: 1 };
  }

  // INSERT INTO scans
  if (lower.startsWith('insert into scans')) {
    const scan = {
      id: crypto.randomUUID(),
      user_id: params[0],
      target_url: params[1],
      status: params[2] || 'PENDING',
      scan_type: params[3] || 'STANDARD',
      security_score: params[4] !== undefined ? params[4] : 100,
      started_at: null,
      completed_at: null,
      created_at: new Date().toISOString(),
    };
    memoryDb.scans.push(scan);
    saveMemoryDb();
    return { rows: [scan], rowCount: 1 };
  }

  // INSERT INTO findings
  if (lower.startsWith('insert into findings')) {
    const colMatch = text.match(/\((.*?)\)\s*values/i);
    let finding: Record<string, any> = {
      id: crypto.randomUUID(),
      created_at: new Date().toISOString(),
      first_seen_at: new Date().toISOString(),
      last_seen_at: new Date().toISOString(),
      resolved_at: null,
      owasp_version: '2025',
    };
    if (colMatch) {
      const cols = colMatch[1].split(',').map(c => c.trim().toLowerCase());
      cols.forEach((col, idx) => {
        finding[col] = params[idx];
      });
      if (!finding.rule_id) finding.rule_id = 'RULE-' + (finding.owasp_category || 'GENERIC');
    } else {
      finding = {
        ...finding,
        scan_id: params[0],
        title: params[1],
        description: params[2],
        severity: params[3],
        confidence: params[4],
        status: params[5] || 'CONFIRMED',
        owasp_category: params[6],
        cwe: params[7],
        affected_url: params[8],
        evidence: params[9],
        impact: params[10],
        remediation: params[11],
        rule_id: 'RULE-' + (params[6] || 'GENERIC'),
      };
    }
    memoryDb.findings.push(finding);
    saveMemoryDb();
    return { rows: [finding], rowCount: 1 };
  }

  // INSERT INTO technologies
  if (lower.startsWith('insert into technologies')) {
    const tech = {
      id: crypto.randomUUID(),
      scan_id: params[0],
      name: params[1],
      version: params[2],
      category: params[3],
      confidence: params[4],
    };
    memoryDb.technologies.push(tech);
    saveMemoryDb();
    return { rows: [tech], rowCount: 1 };
  }

  // INSERT INTO owasp_results
  if (lower.startsWith('insert into owasp_results')) {
    const owasp = {
      id: crypto.randomUUID(),
      scan_id: params[0],
      category: params[1],
      status: params[2],
      score: params[3],
      findings_count: params[4],
    };
    memoryDb.owasp_results.push(owasp);
    saveMemoryDb();
    return { rows: [owasp], rowCount: 1 };
  }

  // INSERT INTO reports
  if (lower.startsWith('insert into reports')) {
    const report = {
      id: crypto.randomUUID(),
      scan_id: params[0],
      file_path: params[1],
      created_at: new Date().toISOString(),
    };
    memoryDb.reports.push(report);
    saveMemoryDb();
    return { rows: [report], rowCount: 1 };
  }

  // INSERT INTO audit_logs
  if (lower.startsWith('insert into audit_logs')) {
    const log = {
      id: crypto.randomUUID(),
      user_id: params[0],
      action: params[1],
      metadata: typeof params[2] === 'string' ? JSON.parse(params[2]) : params[2],
      created_at: new Date().toISOString(),
    };
    memoryDb.audit_logs.push(log);
    saveMemoryDb();
    return { rows: [log], rowCount: 1 };
  }

  // UPDATE scans SET status = ...
  if (lower.startsWith('update scans set status')) {
    const scanId = params[params.length - 1];
    const scan = memoryDb.scans.find(s => s.id === scanId);
    if (scan) {
      if (lower.includes('running')) {
        scan.status = 'RUNNING';
        scan.started_at = new Date().toISOString();
      } else if (lower.includes('completed')) {
        scan.status = 'COMPLETED';
        if (params[0] !== undefined && typeof params[0] === 'number') {
          scan.security_score = params[0];
        }
        scan.completed_at = new Date().toISOString();
      } else if (lower.includes('failed')) {
        scan.status = 'FAILED';
        scan.completed_at = new Date().toISOString();
      } else if (lower.includes('cancelled')) {
        scan.status = 'CANCELLED';
      }
      saveMemoryDb();
    }
    return { rows: scan ? [scan] : [], rowCount: scan ? 1 : 0 };
  }

  // SELECT * FROM users WHERE email = $1
  if (lower.includes('from users where email =')) {
    const match = memoryDb.users.filter(u => u.email === params[0]);
    return { rows: match, rowCount: match.length };
  }

  // SELECT * FROM users WHERE id = $1
  if (lower.includes('from users where id =')) {
    const match = memoryDb.users.filter(u => u.id === params[0]);
    return { rows: match, rowCount: match.length };
  }

  // SELECT * FROM users
  if (lower.includes('from users')) {
    return { rows: [...memoryDb.users], rowCount: memoryDb.users.length };
  }

  // SELECT * FROM scans WHERE id = $1 AND user_id = $2 OR SELECT * FROM scans WHERE id = $1
  if (lower.includes('from scans where id =')) {
    const targetId = params[0];
    const userId = params[1];
    const scan = memoryDb.scans.find(s => s.id === targetId && (!userId || s.user_id === userId));
    return { rows: scan ? [scan] : [], rowCount: scan ? 1 : 0 };
  }

  // SELECT s.*, COUNT(...) FROM scans s ... WHERE s.user_id = $1
  if (lower.includes('from scans') && lower.includes('user_id =')) {
    const userScans = memoryDb.scans.filter(s => s.user_id === params[0]);
    const formatted = userScans.map(s => {
      const scanFindings = memoryDb.findings.filter(f => f.scan_id === s.id);
      return {
        ...s,
        critical_count: scanFindings.filter(f => f.severity === 'CRITICAL').length,
        high_count: scanFindings.filter(f => f.severity === 'HIGH').length,
        medium_count: scanFindings.filter(f => f.severity === 'MEDIUM').length,
        low_count: scanFindings.filter(f => f.severity === 'LOW').length,
      };
    });
    formatted.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
    return { rows: formatted, rowCount: formatted.length };
  }

  // SELECT * FROM scans
  if (lower.includes('from scans')) {
    const userScans = params[0] ? memoryDb.scans.filter(s => s.user_id === params[0]) : memoryDb.scans;
    return { rows: [...userScans], rowCount: userScans.length };
  }

  // SELECT * FROM findings WHERE scan_id = $1
  if (lower.includes('from findings where scan_id =')) {
    const scanFindings = memoryDb.findings.filter(f => f.scan_id === params[0]);
    return { rows: scanFindings, rowCount: scanFindings.length };
  }

  // SELECT * FROM findings
  if (lower.includes('from findings')) {
    return { rows: [...memoryDb.findings], rowCount: memoryDb.findings.length };
  }

  // SELECT * FROM owasp_results WHERE scan_id = $1
  if (lower.includes('from owasp_results where scan_id =')) {
    const res = memoryDb.owasp_results.filter(o => o.scan_id === params[0]);
    return { rows: res, rowCount: res.length };
  }

  // SELECT * FROM technologies WHERE scan_id = $1
  if (lower.includes('from technologies where scan_id =')) {
    const res = memoryDb.technologies.filter(t => t.scan_id === params[0]);
    return { rows: res, rowCount: res.length };
  }

  // SELECT * FROM reports WHERE id = $1
  if (lower.includes('from reports where id =')) {
    const res = memoryDb.reports.filter(r => r.id === params[0]);
    return { rows: res, rowCount: res.length };
  }

  // SELECT COUNT(*) FROM ...
  if (lower.includes('count(*)')) {
    if (lower.includes('from users')) return { rows: [{ count: memoryDb.users.length }], rowCount: 1 };
    if (lower.includes('from scans')) return { rows: [{ count: memoryDb.scans.length }], rowCount: 1 };
  }

  // SELECT a.*, u.email as user_email FROM audit_logs
  if (lower.includes('from audit_logs')) {
    const logs = memoryDb.audit_logs.map(a => {
      const u = memoryDb.users.find(usr => usr.id === a.user_id);
      return { ...a, user_email: u ? u.email : 'System' };
    });
    logs.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
    return { rows: logs, rowCount: logs.length };
  }

  return { rows: [], rowCount: 0 };
}
