import { MongoClient, Db, Collection } from 'mongodb';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';

dotenv.config();

const mongoUri = process.env.MONGODB_URI || 
  (process.env.DATABASE_URL && process.env.DATABASE_URL.startsWith('mongodb') 
    ? process.env.DATABASE_URL 
    : 'mongodb://localhost:27017/webshield_db');

export const client = new MongoClient(mongoUri, {
  serverSelectionTimeoutMS: 2000,
  connectTimeoutMS: 2000,
});

export let db: Db | null = null;
export let isMongoAvailable = false;

const dbFilePath = path.join(process.cwd(), 'data', 'webshield_dev_db.json');

// In-Memory Data Store Fallback with local file persistence when MongoDB is not reachable
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
    console.log(`[DB] Loaded ${memoryDb.users?.length || 0} users and ${memoryDb.scans?.length || 0} scans from dev persistence.`);
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

export function getDb(): Db {
  if (!db) {
    throw new Error('MongoDB is not connected. Call testDbConnection() first.');
  }
  return db;
}

export function getCollection<T extends Record<string, any> = any>(name: string): Collection<T> {
  return getDb().collection<T>(name);
}

export async function testDbConnection(): Promise<boolean> {
  try {
    await client.connect();
    const dbName = process.env.MONGO_DB || 'webshield_db';
    db = client.db(dbName);
    await db.command({ ping: 1 });
    isMongoAvailable = true;
    console.log(`[DB] Connected to MongoDB Database (${dbName})`);
    return true;
  } catch (err: any) {
    isMongoAvailable = false;
    console.log('[DB] MongoDB unavailable. Using Persisted In-Memory Database Fallback for local execution.');
    return false;
  }
}

export async function query(text: string, params: any[] = []): Promise<{ rows: any[]; rowCount: number }> {
  const trimmed = text.trim();
  const lower = trimmed.toLowerCase();

  // DDL Queries (No-op in document database)
  if (lower.startsWith('create table') || lower.startsWith('create extension') || lower.startsWith('create index') || lower.startsWith('alter table')) {
    return { rows: [], rowCount: 0 };
  }

  // ==========================================
  // 1. INSERT INTO users
  // ==========================================
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
    if (isMongoAvailable && db) {
      await db.collection('users').insertOne({ ...user });
    }
    memoryDb.users = memoryDb.users || [];
    memoryDb.users.push(user);
    saveMemoryDb();
    return { rows: [user], rowCount: 1 };
  }

  // ==========================================
  // 2. INSERT INTO scans
  // ==========================================
  if (lower.startsWith('insert into scans')) {
    const scan = {
      id: crypto.randomUUID(),
      user_id: params[0],
      target_url: params[1],
      status: params[2] || 'PENDING',
      scan_type: params[3] || 'STANDARD',
      security_score: params[4] !== undefined ? params[4] : 100,
      coverage_score: params[5] !== undefined ? params[5] : 100,
      started_at: null,
      completed_at: null,
      created_at: new Date().toISOString(),
    };
    if (isMongoAvailable && db) {
      await db.collection('scans').insertOne({ ...scan });
    }
    memoryDb.scans = memoryDb.scans || [];
    memoryDb.scans.push(scan);
    saveMemoryDb();
    return { rows: [scan], rowCount: 1 };
  }

  // ==========================================
  // 3. INSERT INTO findings
  // ==========================================
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
    if (isMongoAvailable && db) {
      await db.collection('findings').insertOne({ ...finding });
    }
    memoryDb.findings = memoryDb.findings || [];
    memoryDb.findings.push(finding);
    saveMemoryDb();
    return { rows: [finding], rowCount: 1 };
  }

  // ==========================================
  // 4. INSERT INTO technologies
  // ==========================================
  if (lower.startsWith('insert into technologies')) {
    const tech = {
      id: crypto.randomUUID(),
      scan_id: params[0],
      name: params[1],
      version: params[2] || null,
      category: params[3],
      confidence: params[4],
    };
    if (isMongoAvailable && db) {
      await db.collection('technologies').insertOne({ ...tech });
    }
    memoryDb.technologies = memoryDb.technologies || [];
    memoryDb.technologies.push(tech);
    saveMemoryDb();
    return { rows: [tech], rowCount: 1 };
  }

  // ==========================================
  // 5. INSERT INTO owasp_results
  // ==========================================
  if (lower.startsWith('insert into owasp_results')) {
    const owasp = {
      id: crypto.randomUUID(),
      scan_id: params[0],
      category: params[1],
      status: params[2],
      score: params[3],
      findings_count: params[4],
    };
    if (isMongoAvailable && db) {
      await db.collection('owasp_results').insertOne({ ...owasp });
    }
    memoryDb.owasp_results = memoryDb.owasp_results || [];
    memoryDb.owasp_results.push(owasp);
    saveMemoryDb();
    return { rows: [owasp], rowCount: 1 };
  }

  // ==========================================
  // 6. INSERT INTO reports
  // ==========================================
  if (lower.startsWith('insert into reports')) {
    const report = {
      id: crypto.randomUUID(),
      scan_id: params[0],
      file_path: params[1],
      created_at: new Date().toISOString(),
    };
    if (isMongoAvailable && db) {
      await db.collection('reports').insertOne({ ...report });
    }
    memoryDb.reports = memoryDb.reports || [];
    memoryDb.reports.push(report);
    saveMemoryDb();
    return { rows: [report], rowCount: 1 };
  }

  // ==========================================
  // 7. INSERT INTO audit_logs
  // ==========================================
  if (lower.startsWith('insert into audit_logs')) {
    const log = {
      id: crypto.randomUUID(),
      user_id: params[0],
      action: params[1],
      metadata: typeof params[2] === 'string' ? JSON.parse(params[2]) : params[2],
      created_at: new Date().toISOString(),
    };
    if (isMongoAvailable && db) {
      await db.collection('audit_logs').insertOne({ ...log });
    }
    memoryDb.audit_logs = memoryDb.audit_logs || [];
    memoryDb.audit_logs.push(log);
    saveMemoryDb();
    return { rows: [log], rowCount: 1 };
  }

  // ==========================================
  // 8. UPDATE scans SET status = ...
  // ==========================================
  if (lower.startsWith('update scans set status')) {
    const scanId = params[params.length - 1];
    const updateDoc: Record<string, any> = {};

    if (lower.includes('running')) {
      updateDoc.status = 'RUNNING';
      updateDoc.started_at = new Date().toISOString();
    } else if (lower.includes('completed')) {
      updateDoc.status = 'COMPLETED';
      if (params[0] !== undefined && typeof params[0] === 'number') {
        updateDoc.security_score = params[0];
      }
      if (params[1] !== undefined && typeof params[1] === 'number') {
        updateDoc.coverage_score = params[1];
      }
      updateDoc.completed_at = new Date().toISOString();
    } else if (lower.includes('failed')) {
      updateDoc.status = 'FAILED';
      updateDoc.completed_at = new Date().toISOString();
    } else if (lower.includes('cancelled')) {
      updateDoc.status = 'CANCELLED';
    }

    if (isMongoAvailable && db) {
      await db.collection('scans').updateOne({ id: scanId }, { $set: updateDoc });
      const scan = await db.collection('scans').findOne({ id: scanId }, { projection: { _id: 0 } });
      return { rows: scan ? [scan] : [], rowCount: scan ? 1 : 0 };
    }

    const scan = memoryDb.scans.find(s => s.id === scanId);
    if (scan) {
      Object.assign(scan, updateDoc);
      saveMemoryDb();
    }
    return { rows: scan ? [scan] : [], rowCount: scan ? 1 : 0 };
  }

  // ==========================================
  // 9. Admin & Stats Aggregations
  // ==========================================

  // Admin Top Vulnerabilities: SELECT title, owasp_category, severity, COUNT(*) as count FROM findings GROUP BY title, owasp_category, severity ORDER BY count DESC LIMIT 5
  if (lower.includes('from findings') && lower.includes('group by title, owasp_category, severity')) {
    if (isMongoAvailable && db) {
      const agg = await db.collection('findings').aggregate([
        { $group: { _id: { title: '$title', owasp_category: '$owasp_category', severity: '$severity' }, count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 5 },
        { $project: { _id: 0, title: '$_id.title', owasp_category: '$_id.owasp_category', severity: '$_id.severity', count: 1 } }
      ]).toArray();
      return { rows: agg, rowCount: agg.length };
    }
    const groupMap = new Map<string, { title: string; owasp_category: string; severity: string; count: number }>();
    memoryDb.findings.forEach(f => {
      const key = `${f.title}_${f.owasp_category}_${f.severity}`;
      if (!groupMap.has(key)) {
        groupMap.set(key, { title: f.title, owasp_category: f.owasp_category, severity: f.severity, count: 0 });
      }
      groupMap.get(key)!.count++;
    });
    const rows = Array.from(groupMap.values()).sort((a, b) => b.count - a.count).slice(0, 5);
    return { rows, rowCount: rows.length };
  }

  // Admin Audit Logs with Users join: SELECT a.*, u.email as user_email FROM audit_logs a LEFT JOIN users u ON a.user_id = u.id ORDER BY a.created_at DESC LIMIT 50
  if (lower.includes('from audit_logs')) {
    if (isMongoAvailable && db) {
      const agg = await db.collection('audit_logs').aggregate([
        { $sort: { created_at: -1 } },
        { $limit: 50 },
        {
          $lookup: {
            from: 'users',
            localField: 'user_id',
            foreignField: 'id',
            as: 'user'
          }
        },
        {
          $project: {
            _id: 0,
            id: 1,
            user_id: 1,
            action: 1,
            metadata: 1,
            created_at: 1,
            user_email: { $ifNull: [{ $arrayElemAt: ['$user.email', 0] }, 'System'] }
          }
        }
      ]).toArray();
      return { rows: agg, rowCount: agg.length };
    }
    const logs = memoryDb.audit_logs.map(a => {
      const u = memoryDb.users.find(usr => usr.id === a.user_id);
      return { ...a, user_email: u ? u.email : 'System' };
    });
    logs.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
    return { rows: logs.slice(0, 50), rowCount: Math.min(logs.length, 50) };
  }

  // Admin scans created today: SELECT COUNT(*) FROM scans WHERE created_at >= CURRENT_DATE
  if (lower.includes('count(*)') && lower.includes('from scans') && lower.includes('current_date')) {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const todayIso = today.toISOString();
    if (isMongoAvailable && db) {
      const count = await db.collection('scans').countDocuments({ created_at: { $gte: todayIso } });
      return { rows: [{ count: String(count) }], rowCount: 1 };
    }
    const count = memoryDb.scans.filter(s => s.created_at >= todayIso).length;
    return { rows: [{ count: String(count) }], rowCount: 1 };
  }

  // Average security score across all scans: SELECT COALESCE(AVG(security_score), 100) FROM scans
  if (lower.includes('avg(security_score)') && !lower.includes('user_id')) {
    if (isMongoAvailable && db) {
      const agg = await db.collection('scans').aggregate([
        { $group: { _id: null, avgScore: { $avg: '$security_score' } } }
      ]).toArray();
      const coalesce = agg.length > 0 && agg[0].avgScore !== null ? agg[0].avgScore : 100;
      return { rows: [{ coalesce: String(coalesce) }], rowCount: 1 };
    }
    const scores = memoryDb.scans.map(s => s.security_score).filter(s => s !== undefined && s !== null);
    const avg = scores.length ? scores.reduce((a, b) => a + b, 0) / scores.length : 100;
    return { rows: [{ coalesce: String(avg) }], rowCount: 1 };
  }

  // Dashboard User Scan Statistics: SELECT COUNT(*) as total_scans, COALESCE(AVG(security_score), 100) as avg_score, ... FROM scans WHERE user_id = $1
  if (lower.includes('from scans where user_id =') && lower.includes('avg_score')) {
    const userId = params[0];
    if (isMongoAvailable && db) {
      const stats = await db.collection('scans').aggregate([
        { $match: { user_id: userId } },
        {
          $group: {
            _id: null,
            total_scans: { $sum: 1 },
            avg_score: { $avg: '$security_score' },
            avg_coverage: { $avg: '$coverage_score' },
            completed_scans: { $sum: { $cond: [{ $eq: ['$status', 'COMPLETED'] }, 1, 0] } },
            active_scans: { $sum: { $cond: [{ $eq: ['$status', 'RUNNING'] }, 1, 0] } },
          }
        }
      ]).toArray();
      const res = stats[0] || { total_scans: 0, avg_score: 100, avg_coverage: 100, completed_scans: 0, active_scans: 0 };
      return {
        rows: [{
          total_scans: String(res.total_scans || 0),
          avg_score: String(res.avg_score ?? 100),
          avg_coverage: String(res.avg_coverage ?? 100),
          completed_scans: String(res.completed_scans || 0),
          active_scans: String(res.active_scans || 0),
        }],
        rowCount: 1,
      };
    }
    const userScans = memoryDb.scans.filter(s => s.user_id === userId);
    const completed = userScans.filter(s => s.status === 'COMPLETED');
    const running = userScans.filter(s => s.status === 'RUNNING');
    const avgScore = userScans.length ? userScans.reduce((acc, s) => acc + (s.security_score || 100), 0) / userScans.length : 100;
    const avgCov = userScans.length ? userScans.reduce((acc, s) => acc + (s.coverage_score || 100), 0) / userScans.length : 100;
    return {
      rows: [{
        total_scans: String(userScans.length),
        avg_score: String(avgScore),
        completed_scans: String(completed.length),
        active_scans: String(running.length),
        avg_coverage: String(avgCov),
      }],
      rowCount: 1,
    };
  }

  // Dashboard User Finding Statistics: SELECT COUNT(*) FILTER (WHERE f.severity = ...) FROM findings f JOIN scans s ON f.scan_id = s.id WHERE s.user_id = $1
  if (lower.includes('from findings f') && lower.includes('join scans s')) {
    const userId = params[0];
    if (isMongoAvailable && db) {
      const userScans = await db.collection('scans').find({ user_id: userId }, { projection: { id: 1 } }).toArray();
      const scanIds = userScans.map(s => s.id);
      const agg = await db.collection('findings').aggregate([
        { $match: { scan_id: { $in: scanIds } } },
        {
          $group: {
            _id: null,
            critical_count: { $sum: { $cond: [{ $and: [{ $eq: ['$severity', 'CRITICAL'] }, { $ne: ['$status', 'RESOLVED'] }] }, 1, 0] } },
            high_count: { $sum: { $cond: [{ $and: [{ $eq: ['$severity', 'HIGH'] }, { $ne: ['$status', 'RESOLVED'] }] }, 1, 0] } },
            medium_count: { $sum: { $cond: [{ $and: [{ $eq: ['$severity', 'MEDIUM'] }, { $ne: ['$status', 'RESOLVED'] }] }, 1, 0] } },
            low_count: { $sum: { $cond: [{ $and: [{ $eq: ['$severity', 'LOW'] }, { $ne: ['$status', 'RESOLVED'] }] }, 1, 0] } },
            info_count: { $sum: { $cond: [{ $and: [{ $eq: ['$severity', 'INFORMATIONAL'] }, { $ne: ['$status', 'RESOLVED'] }] }, 1, 0] } },
            resolved_count: { $sum: { $cond: [{ $eq: ['$status', 'RESOLVED'] }, 1, 0] } },
            total_findings: { $sum: 1 }
          }
        }
      ]).toArray();
      const res = agg[0] || { critical_count: 0, high_count: 0, medium_count: 0, low_count: 0, info_count: 0, resolved_count: 0, total_findings: 0 };
      return {
        rows: [{
          critical_count: String(res.critical_count || 0),
          high_count: String(res.high_count || 0),
          medium_count: String(res.medium_count || 0),
          low_count: String(res.low_count || 0),
          info_count: String(res.info_count || 0),
          resolved_count: String(res.resolved_count || 0),
          total_findings: String(res.total_findings || 0),
        }],
        rowCount: 1,
      };
    }
    const userScans = memoryDb.scans.filter(s => s.user_id === userId);
    const scanIds = new Set(userScans.map(s => s.id));
    const userFindings = memoryDb.findings.filter(f => scanIds.has(f.scan_id));
    return {
      rows: [{
        critical_count: String(userFindings.filter(f => f.severity === 'CRITICAL' && f.status !== 'RESOLVED').length),
        high_count: String(userFindings.filter(f => f.severity === 'HIGH' && f.status !== 'RESOLVED').length),
        medium_count: String(userFindings.filter(f => f.severity === 'MEDIUM' && f.status !== 'RESOLVED').length),
        low_count: String(userFindings.filter(f => f.severity === 'LOW' && f.status !== 'RESOLVED').length),
        info_count: String(userFindings.filter(f => f.severity === 'INFORMATIONAL' && f.status !== 'RESOLVED').length),
        resolved_count: String(userFindings.filter(f => f.status === 'RESOLVED').length),
        total_findings: String(userFindings.length),
      }],
      rowCount: 1,
    };
  }

  // Dashboard Trends: SELECT id, target_url, security_score, coverage_score, created_at, completed_at FROM scans WHERE user_id = $1 AND status = 'COMPLETED' ORDER BY created_at ASC LIMIT 10
  if (lower.includes('from scans where user_id =') && lower.includes("status = 'completed'") && lower.includes('order by created_at asc')) {
    const userId = params[0];
    if (isMongoAvailable && db) {
      const rows = await db.collection('scans').find(
        { user_id: userId, status: 'COMPLETED' },
        { projection: { _id: 0, id: 1, target_url: 1, security_score: 1, coverage_score: 1, created_at: 1, completed_at: 1 } }
      ).sort({ created_at: 1 }).limit(10).toArray();
      return { rows, rowCount: rows.length };
    }
    const userScans = memoryDb.scans.filter(s => s.user_id === userId && s.status === 'COMPLETED');
    userScans.sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());
    return { rows: userScans.slice(0, 10), rowCount: Math.min(userScans.length, 10) };
  }

  // Latest Scan for User: SELECT * FROM scans WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1
  if (lower.includes('from scans where user_id =') && lower.includes('order by created_at desc limit 1')) {
    const userId = params[0];
    if (isMongoAvailable && db) {
      const rows = await db.collection('scans').find({ user_id: userId }, { projection: { _id: 0 } }).sort({ created_at: -1 }).limit(1).toArray();
      return { rows, rowCount: rows.length };
    }
    const userScans = memoryDb.scans.filter(s => s.user_id === userId);
    userScans.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
    return { rows: userScans.slice(0, 1), rowCount: Math.min(userScans.length, 1) };
  }

  // Previous Scan for Same Target: SELECT id FROM scans WHERE user_id = $1 AND target_url = $2 AND id != $3 AND status = 'COMPLETED' ORDER BY created_at DESC LIMIT 1
  if (lower.includes('from scans where user_id =') && lower.includes('target_url =') && lower.includes('id !=')) {
    const [userId, targetUrl, excludeId] = params;
    if (isMongoAvailable && db) {
      const rows = await db.collection('scans').find(
        { user_id: userId, target_url: targetUrl, id: { $ne: excludeId }, status: 'COMPLETED' },
        { projection: { _id: 0, id: 1 } }
      ).sort({ created_at: -1 }).limit(1).toArray();
      return { rows, rowCount: rows.length };
    }
    const match = memoryDb.scans.filter(s => s.user_id === userId && s.target_url === targetUrl && s.id !== excludeId && s.status === 'COMPLETED');
    match.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
    return { rows: match.slice(0, 1), rowCount: Math.min(match.length, 1) };
  }

  // Scans List with Finding Counts: SELECT s.*, COUNT(f.id) FILTER ... FROM scans s LEFT JOIN findings f ON s.id = f.scan_id WHERE s.user_id = $1 GROUP BY s.id ORDER BY s.created_at DESC
  if (lower.includes('from scans s') && lower.includes('left join findings f')) {
    const userId = params[0];
    if (isMongoAvailable && db) {
      const userScans = await db.collection('scans').find({ user_id: userId }, { projection: { _id: 0 } }).sort({ created_at: -1 }).toArray();
      const scanIds = userScans.map(s => s.id);
      const allFindings = await db.collection('findings').find({ scan_id: { $in: scanIds } }, { projection: { _id: 0, scan_id: 1, severity: 1 } }).toArray();
      const formatted = userScans.map(s => {
        const scanFindings = allFindings.filter(f => f.scan_id === s.id);
        return {
          ...s,
          critical_count: scanFindings.filter(f => f.severity === 'CRITICAL').length,
          high_count: scanFindings.filter(f => f.severity === 'HIGH').length,
          medium_count: scanFindings.filter(f => f.severity === 'MEDIUM').length,
          low_count: scanFindings.filter(f => f.severity === 'LOW').length,
          info_count: scanFindings.filter(f => f.severity === 'INFORMATIONAL').length,
        };
      });
      return { rows: formatted, rowCount: formatted.length };
    }
    const userScans = memoryDb.scans.filter(s => s.user_id === userId);
    const formatted = userScans.map(s => {
      const scanFindings = memoryDb.findings.filter(f => f.scan_id === s.id);
      return {
        ...s,
        critical_count: scanFindings.filter(f => f.severity === 'CRITICAL').length,
        high_count: scanFindings.filter(f => f.severity === 'HIGH').length,
        medium_count: scanFindings.filter(f => f.severity === 'MEDIUM').length,
        low_count: scanFindings.filter(f => f.severity === 'LOW').length,
        info_count: scanFindings.filter(f => f.severity === 'INFORMATIONAL').length,
      };
    });
    formatted.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
    return { rows: formatted, rowCount: formatted.length };
  }

  // ==========================================
  // 10. General SELECT queries
  // ==========================================

  // SELECT * FROM users WHERE email = $1 / SELECT id FROM users WHERE email = $1
  if (lower.includes('from users where email =')) {
    if (isMongoAvailable && db) {
      const match = await db.collection('users').find({ email: params[0] }, { projection: { _id: 0 } }).toArray();
      return { rows: match, rowCount: match.length };
    }
    const match = memoryDb.users.filter(u => u.email === params[0]);
    return { rows: match, rowCount: match.length };
  }

  // SELECT * FROM users WHERE id = $1
  if (lower.includes('from users where id =')) {
    if (isMongoAvailable && db) {
      const match = await db.collection('users').find({ id: params[0] }, { projection: { _id: 0 } }).toArray();
      return { rows: match, rowCount: match.length };
    }
    const match = memoryDb.users.filter(u => u.id === params[0]);
    return { rows: match, rowCount: match.length };
  }

  // SELECT * FROM users
  if (lower.includes('from users')) {
    if (lower.includes('count(*)')) {
      if (isMongoAvailable && db) {
        const count = await db.collection('users').countDocuments();
        return { rows: [{ count: String(count) }], rowCount: 1 };
      }
      return { rows: [{ count: String(memoryDb.users.length) }], rowCount: 1 };
    }
    if (isMongoAvailable && db) {
      const rows = await db.collection('users').find({}, { projection: { _id: 0 } }).sort({ created_at: -1 }).toArray();
      return { rows, rowCount: rows.length };
    }
    return { rows: [...memoryDb.users], rowCount: memoryDb.users.length };
  }

  // SELECT * FROM scans WHERE id = $1 AND user_id = $2 OR SELECT * FROM scans WHERE id = $1
  if (lower.includes('from scans where id =')) {
    const targetId = params[0];
    const userId = params[1];
    if (isMongoAvailable && db) {
      const filter: Record<string, any> = { id: targetId };
      if (userId) filter.user_id = userId;
      const scan = await db.collection('scans').findOne(filter, { projection: { _id: 0 } });
      return { rows: scan ? [scan] : [], rowCount: scan ? 1 : 0 };
    }
    const scan = memoryDb.scans.find(s => s.id === targetId && (!userId || s.user_id === userId));
    return { rows: scan ? [scan] : [], rowCount: scan ? 1 : 0 };
  }

  // SELECT * FROM scans
  if (lower.includes('from scans')) {
    if (lower.includes('count(*)')) {
      if (isMongoAvailable && db) {
        const count = await db.collection('scans').countDocuments();
        return { rows: [{ count: String(count) }], rowCount: 1 };
      }
      return { rows: [{ count: String(memoryDb.scans.length) }], rowCount: 1 };
    }
    const userId = params[0];
    if (isMongoAvailable && db) {
      const filter = userId ? { user_id: userId } : {};
      const rows = await db.collection('scans').find(filter, { projection: { _id: 0 } }).sort({ created_at: -1 }).toArray();
      return { rows, rowCount: rows.length };
    }
    const userScans = userId ? memoryDb.scans.filter(s => s.user_id === userId) : memoryDb.scans;
    return { rows: [...userScans], rowCount: userScans.length };
  }

  // SELECT * FROM findings WHERE scan_id = $1
  if (lower.includes('from findings where scan_id =')) {
    const scanId = params[0];
    const sevOrder: Record<string, number> = { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4, INFORMATIONAL: 5 };
    if (isMongoAvailable && db) {
      const scanFindings = await db.collection('findings').find({ scan_id: scanId }, { projection: { _id: 0 } }).toArray();
      scanFindings.sort((a, b) => (sevOrder[a.severity] || 99) - (sevOrder[b.severity] || 99));
      return { rows: scanFindings, rowCount: scanFindings.length };
    }
    const scanFindings = memoryDb.findings.filter(f => f.scan_id === scanId);
    scanFindings.sort((a, b) => (sevOrder[a.severity] || 99) - (sevOrder[b.severity] || 99));
    return { rows: scanFindings, rowCount: scanFindings.length };
  }

  // SELECT * FROM findings
  if (lower.includes('from findings')) {
    if (isMongoAvailable && db) {
      const rows = await db.collection('findings').find({}, { projection: { _id: 0 } }).toArray();
      return { rows, rowCount: rows.length };
    }
    return { rows: [...memoryDb.findings], rowCount: memoryDb.findings.length };
  }

  // SELECT * FROM owasp_results WHERE scan_id = $1
  if (lower.includes('from owasp_results where scan_id =')) {
    const scanId = params[0];
    if (isMongoAvailable && db) {
      const res = await db.collection('owasp_results').find({ scan_id: scanId }, { projection: { _id: 0 } }).sort({ category: 1 }).toArray();
      return { rows: res, rowCount: res.length };
    }
    const res = memoryDb.owasp_results.filter(o => o.scan_id === scanId);
    res.sort((a, b) => (a.category || '').localeCompare(b.category || ''));
    return { rows: res, rowCount: res.length };
  }

  // SELECT * FROM technologies WHERE scan_id = $1
  if (lower.includes('from technologies where scan_id =')) {
    const scanId = params[0];
    if (isMongoAvailable && db) {
      const res = await db.collection('technologies').find({ scan_id: scanId }, { projection: { _id: 0 } }).toArray();
      return { rows: res, rowCount: res.length };
    }
    const res = memoryDb.technologies.filter(t => t.scan_id === scanId);
    return { rows: res, rowCount: res.length };
  }

  // SELECT * FROM reports WHERE id = $1
  if (lower.includes('from reports where id =')) {
    const reportId = params[0];
    if (isMongoAvailable && db) {
      const res = await db.collection('reports').find({ id: reportId }, { projection: { _id: 0 } }).toArray();
      return { rows: res, rowCount: res.length };
    }
    const res = memoryDb.reports.filter(r => r.id === reportId);
    return { rows: res, rowCount: res.length };
  }

  return { rows: [], rowCount: 0 };
}
