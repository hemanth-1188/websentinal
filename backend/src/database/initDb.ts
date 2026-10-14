import { pool, testDbConnection, query } from './db';
import bcrypt from 'bcryptjs';

export async function initDb() {
  const isPg = await testDbConnection();

  if (isPg) {
    const client = await pool.connect();
    try {
      console.log('[DB] Initializing PostgreSQL Database Schema...');

      await client.query(`
        CREATE EXTENSION IF NOT EXISTS "pgcrypto";

        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(50) DEFAULT 'USER',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS scans (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID REFERENCES users(id) ON DELETE CASCADE,
            target_url VARCHAR(2048) NOT NULL,
            status VARCHAR(50) NOT NULL,
            scan_type VARCHAR(50) DEFAULT 'STANDARD',
            security_score INT DEFAULT 100,
            coverage_score INT DEFAULT 100,
            started_at TIMESTAMP WITH TIME ZONE,
            completed_at TIMESTAMP WITH TIME ZONE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS findings (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
            rule_id VARCHAR(100),
            title VARCHAR(255) NOT NULL,
            description TEXT NOT NULL,
            severity VARCHAR(50) NOT NULL,
            confidence VARCHAR(50) NOT NULL,
            status VARCHAR(50) DEFAULT 'CONFIRMED',
            owasp_category VARCHAR(10) NOT NULL,
            owasp_version VARCHAR(20) DEFAULT '2025',
            cwe VARCHAR(50),
            affected_url VARCHAR(2048) NOT NULL,
            evidence TEXT NOT NULL,
            impact TEXT NOT NULL,
            remediation TEXT NOT NULL,
            references TEXT,
            first_seen_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            resolved_at TIMESTAMP WITH TIME ZONE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );

        -- Safe Alter Migrations for Existing Tables
        ALTER TABLE findings ADD COLUMN IF NOT EXISTS rule_id VARCHAR(100);
        ALTER TABLE findings ADD COLUMN IF NOT EXISTS owasp_version VARCHAR(20) DEFAULT '2025';
        ALTER TABLE findings ADD COLUMN IF NOT EXISTS references TEXT;
        ALTER TABLE findings ADD COLUMN IF NOT EXISTS first_seen_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;
        ALTER TABLE findings ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;
        ALTER TABLE findings ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMP WITH TIME ZONE;
        ALTER TABLE scans ADD COLUMN IF NOT EXISTS coverage_score INT DEFAULT 100;

        CREATE TABLE IF NOT EXISTS technologies (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
            name VARCHAR(100) NOT NULL,
            version VARCHAR(50),
            category VARCHAR(100),
            confidence VARCHAR(50) DEFAULT 'HIGH'
        );

        CREATE TABLE IF NOT EXISTS owasp_results (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
            category VARCHAR(10) NOT NULL,
            status VARCHAR(50) NOT NULL,
            score INT DEFAULT 100,
            findings_count INT DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS reports (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
            file_path VARCHAR(1024) NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID REFERENCES users(id) ON DELETE SET NULL,
            action VARCHAR(255) NOT NULL,
            metadata JSONB,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );

        -- Indexes for fast lookup & comparison
        CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
        CREATE INDEX IF NOT EXISTS idx_findings_rule_id ON findings(rule_id);
        CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);
      `);

      const adminCheck = await client.query(`SELECT id FROM users WHERE email = 'admin@webshield.io'`);
      if (adminCheck.rows.length === 0) {
        const adminPass = await bcrypt.hash('Admin@123456', 10);
        const userPass = await bcrypt.hash('User@123456', 10);

        await client.query(
          `INSERT INTO users (name, email, password_hash, role) VALUES 
          ($1, $2, $3, $4),
          ($5, $6, $7, $8)`,
          [
            'System Administrator', 'admin@webshield.io', adminPass, 'ADMIN',
            'Security User', 'user@webshield.io', userPass, 'USER'
          ]
        );
      }
      console.log('[DB] PostgreSQL Schema Initialized');
    } finally {
      client.release();
    }
  } else {
    // Seed users in memory
    const adminCheck = await query(`SELECT id FROM users WHERE email = 'admin@webshield.io'`);
    if (adminCheck.rows.length === 0) {
      const adminPass = await bcrypt.hash('Admin@123456', 10);
      const userPass = await bcrypt.hash('User@123456', 10);

      await query(
        `INSERT INTO users (name, email, password_hash, role) VALUES ($1, $2, $3, $4)`,
        ['System Administrator', 'admin@webshield.io', adminPass, 'ADMIN']
      );
      await query(
        `INSERT INTO users (name, email, password_hash, role) VALUES ($1, $2, $3, $4)`,
        ['Security User', 'user@webshield.io', userPass, 'USER']
      );
      console.log('[DB] Seed users created in memory database: admin@webshield.io / Admin@123456');
    }
  }
}
