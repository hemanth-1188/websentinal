import { testDbConnection, query, isMongoAvailable, getDb } from './db';
import bcrypt from 'bcryptjs';

export async function initDb() {
  const isConnected = await testDbConnection();

  if (isConnected && isMongoAvailable) {
    try {
      const db = getDb();
      console.log('[DB] Initializing MongoDB Collections & Indexes...');

      const usersCol = db.collection('users');
      const scansCol = db.collection('scans');
      const findingsCol = db.collection('findings');
      const techCol = db.collection('technologies');
      const owaspCol = db.collection('owasp_results');
      const reportsCol = db.collection('reports');
      const auditCol = db.collection('audit_logs');

      // Create Indexes
      await usersCol.createIndex({ email: 1 }, { unique: true });
      await scansCol.createIndex({ user_id: 1 });
      await scansCol.createIndex({ created_at: -1 });
      await findingsCol.createIndex({ scan_id: 1 });
      await findingsCol.createIndex({ rule_id: 1 });
      await findingsCol.createIndex({ severity: 1 });
      await techCol.createIndex({ scan_id: 1 });
      await owaspCol.createIndex({ scan_id: 1 });
      await reportsCol.createIndex({ scan_id: 1 });
      await auditCol.createIndex({ user_id: 1 });
      await auditCol.createIndex({ created_at: -1 });

      // Seed Users if empty
      const adminCheck = await usersCol.findOne({ email: 'admin@webshield.io' });
      if (!adminCheck) {
        const adminPass = await bcrypt.hash('Admin@123456', 10);
        const userPass = await bcrypt.hash('User@123456', 10);

        await usersCol.insertMany([
          {
            id: 'd9b939e1-e283-4217-bf45-d88fa7bca001',
            name: 'System Administrator',
            email: 'admin@webshield.io',
            password_hash: adminPass,
            role: 'ADMIN',
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          },
          {
            id: 'd9b939e1-e283-4217-bf45-d88fa7bca002',
            name: 'Security User',
            email: 'user@webshield.io',
            password_hash: userPass,
            role: 'USER',
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          },
        ]);
        console.log('[DB] Seed users created in MongoDB: admin@webshield.io / user@webshield.io');
      }
      console.log('[DB] MongoDB Collections & Indexes Initialized Successfully');
      return;
    } catch (err: any) {
      console.error('[DB] Error initializing MongoDB collections/indexes:', err.message);
    }
  }

  // Fallback: Seed users in persisted local database
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
    console.log('[DB] Seed users created in fallback database: admin@webshield.io / Admin@123456');
  }
}
