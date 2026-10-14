import React, { useEffect, useState } from 'react';
import { Shield, Users, Activity, Lock, AlertTriangle } from 'lucide-react';
import { Navbar } from '../components/Navbar';
import api from '../services/api';

export const AdminDashboardPage: React.FC = () => {
  const [summary, setSummary] = useState<any>(null);
  const [users, setUsers] = useState<any[]>([]);
  const [auditLogs, setAuditLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchAdminData() {
      try {
        const [sumRes, userRes, auditRes] = await Promise.all([
          api.get('/admin/summary'),
          api.get('/admin/users'),
          api.get('/admin/audit-logs'),
        ]);

        if (sumRes.data.success) setSummary(sumRes.data.data);
        if (userRes.data.success) setUsers(userRes.data.data.users);
        if (auditRes.data.success) setAuditLogs(auditRes.data.data.auditLogs);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    }
    fetchAdminData();
  }, []);

  if (loading) {
    return (
      <div style={{ minHeight: '100vh', background: '#0b0f19', color: '#f8fafc' }}>
        <Navbar />
        <div style={{ padding: '4rem', textAlign: 'center', color: '#94a3b8' }}>Loading Admin Console...</div>
      </div>
    );
  }

  return (
    <div style={{ minHeight: '100vh', background: '#0b0f19', color: '#f8fafc' }}>
      <Navbar />

      <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '2.5rem 1.5rem' }}>
        <div style={{ marginBottom: '2rem' }}>
          <h1 style={{ fontSize: '1.85rem', fontWeight: 800, color: '#fca5a5', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Lock size={24} /> Admin Security Console
          </h1>
          <p style={{ color: '#94a3b8', fontSize: '0.9rem' }}>System telemetry, user permissions & platform audit logs</p>
        </div>

        {/* Summary Metric Cards */}
        {summary && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1.5rem', marginBottom: '2.5rem' }}>
            <div className="glass-card">
              <div style={{ fontSize: '0.85rem', color: '#94a3b8', textTransform: 'uppercase' }}>Registered Platform Users</div>
              <div style={{ fontSize: '2rem', fontWeight: 800, color: '#06b6d4', marginTop: '0.5rem' }}>{summary.totalUsers}</div>
            </div>

            <div className="glass-card">
              <div style={{ fontSize: '0.85rem', color: '#94a3b8', textTransform: 'uppercase' }}>Total Executed Scans</div>
              <div style={{ fontSize: '2rem', fontWeight: 800, color: '#3b82f6', marginTop: '0.5rem' }}>{summary.totalScans}</div>
            </div>

            <div className="glass-card">
              <div style={{ fontSize: '0.85rem', color: '#94a3b8', textTransform: 'uppercase' }}>Scans Today</div>
              <div style={{ fontSize: '2rem', fontWeight: 800, color: '#10b981', marginTop: '0.5rem' }}>{summary.scansToday}</div>
            </div>

            <div className="glass-card">
              <div style={{ fontSize: '0.85rem', color: '#94a3b8', textTransform: 'uppercase' }}>Global Average Score</div>
              <div style={{ fontSize: '2rem', fontWeight: 800, color: '#f59e0b', marginTop: '0.5rem' }}>{summary.averageScore}/100</div>
            </div>
          </div>
        )}

        {/* User Management Table */}
        <div className="glass-card" style={{ marginBottom: '2.5rem', padding: '0', overflow: 'hidden' }}>
          <div style={{ padding: '1.25rem', background: '#020617', borderBottom: '1px solid #1e293b', fontWeight: 700 }}>
            User Management & Roles
          </div>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.9rem' }}>
            <thead>
              <tr style={{ background: '#0f172a', color: '#94a3b8', borderBottom: '1px solid #1e293b' }}>
                <th style={{ padding: '0.75rem 1.25rem' }}>Name</th>
                <th style={{ padding: '0.75rem 1.25rem' }}>Email</th>
                <th style={{ padding: '0.75rem 1.25rem' }}>Role</th>
                <th style={{ padding: '0.75rem 1.25rem' }}>Created At</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id} style={{ borderBottom: '1px solid #1e293b' }}>
                  <td style={{ padding: '0.75rem 1.25rem', fontWeight: 600 }}>{u.name}</td>
                  <td style={{ padding: '0.75rem 1.25rem', color: '#94a3b8' }}>{u.email}</td>
                  <td style={{ padding: '0.75rem 1.25rem' }}>
                    <span className={`badge ${u.role === 'ADMIN' ? 'badge-critical' : 'badge-info'}`}>
                      {u.role}
                    </span>
                  </td>
                  <td style={{ padding: '0.75rem 1.25rem', color: '#64748b' }}>{new Date(u.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* System Audit Logs */}
        <div className="glass-card" style={{ padding: '0', overflow: 'hidden' }}>
          <div style={{ padding: '1.25rem', background: '#020617', borderBottom: '1px solid #1e293b', fontWeight: 700 }}>
            Audit Telemetry Logs
          </div>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
            <thead>
              <tr style={{ background: '#0f172a', color: '#94a3b8', borderBottom: '1px solid #1e293b' }}>
                <th style={{ padding: '0.75rem 1.25rem' }}>Timestamp</th>
                <th style={{ padding: '0.75rem 1.25rem' }}>User Email</th>
                <th style={{ padding: '0.75rem 1.25rem' }}>Action</th>
                <th style={{ padding: '0.75rem 1.25rem' }}>Metadata</th>
              </tr>
            </thead>
            <tbody>
              {auditLogs.map((log) => (
                <tr key={log.id} style={{ borderBottom: '1px solid #1e293b' }}>
                  <td style={{ padding: '0.75rem 1.25rem', color: '#94a3b8' }}>{new Date(log.created_at).toLocaleString()}</td>
                  <td style={{ padding: '0.75rem 1.25rem', fontWeight: 600 }}>{log.user_email || 'System'}</td>
                  <td style={{ padding: '0.75rem 1.25rem', color: '#06b6d4', fontWeight: 700 }}>{log.action}</td>
                  <td style={{ padding: '0.75rem 1.25rem', fontFamily: 'var(--font-mono)', color: '#94a3b8' }}>
                    {JSON.stringify(log.metadata)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
