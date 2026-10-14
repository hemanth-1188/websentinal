import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { History, Eye, GitCompare, FileText, Search, Filter } from 'lucide-react';
import { Navbar } from '../components/Navbar';
import api from '../services/api';

export const ScanHistoryPage: React.FC = () => {
  const [scans, setScans] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');

  useEffect(() => {
    async function fetchHistory() {
      try {
        const res = await api.get('/scans');
        if (res.data.success) {
          setScans(res.data.data.scans);
        }
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    }
    fetchHistory();
  }, []);

  const filteredScans = scans.filter((s) => {
    if (statusFilter !== 'ALL' && s.status !== statusFilter) return false;
    if (searchQuery.trim() && !s.target_url.toLowerCase().includes(searchQuery.toLowerCase())) return false;
    return true;
  });

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', color: '#f8fafc' }}>
      <Navbar />

      <div style={{ maxWidth: '1240px', margin: '0 auto', padding: '2.5rem 1.5rem' }}>
        <div style={{ marginBottom: '2rem' }}>
          <h1 style={{ fontSize: '1.85rem', fontWeight: 800 }}>Scan History & Audit Trail</h1>
          <p style={{ color: '#94a3b8', fontSize: '0.9rem' }}>
            Historical security assessments, posture scores, and verifiable findings
          </p>
        </div>

        {/* Search & Filter Controls */}
        <div
          className="glass-card"
          style={{
            padding: '1rem 1.5rem',
            marginBottom: '1.5rem',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '1rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <span style={{ fontSize: '0.85rem', color: '#94a3b8', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <Filter size={15} /> Status:
            </span>
            {['ALL', 'COMPLETED', 'RUNNING', 'FAILED', 'PENDING'].map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                style={{
                  background: statusFilter === st ? '#e11d48' : 'rgba(255,255,255,0.05)',
                  border: '1px solid rgba(255,255,255,0.1)',
                  color: statusFilter === st ? '#ffffff' : '#94a3b8',
                  padding: '0.3rem 0.75rem',
                  borderRadius: '9999px',
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                {st}
              </button>
            ))}
          </div>

          <div style={{ position: 'relative' }}>
            <Search size={14} color="#64748b" style={{ position: 'absolute', left: '10px', top: '9px' }} />
            <input
              type="text"
              placeholder="Search by target URL..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                background: '#040508',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: '9999px',
                padding: '0.35rem 0.75rem 0.35rem 2rem',
                color: '#ffffff',
                fontSize: '0.8rem',
                outline: 'none',
                minWidth: '240px',
              }}
            />
          </div>
        </div>

        {loading ? (
          <div style={{ padding: '3rem', textAlign: 'center', color: '#94a3b8' }}>Loading Scan History...</div>
        ) : (
          <div className="glass-card" style={{ padding: '0', overflow: 'hidden' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.9rem' }}>
              <thead>
                <tr style={{ background: '#020617', borderBottom: '1px solid rgba(255,255,255,0.08)', color: '#94a3b8' }}>
                  <th style={{ padding: '1rem 1.25rem' }}>Target URL</th>
                  <th style={{ padding: '1rem 1.25rem' }}>Date</th>
                  <th style={{ padding: '1rem 1.25rem' }}>Score</th>
                  <th style={{ padding: '1rem 1.25rem' }}>Findings</th>
                  <th style={{ padding: '1rem 1.25rem' }}>Status</th>
                  <th style={{ padding: '1rem 1.25rem', textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredScans.length === 0 ? (
                  <tr>
                    <td colSpan={6} style={{ padding: '2.5rem', textAlign: 'center', color: '#64748b' }}>
                      No matching historical scans found.
                    </td>
                  </tr>
                ) : (
                  filteredScans.map((s) => (
                    <tr key={s.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                      <td style={{ padding: '1rem 1.25rem', fontWeight: 600 }}>{s.target_url}</td>
                      <td style={{ padding: '1rem 1.25rem', color: '#94a3b8' }}>
                        {new Date(s.created_at).toLocaleDateString()}
                      </td>
                      <td
                        style={{
                          padding: '1rem 1.25rem',
                          fontWeight: 800,
                          color: s.security_score >= 90 ? '#10b981' : s.security_score >= 75 ? '#f59e0b' : '#ef4444',
                        }}
                      >
                        {s.security_score}/100
                      </td>
                      <td style={{ padding: '1rem 1.25rem' }}>
                        <span style={{ color: '#ef4444', fontWeight: 700 }}>{s.critical_count || 0} Critical</span> |{' '}
                        <span style={{ color: '#f97316' }}>{s.high_count || 0} High</span> |{' '}
                        <span style={{ color: '#f59e0b' }}>{s.medium_count || 0} Med</span>
                      </td>
                      <td style={{ padding: '1rem 1.25rem' }}>
                        <span
                          className={`badge ${
                            s.status === 'COMPLETED' ? 'status-pass' : s.status === 'RUNNING' ? 'badge-info' : 'badge-critical'
                          }`}
                        >
                          {s.status}
                        </span>
                      </td>
                      <td style={{ padding: '1rem 1.25rem', textAlign: 'right' }}>
                        <Link to={`/scans/${s.id}`} className="btn-secondary" style={{ padding: '0.35rem 0.8rem', fontSize: '0.8rem' }}>
                          <Eye size={13} /> View
                        </Link>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
