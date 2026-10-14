import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Shield, PlusCircle, AlertTriangle, CheckCircle, Clock, ExternalLink, ArrowUpRight, Activity } from 'lucide-react';
import { Navbar } from '../components/Navbar';
import { ScoreGauge } from '../components/ScoreGauge';
import api from '../services/api';

export const DashboardPage: React.FC = () => {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchDashboard() {
      try {
        const res = await api.get('/dashboard/summary');
        if (res.data.success) {
          setData(res.data.data);
        }
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    }
    fetchDashboard();
  }, []);

  if (loading) {
    return (
      <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', color: '#f8fafc' }}>
        <Navbar />
        <div style={{ padding: '4rem', textAlign: 'center', color: '#94a3b8' }}>Loading Security Dashboard...</div>
      </div>
    );
  }

  const { summary, findings, latestScan } = data || {
    summary: { totalScans: 0, averageScore: 100, completedScans: 0, activeScans: 0 },
    findings: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
    latestScan: null,
  };

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', color: '#f8fafc' }}>
      <Navbar />

      <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '2.5rem 1.5rem' }}>
        {/* Header Bar */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
          <div>
            <h1 style={{ fontSize: '1.85rem', fontWeight: 800 }}>Security Dashboard</h1>
            <p style={{ color: '#94a3b8', fontSize: '0.9rem' }}>Real-time posture & automated assessment metrics</p>
          </div>
          <Link to="/scans/new" className="btn-primary">
            <PlusCircle size={18} /> Start New Scan
          </Link>
        </div>

        {/* Metrics Grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.5rem', marginBottom: '2rem' }}>
          {/* Average Security Score Card */}
          <div className="glass-card" style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
            <ScoreGauge score={summary.averageScore} size={120} />
            <div>
              <div style={{ fontSize: '0.85rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Average Score</div>
              <div style={{ fontSize: '1.4rem', fontWeight: 800, marginTop: '0.2rem' }}>
                {summary.averageScore >= 90 ? 'Excellent' : summary.averageScore >= 75 ? 'Good' : summary.averageScore >= 60 ? 'Moderate' : 'Critical Risk'}
              </div>
              <div style={{ fontSize: '0.8rem', color: '#64748b', marginTop: '0.4rem' }}>Based on {summary.completedScans} completed scans</div>
            </div>
          </div>

          {/* Finding Severity Breakdown Card */}
          <div className="glass-card">
            <div style={{ fontSize: '0.85rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '1rem' }}>Active Vulnerabilities</div>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: '0.5rem' }}>
              <div style={{ textAlign: 'center', background: 'rgba(239, 68, 68, 0.1)', padding: '0.75rem', borderRadius: '8px', flex: 1 }}>
                <div style={{ color: '#ef4444', fontWeight: 800, fontSize: '1.25rem' }}>{findings.critical}</div>
                <div style={{ fontSize: '0.7rem', color: '#fca5a5' }}>CRITICAL</div>
              </div>
              <div style={{ textAlign: 'center', background: 'rgba(249, 115, 22, 0.1)', padding: '0.75rem', borderRadius: '8px', flex: 1 }}>
                <div style={{ color: '#f97316', fontWeight: 800, fontSize: '1.25rem' }}>{findings.high}</div>
                <div style={{ fontSize: '0.7rem', color: '#fdba74' }}>HIGH</div>
              </div>
              <div style={{ textAlign: 'center', background: 'rgba(245, 158, 11, 0.1)', padding: '0.75rem', borderRadius: '8px', flex: 1 }}>
                <div style={{ color: '#f59e0b', fontWeight: 800, fontSize: '1.25rem' }}>{findings.medium}</div>
                <div style={{ fontSize: '0.7rem', color: '#fde047' }}>MEDIUM</div>
              </div>
              <div style={{ textAlign: 'center', background: 'rgba(59, 130, 246, 0.1)', padding: '0.75rem', borderRadius: '8px', flex: 1 }}>
                <div style={{ color: '#3b82f6', fontWeight: 800, fontSize: '1.25rem' }}>{findings.low}</div>
                <div style={{ fontSize: '0.7rem', color: '#93c5fd' }}>LOW</div>
              </div>
            </div>
          </div>

          {/* Quick Stats */}
          <div className="glass-card">
            <div style={{ fontSize: '0.85rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '1rem' }}>Scan Activity</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.9rem' }}>
                <span style={{ color: '#94a3b8' }}>Total Scans Initiated:</span>
                <span style={{ fontWeight: 700 }}>{summary.totalScans}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.9rem' }}>
                <span style={{ color: '#94a3b8' }}>Avg Automated Coverage:</span>
                <span style={{ fontWeight: 700, color: '#10b981' }}>{summary.averageCoverage || 100}%</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.9rem' }}>
                <span style={{ color: '#94a3b8' }}>Resolved Findings:</span>
                <span style={{ fontWeight: 700, color: '#10b981' }}>{findings.resolved || 0}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.9rem' }}>
                <span style={{ color: '#94a3b8' }}>Active Open Findings:</span>
                <span style={{ fontWeight: 700, color: '#f59e0b' }}>{(findings.critical + findings.high + findings.medium + findings.low) || 0}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Latest Scan Overview */}
        <div className="glass-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
            <h3 style={{ fontSize: '1.1rem', fontWeight: 700 }}>Latest Assessment Result</h3>
            <Link to="/history" style={{ color: '#06b6d4', textDecoration: 'none', fontSize: '0.85rem' }}>View History →</Link>
          </div>

          {latestScan ? (
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '1rem', background: '#020617', borderRadius: '8px', border: '1px solid #1e293b' }}>
              <div>
                <div style={{ fontWeight: 700, fontSize: '1.1rem', color: '#f8fafc' }}>{latestScan.target_url}</div>
                <div style={{ fontSize: '0.8rem', color: '#64748b', marginTop: '0.2rem' }}>
                  Scan ID: {latestScan.id} | Type: {latestScan.scan_type} | Date: {new Date(latestScan.created_at).toLocaleDateString()}
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
                <div style={{ textAlign: 'right' }}>
                  <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Security Score</div>
                  <div style={{ fontSize: '1.25rem', fontWeight: 800, color: latestScan.security_score >= 90 ? '#10b981' : latestScan.security_score >= 75 ? '#f59e0b' : '#ef4444' }}>
                    {latestScan.security_score}/100
                  </div>
                </div>
                <Link to={`/scans/${latestScan.id}`} className="btn-secondary" style={{ fontSize: '0.85rem' }}>
                  View Full Findings
                </Link>
              </div>
            </div>
          ) : (
            <div style={{ textAlign: 'center', padding: '2rem', color: '#64748b' }}>
              No scans conducted yet. Initiate your first website security scan above.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
