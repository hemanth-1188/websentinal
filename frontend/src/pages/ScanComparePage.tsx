import React, { useEffect, useState } from 'react';
import { GitCompare, TrendingUp, ShieldCheck, ArrowRight, CheckCircle2, AlertTriangle, Info } from 'lucide-react';
import { Navbar } from '../components/Navbar';
import api from '../services/api';

export const ScanComparePage: React.FC = () => {
  const [scans, setScans] = useState<any[]>([]);
  const [scan1Id, setScan1Id] = useState<string>('');
  const [scan2Id, setScan2Id] = useState<string>('');
  const [comparison, setComparison] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<'resolved' | 'persistent' | 'new'>('resolved');

  useEffect(() => {
    async function fetchScans() {
      try {
        const res = await api.get('/scans');
        if (res.data.success) {
          const list = res.data.data.scans;
          setScans(list);
          if (list.length >= 2) {
            setScan1Id(list[list.length - 1].id);
            setScan2Id(list[0].id);
          } else if (list.length === 1) {
            setScan1Id(list[0].id);
            setScan2Id(list[0].id);
          }
        }
      } catch (e) {
        console.error(e);
      }
    }
    fetchScans();
  }, []);

  const handleCompare = async () => {
    if (!scan1Id || !scan2Id) return;
    setLoading(true);
    try {
      const res = await api.get(`/scans/compare?base=${scan1Id}&target=${scan2Id}`);
      if (res.data.success) {
        setComparison(res.data.data);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', color: '#f8fafc' }}>
      <Navbar />

      <div style={{ maxWidth: '1240px', margin: '0 auto', padding: '2.5rem 1.5rem' }}>
        <div style={{ marginBottom: '2rem' }}>
          <h1 style={{ fontSize: '1.85rem', fontWeight: 800 }}>Scan Comparison & Finding Lifecycle</h1>
          <p style={{ color: '#94a3b8', fontSize: '0.9rem' }}>
            Verify remediations by comparing baseline findings against current re-scan results
          </p>
        </div>

        {/* Selection Form */}
        <div className="glass-card" style={{ marginBottom: '2rem' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.5rem', alignItems: 'end' }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 700, color: '#94a3b8', marginBottom: '0.5rem' }}>
                Baseline Scan (Earlier Assessment)
              </label>
              <select
                value={scan1Id}
                onChange={(e) => setScan1Id(e.target.value)}
                style={{
                  width: '100%',
                  background: '#040508',
                  border: '1px solid rgba(255,255,255,0.12)',
                  color: '#f8fafc',
                  padding: '0.75rem',
                  borderRadius: '10px',
                  fontSize: '0.9rem',
                }}
              >
                <option value="">Select Baseline Scan</option>
                {scans.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.target_url} — Score: {s.security_score} ({new Date(s.created_at).toLocaleDateString()})
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 700, color: '#94a3b8', marginBottom: '0.5rem' }}>
                Current Re-Scan (Verification Assessment)
              </label>
              <select
                value={scan2Id}
                onChange={(e) => setScan2Id(e.target.value)}
                style={{
                  width: '100%',
                  background: '#040508',
                  border: '1px solid rgba(255,255,255,0.12)',
                  color: '#f8fafc',
                  padding: '0.75rem',
                  borderRadius: '10px',
                  fontSize: '0.9rem',
                }}
              >
                <option value="">Select Current Scan</option>
                {scans.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.target_url} — Score: {s.security_score} ({new Date(s.created_at).toLocaleDateString()})
                  </option>
                ))}
              </select>
            </div>

            <button
              onClick={handleCompare}
              disabled={loading || !scan1Id || !scan2Id}
              className="btn-start-free-sm"
              style={{ height: '44px', width: '100%', justifyContent: 'center' }}
            >
              <GitCompare size={16} /> {loading ? 'Analyzing...' : 'Compare Scans'}
            </button>
          </div>
        </div>

        {/* Comparison Results */}
        {comparison && (
          <div>
            {/* Score Delta Highlight Banner */}
            <div
              className="glass-card"
              style={{
                background: comparison.scoreDiff >= 0 ? 'rgba(16, 185, 129, 0.08)' : 'rgba(225, 29, 72, 0.08)',
                borderColor: comparison.scoreDiff >= 0 ? 'rgba(16, 185, 129, 0.3)' : 'rgba(225, 29, 72, 0.3)',
                textAlign: 'center',
                padding: '2.5rem 1.5rem',
                marginBottom: '2rem',
              }}
            >
              <div style={{ fontSize: '0.85rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                Remediation Verification Delta
              </div>
              <div
                style={{
                  fontSize: '3rem',
                  fontWeight: 800,
                  color: comparison.scoreDiff >= 0 ? '#10b981' : '#ef4444',
                  margin: '0.5rem 0',
                }}
              >
                {comparison.scoreDiff >= 0 ? `+${comparison.scoreDiff}` : comparison.scoreDiff} Points
              </div>
              <div style={{ fontSize: '1.1rem', color: '#f8fafc', fontWeight: 600 }}>
                {comparison.remediatedCount} vulnerability findings confirmed RESOLVED on re-scan
              </div>
            </div>

            {/* Side by Side Metadata Cards */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.5rem', marginBottom: '2.5rem' }}>
              {/* Baseline */}
              <div className="glass-card">
                <div style={{ fontSize: '0.8rem', color: '#94a3b8', textTransform: 'uppercase', marginBottom: '0.75rem' }}>Baseline Assessment</div>
                <h3 style={{ fontSize: '1.2rem', fontWeight: 700, marginBottom: '0.4rem', color: '#ffffff' }}>{comparison.baselineScan.target_url}</h3>
                <div style={{ fontSize: '2.25rem', fontWeight: 800, color: comparison.baselineScan.security_score >= 75 ? '#f59e0b' : '#ef4444' }}>
                  {comparison.baselineScan.security_score} <span style={{ fontSize: '1rem', color: '#64748b' }}>/ 100</span>
                </div>
                <div style={{ color: '#94a3b8', fontSize: '0.85rem', marginTop: '0.75rem' }}>
                  Total Findings: <strong>{comparison.previousFindingsCount}</strong>
                </div>
              </div>

              {/* Current */}
              <div className="glass-card">
                <div style={{ fontSize: '0.8rem', color: '#38bdf8', textTransform: 'uppercase', marginBottom: '0.75rem' }}>Current Assessment</div>
                <h3 style={{ fontSize: '1.2rem', fontWeight: 700, marginBottom: '0.4rem', color: '#ffffff' }}>{comparison.currentScan.target_url}</h3>
                <div style={{ fontSize: '2.25rem', fontWeight: 800, color: comparison.currentScan.security_score >= 90 ? '#10b981' : '#f59e0b' }}>
                  {comparison.currentScan.security_score} <span style={{ fontSize: '1rem', color: '#64748b' }}>/ 100</span>
                </div>
                <div style={{ color: '#94a3b8', fontSize: '0.85rem', marginTop: '0.75rem' }}>
                  Active Findings: <strong>{comparison.currentFindingsCount}</strong>
                </div>
              </div>
            </div>

            {/* Detailed Findings Diff Tabs */}
            <div className="glass-card">
              <div style={{ display: 'flex', gap: '1rem', borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: '1rem', marginBottom: '1.5rem' }}>
                <button
                  onClick={() => setActiveTab('resolved')}
                  style={{
                    background: activeTab === 'resolved' ? 'rgba(16, 185, 129, 0.15)' : 'transparent',
                    border: activeTab === 'resolved' ? '1px solid rgba(16, 185, 129, 0.4)' : '1px solid transparent',
                    color: activeTab === 'resolved' ? '#6ee7b7' : '#94a3b8',
                    padding: '0.4rem 1rem',
                    borderRadius: '9999px',
                    fontSize: '0.85rem',
                    fontWeight: 600,
                    cursor: 'pointer',
                  }}
                >
                  ✓ Resolved ({comparison.resolvedFindings?.length || 0})
                </button>
                <button
                  onClick={() => setActiveTab('persistent')}
                  style={{
                    background: activeTab === 'persistent' ? 'rgba(245, 158, 11, 0.15)' : 'transparent',
                    border: activeTab === 'persistent' ? '1px solid rgba(245, 158, 11, 0.4)' : '1px solid transparent',
                    color: activeTab === 'persistent' ? '#fde047' : '#94a3b8',
                    padding: '0.4rem 1rem',
                    borderRadius: '9999px',
                    fontSize: '0.85rem',
                    fontWeight: 600,
                    cursor: 'pointer',
                  }}
                >
                  ⚠️ Persistent ({comparison.persistentFindings?.length || 0})
                </button>
                <button
                  onClick={() => setActiveTab('new')}
                  style={{
                    background: activeTab === 'new' ? 'rgba(225, 29, 72, 0.15)' : 'transparent',
                    border: activeTab === 'new' ? '1px solid rgba(225, 29, 72, 0.4)' : '1px solid transparent',
                    color: activeTab === 'new' ? '#fca5a5' : '#94a3b8',
                    padding: '0.4rem 1rem',
                    borderRadius: '9999px',
                    fontSize: '0.85rem',
                    fontWeight: 600,
                    cursor: 'pointer',
                  }}
                >
                  + New ({comparison.newFindings?.length || 0})
                </button>
              </div>

              {/* Tab Contents */}
              {activeTab === 'resolved' && (
                <div>
                  {(!comparison.resolvedFindings || comparison.resolvedFindings.length === 0) ? (
                    <div style={{ textAlign: 'center', padding: '2rem', color: '#64748b' }}>
                      No resolved findings detected between these two scans.
                    </div>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                      {comparison.resolvedFindings.map((f: any) => (
                        <div key={f.id || f.rule_id} style={{ background: 'rgba(16, 185, 129, 0.05)', border: '1px solid rgba(16, 185, 129, 0.25)', borderRadius: '12px', padding: '1.25rem' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                              <CheckCircle2 size={16} color="#10b981" />
                              <strong style={{ color: '#ffffff' }}>{f.title}</strong>
                              <span style={{ fontSize: '0.75rem', color: '#10b981', background: 'rgba(16,185,129,0.1)', padding: '0.2rem 0.5rem', borderRadius: '4px' }}>
                                RESOLVED
                              </span>
                            </div>
                            <span style={{ fontSize: '0.8rem', color: '#64748b', fontFamily: 'var(--font-mono)' }}>[{f.rule_id}]</span>
                          </div>
                          <p style={{ color: '#94a3b8', fontSize: '0.85rem', marginTop: '0.5rem' }}>{f.description}</p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'persistent' && (
                <div>
                  {(!comparison.persistentFindings || comparison.persistentFindings.length === 0) ? (
                    <div style={{ textAlign: 'center', padding: '2rem', color: '#10b981' }}>
                      Zero persistent findings! All previous vulnerabilities have been fixed.
                    </div>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                      {comparison.persistentFindings.map((f: any) => (
                        <div key={f.id || f.rule_id} style={{ background: 'rgba(245, 158, 11, 0.05)', border: '1px solid rgba(245, 158, 11, 0.25)', borderRadius: '12px', padding: '1.25rem' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                              <AlertTriangle size={16} color="#f59e0b" />
                              <strong style={{ color: '#ffffff' }}>{f.title}</strong>
                              <span style={{ fontSize: '0.75rem', color: '#f59e0b', background: 'rgba(245,158,11,0.1)', padding: '0.2rem 0.5rem', borderRadius: '4px' }}>
                                PERSISTENT [{f.severity}]
                              </span>
                            </div>
                            <span style={{ fontSize: '0.8rem', color: '#64748b', fontFamily: 'var(--font-mono)' }}>[{f.rule_id}]</span>
                          </div>
                          <p style={{ color: '#94a3b8', fontSize: '0.85rem', marginTop: '0.5rem' }}>{f.description}</p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'new' && (
                <div>
                  {(!comparison.newFindings || comparison.newFindings.length === 0) ? (
                    <div style={{ textAlign: 'center', padding: '2rem', color: '#64748b' }}>
                      No new security issues introduced in current scan.
                    </div>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                      {comparison.newFindings.map((f: any) => (
                        <div key={f.id || f.rule_id} style={{ background: 'rgba(225, 29, 72, 0.05)', border: '1px solid rgba(225, 29, 72, 0.25)', borderRadius: '12px', padding: '1.25rem' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                              <span className="badge badge-high">NEW</span>
                              <strong style={{ color: '#ffffff' }}>{f.title}</strong>
                            </div>
                            <span style={{ fontSize: '0.8rem', color: '#64748b', fontFamily: 'var(--font-mono)' }}>[{f.rule_id}]</span>
                          </div>
                          <p style={{ color: '#94a3b8', fontSize: '0.85rem', marginTop: '0.5rem' }}>{f.description}</p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
