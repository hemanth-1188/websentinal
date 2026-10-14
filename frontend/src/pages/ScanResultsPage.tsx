import React, { useEffect, useState } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import {
  Shield,
  FileText,
  CheckCircle,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Download,
  ArrowLeft,
  Terminal,
  RefreshCw,
  Wrench,
  RotateCw,
  Code2,
  ExternalLink,
  Filter,
  Search
} from 'lucide-react';
import { Navbar } from '../components/Navbar';
import { ScoreGauge } from '../components/ScoreGauge';
import api from '../services/api';

export const ScanResultsPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [reportLoading, setReportLoading] = useState(false);
  const [rescanLoading, setRescanLoading] = useState(false);
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const [fetchError, setFetchError] = useState<string | null>(null);

  // Filters
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [categoryFilter, setCategoryFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  const fetchResults = async () => {
    setLoading(true);
    setFetchError(null);
    try {
      const res = await api.get(`/scans/${id}`);
      if (res.data.success) {
        setData(res.data.data);
      } else {
        setFetchError(res.data.error?.message || 'Unable to retrieve scan findings.');
      }
    } catch (e: any) {
      console.error(e);
      setFetchError(e.response?.data?.error?.message || 'Scan results not found.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchResults();
  }, [id]);

  const handleGenerateReport = async () => {
    setReportLoading(true);
    try {
      const res = await api.post(`/scans/${id}/reports`);
      if (res.data.success) {
        const reportId = res.data.data.report.id;
        const downloadRes = await api.get(`/reports/${reportId}/download`, { responseType: 'blob' });
        const blob = new Blob([downloadRes.data], { type: 'application/pdf' });
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        const targetClean = data?.scan?.target_url ? data.scan.target_url.replace(/[^a-zA-Z0-9]/g, '_') : id;
        link.setAttribute('download', `WebSentinel_Security_Report_${targetClean}.pdf`);
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.URL.revokeObjectURL(url);
      }
    } catch (e: any) {
      console.error(e);
      alert('Failed to generate PDF report: ' + (e.response?.data?.error?.message || e.message));
    } finally {
      setReportLoading(false);
    }
  };

  const handleDownloadJsonReport = async () => {
    try {
      const res = await api.get(`/scans/${id}/report`);
      if (res.data.success) {
        const jsonStr = JSON.stringify(res.data.data.report, null, 2);
        const blob = new Blob([jsonStr], { type: 'application/json' });
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.setAttribute('download', `WebSentinel_Report_${id}.json`);
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.URL.revokeObjectURL(url);
      }
    } catch (e: any) {
      alert('Failed to export JSON report: ' + e.message);
    }
  };

  const handleRescan = async () => {
    setRescanLoading(true);
    try {
      const res = await api.post(`/scans/${id}/rescan`);
      if (res.data.success && res.data.data.newScan) {
        navigate(`/scans/${res.data.data.newScan.id}/progress`);
      }
    } catch (e: any) {
      alert('Failed to queue re-scan: ' + (e.response?.data?.error?.message || e.message));
    } finally {
      setRescanLoading(false);
    }
  };

  if (loading) {
    return (
      <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', color: '#f8fafc' }}>
        <Navbar />
        <div style={{ padding: '6rem 2rem', textAlign: 'center', color: '#94a3b8' }}>
          <div style={{ fontSize: '1.2rem', fontWeight: 600 }}>Loading Security Assessment Results...</div>
        </div>
      </div>
    );
  }

  if (fetchError || !data || !data.scan) {
    return (
      <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', color: '#f8fafc' }}>
        <Navbar />
        <div style={{ maxWidth: '600px', margin: '6rem auto', padding: '0 1.5rem', textAlign: 'center' }}>
          <div className="glass-card" style={{ padding: '3rem' }}>
            <AlertTriangle size={48} color="#f59e0b" style={{ marginBottom: '1rem' }} />
            <h2 style={{ fontSize: '1.5rem', fontWeight: 800, marginBottom: '0.5rem' }}>Scan Result Unavailable</h2>
            <p style={{ color: '#94a3b8', fontSize: '0.95rem', marginBottom: '2rem' }}>
              {fetchError || 'Scan details could not be retrieved from system storage.'}
            </p>
            <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center' }}>
              <button onClick={fetchResults} className="btn-primary">
                <RefreshCw size={16} /> Retry Fetching Results
              </button>
              <Link to="/dashboard" className="btn-secondary">
                Back to Dashboard
              </Link>
            </div>
          </div>
        </div>
      </div>
    );
  }

  const { scan, findings = [], owaspResults = [], technologies = [] } = data;

  const severityBadges: Record<string, string> = {
    CRITICAL: 'badge-critical',
    HIGH: 'badge-high',
    MEDIUM: 'badge-medium',
    LOW: 'badge-low',
    INFORMATIONAL: 'badge-info',
  };

  const statusBadges: Record<string, string> = {
    PASS: 'status-pass',
    FAIL: 'status-fail',
    FINDING: 'status-fail',
    WARNING: 'status-warning',
    NOT_TESTED: 'status-manual',
    MANUAL_REVIEW: 'status-manual',
    MANUAL_REVIEW_REQUIRED: 'status-manual',
  };

  // Filter findings
  const filteredFindings = findings.filter((f: any) => {
    if (severityFilter !== 'ALL' && f.severity !== severityFilter) return false;
    if (categoryFilter !== 'ALL' && f.owasp_category !== categoryFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const match =
        f.title?.toLowerCase().includes(q) ||
        f.description?.toLowerCase().includes(q) ||
        f.rule_id?.toLowerCase().includes(q) ||
        f.evidence?.toLowerCase().includes(q);
      if (!match) return false;
    }
    return true;
  });

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', color: '#f8fafc' }}>
      <Navbar />

      <div style={{ maxWidth: '1240px', margin: '0 auto', padding: '2.5rem 1.5rem' }}>
        <Link
          to="/dashboard"
          style={{
            color: '#94a3b8',
            textDecoration: 'none',
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.4rem',
            fontSize: '0.9rem',
            marginBottom: '1.5rem',
          }}
        >
          <ArrowLeft size={16} /> Back to Dashboard
        </Link>

        {/* Top Header Card */}
        <div
          className="glass-card"
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: '2rem',
            flexWrap: 'wrap',
            gap: '1.5rem',
          }}
        >
          <div>
            <div style={{ fontSize: '0.8rem', color: '#e11d48', fontWeight: 800, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              Target Assessment Overview
            </div>
            <h1 style={{ fontSize: '2rem', fontWeight: 800, margin: '0.25rem 0' }}>{scan.target_url}</h1>
            <div style={{ fontSize: '0.85rem', color: '#94a3b8', display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
              <span>Scan ID: <code style={{ color: '#38bdf8' }}>{scan.id.slice(0, 8)}</code></span>
              <span>Completed: {new Date(scan.completed_at || scan.created_at).toLocaleString()}</span>
              <span>Coverage: <strong style={{ color: '#10b981' }}>{scan.coverage_score || 100}%</strong></span>
              <span>Profile: <strong>{scan.scan_type}</strong></span>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem', flexWrap: 'wrap' }}>
            <ScoreGauge score={scan.security_score} size={110} />
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
              <div style={{ display: 'flex', gap: '0.6rem' }}>
                <button onClick={handleGenerateReport} disabled={reportLoading} className="btn-primary" style={{ padding: '0.6rem 1.2rem', fontSize: '0.85rem' }}>
                  <Download size={15} /> {reportLoading ? 'Generating PDF...' : 'Download PDF'}
                </button>
                <button onClick={handleDownloadJsonReport} className="btn-secondary" style={{ padding: '0.6rem 1.2rem', fontSize: '0.85rem' }}>
                  <Code2 size={15} /> Export JSON
                </button>
              </div>
              <button
                onClick={handleRescan}
                disabled={rescanLoading}
                className="btn-start-free-sm"
                style={{ width: '100%', justifyContent: 'center' }}
              >
                <RotateCw size={14} /> {rescanLoading ? 'Queueing...' : 'Verify Fixes (Re-Scan)'}
              </button>
            </div>
          </div>
        </div>

        {/* Threat Summary Alert Banner */}
        {findings.length > 0 && (
          <div
            className="glass-card"
            style={{
              borderLeft: '4px solid #e11d48',
              marginBottom: '2rem',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
            }}
          >
            <div>
              <div style={{ fontWeight: 800, color: '#fca5a5', fontSize: '1.1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <AlertTriangle size={20} color="#ef4444" /> {findings.length} VERIFIABLE FINDINGS REQUIRING REMEDIATION
              </div>
              <p style={{ color: '#94a3b8', fontSize: '0.9rem', marginTop: '0.3rem' }}>
                Review technical evidence and actionable code remediation snippets below. Re-scan target upon applying patches to update your score.
              </p>
            </div>
          </div>
        )}

        {/* OWASP Top 10:2025 Matrix Status Grid */}
        <div style={{ marginBottom: '2.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
            <h2 style={{ fontSize: '1.35rem', fontWeight: 800 }}>OWASP Top 10:2025 Assessment Matrix</h2>
            <span style={{ fontSize: '0.8rem', color: '#64748b' }}>
              Standard: <strong>OWASP Top 10 (2025 Release)</strong>
            </span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem' }}>
            {owaspResults.map((ow: any) => {
              const status = ow.status;
              const displayStatus =
                status === 'NOT_TESTED' ? 'NOT TESTED' :
                status === 'MANUAL_REVIEW' || status === 'MANUAL_REVIEW_REQUIRED' ? 'MANUAL REVIEW' :
                status;

              return (
                <div key={ow.id || ow.category} className="glass-card" style={{ padding: '1.25rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                    <span style={{ fontWeight: 800, fontSize: '0.95rem', color: '#ffffff' }}>
                      {ow.category} <span style={{ color: '#64748b', fontSize: '0.8rem' }}>:2025</span>
                    </span>
                    <span className={`badge ${statusBadges[status] || 'status-manual'}`}>
                      {displayStatus}
                    </span>
                  </div>
                  <div style={{ fontSize: '0.8rem', color: '#94a3b8', marginBottom: '0.5rem' }}>
                    {ow.title || 'Security Domain'}
                  </div>
                  <div style={{ fontSize: '0.85rem', color: '#64748b' }}>
                    Findings: <strong style={{ color: ow.findings_count > 0 ? '#ef4444' : '#10b981' }}>{ow.findings_count}</strong>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Findings Filter Bar */}
        <div
          className="glass-card"
          style={{
            padding: '1rem 1.5rem',
            marginBottom: '1.5rem',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '1rem',
            flexWrap: 'wrap',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
            <span style={{ fontSize: '0.85rem', color: '#94a3b8', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <Filter size={15} /> Severity:
            </span>
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'].map(sev => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                style={{
                  background: severityFilter === sev ? '#e11d48' : 'rgba(255,255,255,0.05)',
                  border: '1px solid rgba(255,255,255,0.1)',
                  color: severityFilter === sev ? '#ffffff' : '#94a3b8',
                  padding: '0.3rem 0.75rem',
                  borderRadius: '9999px',
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                {sev}
              </button>
            ))}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <div style={{ position: 'relative' }}>
              <Search size={14} color="#64748b" style={{ position: 'absolute', left: '10px', top: '9px' }} />
              <input
                type="text"
                placeholder="Search findings..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                style={{
                  background: '#040508',
                  border: '1px solid rgba(255,255,255,0.1)',
                  borderRadius: '9999px',
                  padding: '0.35rem 0.75rem 0.35rem 2rem',
                  color: '#ffffff',
                  fontSize: '0.8rem',
                  outline: 'none',
                }}
              />
            </div>
          </div>
        </div>

        {/* Detailed Vulnerability Findings & Action Guidance */}
        <div style={{ marginBottom: '2.5rem' }}>
          <h2 style={{ fontSize: '1.35rem', fontWeight: 800, marginBottom: '1.25rem' }}>
            Technical Findings & Evidence ({filteredFindings.length})
          </h2>

          {filteredFindings.length === 0 ? (
            <div className="glass-card" style={{ textAlign: 'center', padding: '3rem', color: '#10b981' }}>
              <CheckCircle size={40} style={{ marginBottom: '0.75rem' }} />
              <div style={{ fontSize: '1.1rem', fontWeight: 700 }}>
                {findings.length === 0 ? 'All baseline security checks passed! Target is hardened.' : 'No findings match current filter criteria.'}
              </div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              {filteredFindings.map((finding: any) => {
                const isExpanded = expandedFinding === finding.id || expandedFinding === null;
                return (
                  <div
                    key={finding.id}
                    className="glass-card"
                    style={{
                      padding: '1.5rem',
                      borderLeft: `4px solid ${
                        finding.severity === 'CRITICAL' ? '#ef4444' :
                        finding.severity === 'HIGH' ? '#f97316' :
                        finding.severity === 'MEDIUM' ? '#f59e0b' : '#3b82f6'
                      }`,
                    }}
                  >
                    <div
                      onClick={() => setExpandedFinding(isExpanded ? '' : finding.id)}
                      style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer', flexWrap: 'wrap', gap: '0.75rem' }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                        <span className={`badge ${severityBadges[finding.severity] || 'badge-info'}`}>
                          {finding.severity}
                        </span>
                        <span style={{ fontWeight: 800, fontSize: '1.05rem', color: '#ffffff' }}>{finding.title}</span>
                        <span
                          style={{
                            fontSize: '0.75rem',
                            color: '#e11d48',
                            background: 'rgba(225, 29, 72, 0.1)',
                            border: '1px solid rgba(225, 29, 72, 0.25)',
                            padding: '0.2rem 0.5rem',
                            borderRadius: '6px',
                            fontFamily: 'var(--font-mono)',
                          }}
                        >
                          {finding.owasp_category}:2025
                        </span>
                        {finding.rule_id && (
                          <span style={{ fontSize: '0.75rem', color: '#64748b', fontFamily: 'var(--font-mono)' }}>
                            [{finding.rule_id}]
                          </span>
                        )}
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', color: '#94a3b8', fontSize: '0.85rem' }}>
                        <span>Confidence: <strong style={{ color: '#f8fafc' }}>{finding.confidence}</strong></span>
                        <span>Status: <strong style={{ color: finding.status === 'RESOLVED' ? '#10b981' : '#f59e0b' }}>{finding.status || 'CONFIRMED'}</strong></span>
                        {isExpanded ? <ChevronUp size={18} color="#e11d48" /> : <ChevronDown size={18} />}
                      </div>
                    </div>

                    {isExpanded && (
                      <div style={{ marginTop: '1.25rem', paddingTop: '1.25rem', borderTop: '1px solid var(--border-color)', fontSize: '0.925rem' }}>
                        {/* 1. Necessary Action Plan */}
                        <div
                          style={{
                            background: 'rgba(225, 29, 72, 0.08)',
                            border: '1px solid rgba(225, 29, 72, 0.25)',
                            borderRadius: '10px',
                            padding: '1rem',
                            marginBottom: '1.25rem',
                          }}
                        >
                          <div style={{ fontWeight: 800, color: '#f43f5e', fontSize: '0.875rem', display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.4rem' }}>
                            <Wrench size={15} /> Recommended Engineering Action:
                          </div>
                          <ol style={{ fontSize: '0.875rem', color: '#f8fafc', paddingLeft: '1.2rem', lineHeight: 1.6 }}>
                            <li>Inspect configuration directives on <code>{finding.affected_url}</code>.</li>
                            <li>Apply the remediation code snippet provided below to your server or code base.</li>
                            <li>Deploy changes and click <strong>Verify Fixes (Re-Scan)</strong> above to confirm resolution.</li>
                          </ol>
                        </div>

                        <div style={{ marginBottom: '1.25rem' }}>
                          <strong style={{ color: '#94a3b8', fontSize: '0.8rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Description:</strong>
                          <p style={{ marginTop: '0.3rem', color: '#f8fafc', lineHeight: 1.6 }}>{finding.description}</p>
                        </div>

                        {/* Technical Verifiable Evidence */}
                        <div style={{ marginBottom: '1.25rem' }}>
                          <strong style={{ color: '#94a3b8', fontSize: '0.8rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Technical Evidence (Sanitized):</strong>
                          <div className="code-block" style={{ marginTop: '0.4rem', background: '#020305' }}>
                            {finding.evidence}
                          </div>
                        </div>

                        <div style={{ marginBottom: '1.25rem' }}>
                          <strong style={{ color: '#94a3b8', fontSize: '0.8rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Security Impact:</strong>
                          <p style={{ marginTop: '0.3rem', color: '#fca5a5', lineHeight: 1.6 }}>{finding.impact}</p>
                        </div>

                        <div style={{ marginBottom: '1rem' }}>
                          <strong style={{ color: '#94a3b8', fontSize: '0.8rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Remediation Guidance & Snippet:</strong>
                          <div className="code-block" style={{ color: '#4ade80', marginTop: '0.4rem', background: '#020305' }}>
                            <Terminal size={15} style={{ display: 'inline', marginRight: '0.5rem', color: '#38bdf8' }} />
                            {finding.remediation}
                          </div>
                        </div>

                        {finding.references && (
                          <div style={{ fontSize: '0.8rem', color: '#64748b', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                            <span>Reference:</span>
                            <a href={finding.references} target="_blank" rel="noreferrer" style={{ color: '#38bdf8', textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: '0.2rem' }}>
                              {finding.references} <ExternalLink size={12} />
                            </a>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Technology Stack */}
        {technologies && technologies.length > 0 && (
          <div className="glass-card">
            <h3 style={{ fontSize: '1.15rem', fontWeight: 800, marginBottom: '1rem' }}>Identified Component Stack</h3>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem' }}>
              {technologies.map((t: any) => (
                <div
                  key={t.id || t.name}
                  style={{
                    background: '#040508',
                    border: '1px solid var(--border-color)',
                    padding: '0.5rem 1rem',
                    borderRadius: '8px',
                    fontSize: '0.85rem',
                  }}
                >
                  <span style={{ fontWeight: 700, color: '#f8fafc' }}>{t.name}</span>{' '}
                  <span style={{ color: '#94a3b8' }}>({t.category})</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
