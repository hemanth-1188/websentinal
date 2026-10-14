import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Lock, AlertTriangle, Play, CheckCircle } from 'lucide-react';
import { Navbar } from '../components/Navbar';
import api from '../services/api';

export const NewScanPage: React.FC = () => {
  const [targetUrl, setTargetUrl] = useState('');
  const [scanType, setScanType] = useState<'QUICK' | 'STANDARD' | 'DEEP'>('STANDARD');
  const [isAuthorized, setIsAuthorized] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const navigate = useNavigate();

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isAuthorized) {
      setError('You must explicitly confirm authorization before initiating a scan.');
      return;
    }

    setError(null);
    setSubmitting(true);

    try {
      const res = await api.post('/scans', {
        target_url: targetUrl,
        scan_type: scanType,
        is_authorized: true,
      });

      if (res.data.success) {
        const scanId = res.data.data.scan.id;
        navigate(`/scans/${scanId}/progress`);
      } else {
        setError(res.data.error.message);
      }
    } catch (err: any) {
      setError(err.response?.data?.error?.message || 'Failed to queue scan job.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', color: '#f8fafc' }}>
      <Navbar />

      <div style={{ maxWidth: '800px', margin: '0 auto', padding: '3rem 1.5rem' }}>
        <div style={{ marginBottom: '2rem' }}>
          <h1 style={{ fontSize: '2rem', fontWeight: 800 }}>Initiate Web Security Scan</h1>
          <p style={{ color: '#94a3b8', fontSize: '0.95rem' }}>Configure target parameters and authorization details</p>
        </div>

        {error && (
          <div style={{ background: 'rgba(239, 68, 68, 0.15)', border: '1px solid rgba(239, 68, 68, 0.3)', color: '#fca5a5', padding: '1rem', borderRadius: '8px', marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <AlertTriangle size={18} /> {error}
          </div>
        )}

        <form onSubmit={handleStartScan} className="glass-card" style={{ padding: '2.5rem' }}>
          {/* Target URL */}
          <div style={{ marginBottom: '2rem' }}>
            <label style={{ display: 'block', fontSize: '0.9rem', fontWeight: 700, marginBottom: '0.5rem' }}>
              Target Website URL <span style={{ color: '#ef4444' }}>*</span>
            </label>
            <input
              type="text"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://example.com"
              required
              style={{ width: '100%', background: '#020617', border: '1px solid #334155', color: '#f8fafc', padding: '0.85rem', borderRadius: '8px', fontSize: '1rem', outline: 'none' }}
            />
          </div>

          {/* Scan Profiles */}
          <div style={{ marginBottom: '2rem' }}>
            <label style={{ display: 'block', fontSize: '0.9rem', fontWeight: 700, marginBottom: '0.75rem' }}>
              Select Scan Profile
            </label>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem' }}>
              <div
                onClick={() => setScanType('QUICK')}
                style={{
                  background: scanType === 'QUICK' ? 'rgba(6, 182, 212, 0.15)' : '#020617',
                  border: scanType === 'QUICK' ? '2px solid #06b6d4' : '1px solid #334155',
                  padding: '1rem',
                  borderRadius: '8px',
                  cursor: 'pointer',
                  textAlign: 'center',
                }}
              >
                <div style={{ fontWeight: 700, fontSize: '0.95rem' }}>QUICK</div>
                <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginTop: '0.2rem' }}>Headers & TLS focus (~30s)</div>
              </div>

              <div
                onClick={() => setScanType('STANDARD')}
                style={{
                  background: scanType === 'STANDARD' ? 'rgba(6, 182, 212, 0.15)' : '#020617',
                  border: scanType === 'STANDARD' ? '2px solid #06b6d4' : '1px solid #334155',
                  padding: '1rem',
                  borderRadius: '8px',
                  cursor: 'pointer',
                  textAlign: 'center',
                }}
              >
                <div style={{ fontWeight: 700, fontSize: '0.95rem', color: '#38bdf8' }}>STANDARD (Default)</div>
                <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginTop: '0.2rem' }}>Full OWASP Top 10 (~1-2m)</div>
              </div>

              <div
                onClick={() => setScanType('DEEP')}
                style={{
                  background: scanType === 'DEEP' ? 'rgba(6, 182, 212, 0.15)' : '#020617',
                  border: scanType === 'DEEP' ? '2px solid #06b6d4' : '1px solid #334155',
                  padding: '1rem',
                  borderRadius: '8px',
                  cursor: 'pointer',
                  textAlign: 'center',
                }}
              >
                <div style={{ fontWeight: 700, fontSize: '0.95rem' }}>DEEP</div>
                <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginTop: '0.2rem' }}>Deep path analysis (~3m)</div>
              </div>
            </div>
          </div>

          {/* Safety & Limits Box */}
          <div style={{ background: '#020617', border: '1px solid #1e293b', borderRadius: '8px', padding: '1.25rem', marginBottom: '2rem' }}>
            <div style={{ fontWeight: 700, fontSize: '0.85rem', color: '#94a3b8', textTransform: 'uppercase', marginBottom: '0.5rem' }}>Enforced Safety Limits</div>
            <ul style={{ fontSize: '0.85rem', color: '#64748b', paddingLeft: '1.2rem', lineHeight: 1.6 }}>
              <li>Max Scan Duration: 5 minutes</li>
              <li>Max Requests per Assessment: 100 requests</li>
              <li>Rate Limit: 5 concurrent requests</li>
              <li>SSRF Protection: Internal subnets, loopbacks, and cloud metadata strictly blocked.</li>
            </ul>
          </div>

          {/* Mandatory Authorization Declaration */}
          <div style={{ background: 'rgba(245, 158, 11, 0.1)', border: '1px solid rgba(245, 158, 11, 0.3)', padding: '1.25rem', borderRadius: '8px', marginBottom: '2rem' }}>
            <div style={{ fontWeight: 700, color: '#fde047', fontSize: '0.9rem', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <Lock size={16} /> Defensive Use Authorization Requirement
            </div>
            <p style={{ fontSize: '0.85rem', color: '#cbd5e1', marginBottom: '1rem' }}>
              Only scan websites and systems that you own or have explicit, documented authorization to test.
            </p>
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', fontSize: '0.9rem', fontWeight: 600, color: '#f8fafc', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={isAuthorized}
                onChange={(e) => setIsAuthorized(e.target.checked)}
                style={{ width: '18px', height: '18px', accentColor: '#06b6d4' }}
              />
              I confirm that I am authorized to scan this target.
            </label>
          </div>

          <button
            type="submit"
            disabled={!isAuthorized || submitting}
            className="btn-primary"
            style={{ width: '100%', justifyContent: 'center', padding: '1rem', fontSize: '1rem', opacity: isAuthorized ? 1 : 0.5 }}
          >
            <Play size={18} /> {submitting ? 'Initiating Scan Engine...' : 'START SECURITY SCAN'}
          </button>
        </form>
      </div>
    </div>
  );
};
