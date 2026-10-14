import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Shield, Loader2, XCircle, CheckCircle } from 'lucide-react';
import { Navbar } from '../components/Navbar';
import api from '../services/api';

export const ScanProgressPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [progress, setProgress] = useState<{ step: string; percent: number }>({ step: 'Initializing scan worker...', percent: 5 });
  const [cancelling, setCancelling] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    let interval: any;

    async function pollProgress() {
      try {
        const res = await api.get(`/scans/${id}/progress`);
        if (res.data.success) {
          const data = res.data.data;
          setProgress(data);

          if (data.percent >= 100) {
            clearInterval(interval);
            setTimeout(() => {
              navigate(`/scans/${id}`);
            }, 1000);
          }
        }
      } catch (e) {
        console.error(e);
      }
    }

    pollProgress();
    interval = setInterval(pollProgress, 1000);

    return () => clearInterval(interval);
  }, [id, navigate]);

  const handleCancel = async () => {
    setCancelling(true);
    try {
      await api.post(`/scans/${id}/cancel`);
      navigate('/dashboard');
    } catch (e) {
      console.error(e);
    } finally {
      setCancelling(false);
    }
  };

  const stepsList = [
    { label: 'Target validation & SSRF protection', p: 10 },
    { label: 'HTTP / HTTPS connection & headers', p: 25 },
    { label: 'Security headers analysis (CSP, HSTS, XFO)', p: 40 },
    { label: 'TLS / SSL certificate inspection', p: 50 },
    { label: 'Cookie security attributes (HttpOnly, Secure)', p: 60 },
    { label: 'Technology stack fingerprinting', p: 70 },
    { label: 'Information disclosure & path probes', p: 80 },
    { label: 'OWASP Top 10 mapping & risk scoring', p: 90 },
  ];

  return (
    <div style={{ minHeight: '100vh', background: '#0b0f19', color: '#f8fafc' }}>
      <Navbar />

      <div style={{ maxWidth: '800px', margin: '0 auto', padding: '4rem 1.5rem', textAlign: 'center' }}>
        <div style={{ display: 'inline-flex', background: 'rgba(6, 182, 212, 0.1)', padding: '1.25rem', borderRadius: '9999px', color: '#06b6d4', marginBottom: '1.5rem' }}>
          <Loader2 size={48} className="animate-spin" style={{ animation: 'spin 2s linear infinite' }} />
        </div>

        <h1 style={{ fontSize: '2rem', fontWeight: 800, marginBottom: '0.5rem' }}>Scan Execution In Progress</h1>
        <p style={{ color: '#94a3b8', fontSize: '0.95rem', marginBottom: '2.5rem' }}>Scan ID: <code style={{ color: '#06b6d4' }}>{id}</code></p>

        {/* Progress Bar */}
        <div style={{ background: '#1e293b', height: '14px', borderRadius: '9999px', overflow: 'hidden', marginBottom: '1.5rem', border: '1px solid #334155' }}>
          <div
            style={{
              height: '100%',
              width: `${Math.max(5, progress.percent)}%`,
              background: 'linear-gradient(90deg, #06b6d4, #3b82f6)',
              transition: 'width 0.4s ease',
              borderRadius: '9999px',
            }}
          />
        </div>

        <div style={{ fontSize: '1.1rem', fontWeight: 700, color: '#38bdf8', marginBottom: '3rem' }}>
          {progress.step} ({progress.percent}%)
        </div>

        {/* Steps List */}
        <div className="glass-card" style={{ textAlign: 'left', padding: '2rem', marginBottom: '2rem' }}>
          <div style={{ fontSize: '0.9rem', fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase', marginBottom: '1rem' }}>
            Assessment Stages
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {stepsList.map((st, idx) => {
              const isDone = progress.percent >= st.p;
              const isCurrent = progress.percent < st.p && (idx === 0 || progress.percent >= stepsList[idx - 1].p);
              return (
                <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: '1rem', opacity: isDone || isCurrent ? 1 : 0.4 }}>
                  {isDone ? (
                    <CheckCircle size={20} color="#10b981" />
                  ) : isCurrent ? (
                    <Loader2 size={20} color="#06b6d4" style={{ animation: 'spin 1.5s linear infinite' }} />
                  ) : (
                    <div style={{ width: '20px', height: '20px', borderRadius: '50%', border: '2px solid #64748b' }} />
                  )}
                  <span style={{ fontSize: '0.95rem', fontWeight: isCurrent ? 700 : 400, color: isCurrent ? '#06b6d4' : '#f8fafc' }}>
                    {st.label}
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        <button onClick={handleCancel} disabled={cancelling} className="btn-secondary" style={{ color: '#ef4444', borderColor: 'rgba(239,68,68,0.3)' }}>
          <XCircle size={18} /> {cancelling ? 'Cancelling...' : 'CANCEL SCAN'}
        </button>
      </div>

      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
};
