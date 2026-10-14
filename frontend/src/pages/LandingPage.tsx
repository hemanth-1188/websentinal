import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Shield,
  Play,
  ArrowRight,
  Terminal,
  Lock,
  Search,
  AlertTriangle,
  Server,
  FileCode,
  CheckCircle2,
  Cpu,
  Layers,
  Zap,
  Globe,
  X,
  ExternalLink
} from 'lucide-react';
import { Navbar } from '../components/Navbar';

export const LandingPage: React.FC = () => {
  const [demoModalOpen, setDemoModalOpen] = useState(false);
  const [demoRunning, setDemoRunning] = useState(false);
  const [demoStep, setDemoStep] = useState(0);
  const navigate = useNavigate();

  const handleStartDemo = () => {
    setDemoModalOpen(true);
    setDemoRunning(true);
    setDemoStep(0);

    const stepInterval = setInterval(() => {
      setDemoStep((prev) => {
        if (prev >= 4) {
          clearInterval(stepInterval);
          setDemoRunning(false);
          return 4;
        }
        return prev + 1;
      });
    }, 1200);
  };

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg-primary)', color: '#f8fafc', overflowX: 'hidden' }}>
      <Navbar />

      {/* Hero Section */}
      <section
        style={{
          position: 'relative',
          padding: '5rem 1.5rem 5rem',
          maxWidth: '1280px',
          margin: '0 auto',
          textAlign: 'center',
        }}
      >

        {/* Main Headline */}
        <h1
          style={{
            fontSize: 'clamp(2.75rem, 6vw, 4.75rem)',
            fontWeight: 800,
            lineHeight: 1.12,
            letterSpacing: '-0.035em',
            color: '#ffffff',
            marginBottom: '1.75rem',
            maxWidth: '1000px',
            marginInline: 'auto',
          }}
        >
          WebSentinel
        </h1>

        {/* Subtitle */}
        <p
          style={{
            fontSize: 'clamp(1rem, 1.8vw, 1.15rem)',
            color: '#94a3b8',
            maxWidth: '720px',
            margin: '0 auto 2.5rem',
            lineHeight: 1.65,
          }}
        >
          Automate penetration testing, vulnerability management, and security operations
          with AI agents that think like hackers and defend like experts.
        </p>

        {/* Hero CTA Buttons */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '1.25rem',
            marginBottom: '4rem',
            flexWrap: 'wrap',
          }}
        >
          <Link to="/register" className="btn-start-free">
            Start Free
          </Link>
          <button onClick={handleStartDemo} className="btn-watch-demo">
            Watch Demo
          </button>
        </div>

        {/* Code Showcase Terminal Card */}
        <div
          style={{
            maxWidth: '860px',
            margin: '0 auto',
            position: 'relative',
          }}
        >
          <div className="code-showcase-card">
            {/* Window control dots */}
            <div className="code-dots-bar">
              <span className="code-dot dot-red" />
              <span className="code-dot dot-yellow" />
              <span className="code-dot dot-green" />
              <span
                style={{
                  marginLeft: '0.75rem',
                  fontSize: '0.75rem',
                  color: '#64748b',
                  fontFamily: 'var(--font-mono)',
                }}
              >
                agent-daemon.js — WebSentinel Autonomous Engine
              </span>
            </div>

            {/* Code snippet layout */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
                gap: '1.5rem',
                textAlign: 'left',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.85rem',
                lineHeight: 1.6,
              }}
            >
              {/* Left Column Code */}
              <div>
                <div>
                  <span className="t-tag">&lt;script&gt;</span>
                </div>
                <div>
                  <span className="t-paren">(()=&gt;&#123;</span>
                  <span className="t-kw">const </span>
                  <span className="t-var">data</span>
                  <span className="t-paren">=&#123;</span>
                </div>
                <div style={{ paddingLeft: '1.25rem' }}>
                  <span className="t-key">trustedBy</span>: <span className="t-str">"Trusted by 500+ security teams"</span>,
                </div>
                <div style={{ paddingLeft: '1.25rem' }}>
                  <span className="t-key">certs</span>: <span className="t-str">"SOC 2 Certified"</span>,
                </div>
                <div style={{ paddingLeft: '1.25rem' }}>
                  <span className="t-key">billing</span>: <span className="t-str">"No credit card required"</span>
                </div>
              </div>

              {/* Right Column Dispatch */}
              <div>
                <div>
                  <span className="t-paren">&#125;;</span>
                  <span className="t-fn">window.</span>
                  <span className="t-call">dispatchEvent</span>
                  <span className="t-paren">(</span>
                  <span className="t-kw">new </span>
                </div>
                <div>
                  <span className="t-class">CustomEvent</span>
                  <span className="t-paren">(</span>
                  <span className="t-str">"ScanningTarget"</span>
                  <span className="t-paren">,</span>
                </div>
                <div style={{ paddingLeft: '1.25rem' }}>
                  <span className="t-paren">&#123;</span>
                  <span className="t-key">detail</span>: <span className="t-var">data</span>
                  <span className="t-paren">&#125;));</span>
                </div>
                <div>
                  <span className="t-fn">console.</span>
                  <span className="t-call">info</span>
                  <span className="t-paren">(</span>
                  <span className="t-str">"ScanningTarget:"</span>
                  <span className="t-paren">, </span>
                  <span className="t-var">data</span>
                  <span className="t-paren">);&#125;)();</span>
                </div>
              </div>
            </div>

            {/* Overlapping Glass Detail Card */}
            <div
              style={{
                marginTop: '1.75rem',
                paddingTop: '1rem',
                borderTop: '1px solid rgba(255, 255, 255, 0.06)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: '1rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                <span className="live-dot" />
                <span style={{ fontSize: '0.825rem', color: '#94a3b8', fontWeight: 500 }}>
                  Agent Cluster Status: <strong style={{ color: '#22c55e' }}>ONLINE & DEFENDING</strong>
                </span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                <span style={{ fontSize: '0.8rem', color: '#64748b' }}>Target: http://localhost:8080 (Sandbox Target)</span>
                <Link
                  to="/scans/new"
                  style={{
                    color: '#e11d48',
                    textDecoration: 'none',
                    fontSize: '0.825rem',
                    fontWeight: 600,
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.3rem',
                  }}
                >
                  Launch Scan <ArrowRight size={13} />
                </Link>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Autonomous AI Agents Showcase */}
      <section id="agents" style={{ padding: '6rem 1.5rem', maxWidth: '1280px', margin: '0 auto' }}>
        <div style={{ textAlign: 'center', marginBottom: '4rem' }}>
          <div
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.5rem',
              background: 'rgba(225, 29, 72, 0.1)',
              border: '1px solid rgba(225, 29, 72, 0.3)',
              padding: '0.35rem 1rem',
              borderRadius: '9999px',
              color: '#f43f5e',
              fontSize: '0.825rem',
              fontWeight: 600,
              marginBottom: '1rem',
            }}
          >
            <Cpu size={14} /> WEBSENTINEL CYBER DEFENSE FLEET
          </div>
          <h2 style={{ fontSize: '2.5rem', fontWeight: 800, color: '#ffffff', marginBottom: '1rem' }}>
            Multi-Agent Architecture for Rapid Web Security
          </h2>
          <p style={{ color: '#94a3b8', maxWidth: '680px', margin: '0 auto', fontSize: '1.05rem' }}>
            Specialized WebSentinel modules work concurrently to inspect transport layers, test injection surfaces, and enforce OWASP Top 10 compliance.
          </p>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: '1.5rem' }}>
          <div className="glass-card">
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
              <div style={{ background: 'rgba(225, 29, 72, 0.15)', padding: '0.65rem', borderRadius: '12px', color: '#f43f5e' }}>
                <AlertTriangle size={24} />
              </div>
              <span className="badge badge-high">Agent 01</span>
            </div>
            <h3 style={{ fontSize: '1.25rem', fontWeight: 700, marginBottom: '0.5rem', color: '#ffffff' }}>Safe Injection Probe Agent</h3>
            <p style={{ color: '#94a3b8', fontSize: '0.9rem', lineHeight: 1.6, marginBottom: '1.25rem' }}>
              Deploys safe, non-destructive probe payloads to uncover reflected input parameters, database traceback disclosures, and XSS risks without mutating database state.
            </p>
            <div style={{ fontSize: '0.8rem', color: '#64748b', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <CheckCircle2 size={14} color="#10b981" /> Automated parameter reflection detection
            </div>
          </div>

          <div className="glass-card">
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
              <div style={{ background: 'rgba(59, 130, 246, 0.15)', padding: '0.65rem', borderRadius: '12px', color: '#3b82f6' }}>
                <Lock size={24} />
              </div>
              <span className="badge badge-low">Agent 02</span>
            </div>
            <h3 style={{ fontSize: '1.25rem', fontWeight: 700, marginBottom: '0.5rem', color: '#ffffff' }}>TLS & Transport Security Agent</h3>
            <p style={{ color: '#94a3b8', fontSize: '0.9rem', lineHeight: 1.6, marginBottom: '1.25rem' }}>
              Evaluates SSL/TLS certificate chains, expiration days, protocol negotiation (TLS 1.2 / 1.3), HTTPS downgrade prevention, and HSTS headers.
            </p>
            <div style={{ fontSize: '0.8rem', color: '#64748b', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <CheckCircle2 size={14} color="#10b981" /> Cipher suite & certificate verification
            </div>
          </div>

          <div className="glass-card">
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
              <div style={{ background: 'rgba(16, 185, 129, 0.15)', padding: '0.65rem', borderRadius: '12px', color: '#10b981' }}>
                <Shield size={24} />
              </div>
              <span className="badge badge-medium">Agent 03</span>
            </div>
            <h3 style={{ fontSize: '1.25rem', fontWeight: 700, marginBottom: '0.5rem', color: '#ffffff' }}>HTTP Security Headers Agent</h3>
            <p style={{ color: '#94a3b8', fontSize: '0.9rem', lineHeight: 1.6, marginBottom: '1.25rem' }}>
              Validates Content-Security-Policy (CSP), X-Frame-Options (Clickjacking defense), X-Content-Type-Options (MIME sniffing), and Referrer-Policy.
            </p>
            <div style={{ fontSize: '0.8rem', color: '#64748b', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <CheckCircle2 size={14} color="#10b981" /> Header remediation code snippets
            </div>
          </div>

          <div className="glass-card">
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
              <div style={{ background: 'rgba(245, 158, 11, 0.15)', padding: '0.65rem', borderRadius: '12px', color: '#f59e0b' }}>
                <Search size={24} />
              </div>
              <span className="badge badge-critical">Agent 04</span>
            </div>
            <h3 style={{ fontSize: '1.25rem', fontWeight: 700, marginBottom: '0.5rem', color: '#ffffff' }}>Information Disclosure Detective</h3>
            <p style={{ color: '#94a3b8', fontSize: '0.9rem', lineHeight: 1.6, marginBottom: '1.25rem' }}>
              Probes for leaked `.env.example`, `.git/HEAD`, database dumps, backup archives, debug endpoints, and secrets unintentionally left in production.
            </p>
            <div style={{ fontSize: '0.8rem', color: '#64748b', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <CheckCircle2 size={14} color="#10b981" /> High-confidence disclosure verification
            </div>
          </div>

          <div className="glass-card">
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
              <div style={{ background: 'rgba(168, 85, 247, 0.15)', padding: '0.65rem', borderRadius: '12px', color: '#a855f7' }}>
                <Server size={24} />
              </div>
              <span className="badge badge-info">Agent 05</span>
            </div>
            <h3 style={{ fontSize: '1.25rem', fontWeight: 700, marginBottom: '0.5rem', color: '#ffffff' }}>Technology Fingerprint Agent</h3>
            <p style={{ color: '#94a3b8', fontSize: '0.9rem', lineHeight: 1.6, marginBottom: '1.25rem' }}>
              Identifies backend servers (Nginx, Apache), web frameworks (Express, Next.js, Django), CMS stacks, and outdated libraries susceptible to known CVEs.
            </p>
            <div style={{ fontSize: '0.8rem', color: '#64748b', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <CheckCircle2 size={14} color="#10b981" /> Component version & surface profiling
            </div>
          </div>

          <div className="glass-card">
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
              <div style={{ background: 'rgba(236, 72, 153, 0.15)', padding: '0.65rem', borderRadius: '12px', color: '#ec4899' }}>
                <FileCode size={24} />
              </div>
              <span className="badge badge-high">Agent 06</span>
            </div>
            <h3 style={{ fontSize: '1.25rem', fontWeight: 700, marginBottom: '0.5rem', color: '#ffffff' }}>OWASP Top 10 Mapper & Auditor</h3>
            <p style={{ color: '#94a3b8', fontSize: '0.9rem', lineHeight: 1.6, marginBottom: '1.25rem' }}>
              Aggregates all findings directly into OWASP A01-A10 categories with compliance scores and generates downloadable PDF audit reports with remediation steps.
            </p>
            <div style={{ fontSize: '0.8rem', color: '#64748b', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <CheckCircle2 size={14} color="#10b981" /> Executive & engineering PDF exports
            </div>
          </div>
        </div>
      </section>

      {/* Interactive Quick Scan Sandbox Section */}
      <section style={{ background: 'rgba(11, 13, 20, 0.7)', borderTop: '1px solid rgba(255,255,255,0.06)', borderBottom: '1px solid rgba(255,255,255,0.06)', padding: '5rem 1.5rem' }}>
        <div style={{ maxWidth: '960px', margin: '0 auto', textAlign: 'center' }}>
          <h2 style={{ fontSize: '2.25rem', fontWeight: 800, color: '#ffffff', marginBottom: '1rem' }}>
            Experience the WebSentinel Scanner in 1 Click
          </h2>
          <p style={{ color: '#94a3b8', fontSize: '1.05rem', marginBottom: '2.5rem' }}>
            Our built-in training target is running locally at <code style={{ color: '#38bdf8' }}>http://localhost:8080</code>. Launch a scan right away to discover intentional vulnerabilities and test remediation.
          </p>

          <div
            style={{
              background: '#090a10',
              border: '1px solid rgba(255, 255, 255, 0.12)',
              borderRadius: '9999px',
              padding: '0.5rem 0.65rem 0.5rem 1.5rem',
              display: 'flex',
              alignItems: 'center',
              gap: '1rem',
              maxWidth: '680px',
              margin: '0 auto 1.5rem',
              boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
            }}
          >
            <Globe size={20} color="#64748b" />
            <input
              type="text"
              readOnly
              value="http://localhost:8080"
              style={{
                flex: 1,
                background: 'transparent',
                border: 'none',
                color: '#ffffff',
                fontFamily: 'var(--font-mono)',
                fontSize: '1rem',
                outline: 'none',
              }}
            />
            <Link to="/scans/new" className="btn-start-free-sm" style={{ padding: '0.75rem 1.75rem' }}>
              Launch Full Scan <ArrowRight size={14} />
            </Link>
          </div>

          <div style={{ display: 'flex', justifyContent: 'center', gap: '2rem', color: '#64748b', fontSize: '0.85rem' }}>
            <span>✓ Pre-configured Vulnerable Target</span>
            <span>✓ Safe SSRF Guard Enforced</span>
            <span>✓ Zero Rate Limit on Local Sandbox</span>
          </div>
        </div>
      </section>


      {/* Docs / Compliance Section */}
      <section id="docs" style={{ padding: '4rem 1.5rem', background: 'rgba(8, 10, 16, 0.7)', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
        <div style={{ maxWidth: '1080px', margin: '0 auto', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '2rem' }}>
          <div>
            <h3 style={{ fontSize: '1.5rem', fontWeight: 700, color: '#ffffff', marginBottom: '0.5rem' }}>
              Built for Responsible & Defensive Assessment
            </h3>
            <p style={{ color: '#94a3b8', maxWidth: '600px', fontSize: '0.925rem' }}>
              All scans strictly enforce protocol restrictions, IP blocklists, and target authorization verification before execution.
            </p>
          </div>
          <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
            <span className="pill-chip"><Shield size={14} color="#10b981" /> SSRF Guardian</span>
            <span className="pill-chip"><CheckCircle2 size={14} color="#3b82f6" /> Non-Destructive</span>
            <span className="pill-chip"><Lock size={14} color="#f59e0b" /> RBAC Protected</span>
          </div>
        </div>
      </section>

      {/* Modern Sleek Footer */}
      <footer id="contact" style={{ padding: '3.5rem 2rem 2.5rem', borderTop: '1px solid rgba(255,255,255,0.06)', background: '#050608' }}>
        <div style={{ maxWidth: '1280px', margin: '0 auto', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1.5rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
              <span style={{ fontWeight: 800, fontSize: '1.15rem', color: '#ffffff' }}>WEBSENTINEL</span>
              <span style={{ fontSize: '0.75rem', color: '#64748b' }}>Security Platform</span>
            </div>
            <p style={{ color: '#64748b', fontSize: '0.85rem' }}>
              WebSentinel — Web Security Assessment & Vulnerability Defense Platform.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '2rem', fontSize: '0.85rem' }}>
            <Link to="/login" style={{ color: '#94a3b8', textDecoration: 'none' }}>Login</Link>
            <Link to="/register" style={{ color: '#94a3b8', textDecoration: 'none' }}>Register</Link>
            <a href="http://localhost:8080" target="_blank" rel="noreferrer" style={{ color: '#94a3b8', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
              Demo Target <ExternalLink size={12} />
            </a>
            <span style={{ color: '#22c55e', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <span className="live-dot" /> All Systems Operational
            </span>
          </div>
        </div>
        <div style={{ maxWidth: '1280px', margin: '2rem auto 0', paddingTop: '1.5rem', borderTop: '1px solid rgba(255,255,255,0.04)', textAlign: 'center', color: '#475569', fontSize: '0.8rem' }}>
          © 2026 WebSentinel. Strictly for authorized penetration testing and security posture assessment.
        </div>
      </footer>

      {/* Interactive Watch Demo Modal */}
      {demoModalOpen && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 1000,
            background: 'rgba(0, 0, 0, 0.85)',
            backdropFilter: 'blur(16px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '1.5rem',
          }}
          onClick={() => setDemoModalOpen(false)}
        >
          <div
            style={{
              background: '#0a0d14',
              border: '1px solid rgba(255, 255, 255, 0.12)',
              borderRadius: '24px',
              maxWidth: '680px',
              width: '100%',
              padding: '2rem',
              boxShadow: '0 25px 60px rgba(0, 0, 0, 0.9), 0 0 40px rgba(225, 29, 72, 0.2)',
              position: 'relative',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <div style={{ background: 'rgba(225, 29, 72, 0.2)', padding: '0.5rem', borderRadius: '10px', color: '#e11d48' }}>
                  <Terminal size={20} />
                </div>
                <div>
                  <h3 style={{ fontSize: '1.25rem', fontWeight: 800, color: '#ffffff' }}>WebSentinel Security Simulation</h3>
                  <p style={{ color: '#94a3b8', fontSize: '0.825rem' }}>Target: http://localhost:8080 (Local Security Sandbox)</p>
                </div>
              </div>
              <button
                onClick={() => setDemoModalOpen(false)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: '#94a3b8',
                  cursor: 'pointer',
                  padding: '0.4rem',
                }}
              >
                <X size={20} />
              </button>
            </div>

            {/* Terminal Window */}
            <div
              style={{
                background: '#040508',
                border: '1px solid #1e2433',
                borderRadius: '14px',
                padding: '1.25rem',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.85rem',
                minHeight: '220px',
                marginBottom: '1.5rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.65rem',
              }}
            >
              <div style={{ color: '#38bdf8' }}>
                &gt; websentinel scan --target http://localhost:8080 --mode autonomous
              </div>
              {demoStep >= 1 && (
                <div style={{ color: '#94a3b8' }}>
                  [Agent 01: SSRF Guardian] <span style={{ color: '#22c55e' }}>PASS</span> — Target verified as local authorized sandbox.
                </div>
              )}
              {demoStep >= 2 && (
                <div style={{ color: '#94a3b8' }}>
                  [Agent 02: Header Auditor] <span style={{ color: '#ef4444' }}>FAIL</span> — Missing CSP, HSTS, and X-Frame-Options headers.
                </div>
              )}
              {demoStep >= 3 && (
                <div style={{ color: '#94a3b8' }}>
                  [Agent 03: Safe Injection] <span style={{ color: '#eab308' }}>WARN</span> — Parameter reflection detected on /search?q=
                </div>
              )}
              {demoStep >= 4 && (
                <div style={{ color: '#94a3b8' }}>
                  [Agent 04: Secrets Hunter] <span style={{ color: '#ef4444' }}>ALERT</span> — Exposed /.env.example found with credentials.
                </div>
              )}

              {demoRunning ? (
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#e11d48', marginTop: '0.5rem' }}>
                  <span className="live-dot" /> WebSentinel Agent probing active targets...
                </div>
              ) : (
                <div style={{ color: '#22c55e', marginTop: '0.5rem', fontWeight: 600 }}>
                  ✓ Assessment complete. Initial Posture Score: 48/100 (4 Critical Findings).
                </div>
              )}
            </div>

            {/* Modal Actions */}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '1rem' }}>
              <button
                onClick={() => {
                  setDemoStep(0);
                  setDemoRunning(true);
                  handleStartDemo();
                }}
                className="btn-secondary"
                style={{ fontSize: '0.9rem', padding: '0.65rem 1.4rem' }}
              >
                Re-Run Simulation
              </button>
              <button
                onClick={() => {
                  setDemoModalOpen(false);
                  navigate('/scans/new');
                }}
                className="btn-start-free-sm"
                style={{ fontSize: '0.9rem', padding: '0.65rem 1.6rem' }}
              >
                Launch Live Scan <ArrowRight size={14} />
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
