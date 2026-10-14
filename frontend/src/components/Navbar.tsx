import React from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { LayoutDashboard, PlusCircle, History, GitCompare, Lock, LogOut } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { SiegepalLogo } from './SiegepalLogo';

export const Navbar: React.FC = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const isHome = location.pathname === '/';

  return (
    <header
      style={{
        position: 'sticky',
        top: 0,
        zIndex: 100,
        background: 'rgba(6, 7, 10, 0.82)',
        backdropFilter: 'blur(20px)',
        WebkitBackdropFilter: 'blur(20px)',
        borderBottom: '1px solid rgba(255, 255, 255, 0.06)',
      }}
    >
      <div
        style={{
          maxWidth: '1280px',
          margin: '0 auto',
          padding: '0.85rem 2rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        {/* Left: Brand Logo removed */}
        <div style={{ display: 'flex', alignItems: 'center', width: '32px' }} />

        {/* Center: Navigation Links */}
        {user ? (
          <nav style={{ display: 'flex', alignItems: 'center', gap: '1.75rem' }}>
            <Link
              to="/dashboard"
              style={{
                color: location.pathname === '/dashboard' ? '#ffffff' : '#94a3b8',
                textDecoration: 'none',
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
                fontSize: '0.9rem',
                fontWeight: 500,
                transition: 'color 0.2s',
              }}
            >
              <LayoutDashboard size={15} color="#e11d48" /> Dashboard
            </Link>
            <Link
              to="/scans/new"
              style={{
                color: location.pathname === '/scans/new' ? '#ffffff' : '#94a3b8',
                textDecoration: 'none',
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
                fontSize: '0.9rem',
                fontWeight: 500,
                transition: 'color 0.2s',
              }}
            >
              <PlusCircle size={15} color="#10b981" /> New Scan
            </Link>
            <Link
              to="/history"
              style={{
                color: location.pathname === '/history' ? '#ffffff' : '#94a3b8',
                textDecoration: 'none',
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
                fontSize: '0.9rem',
                fontWeight: 500,
                transition: 'color 0.2s',
              }}
            >
              <History size={15} color="#3b82f6" /> History
            </Link>
            <Link
              to="/compare"
              style={{
                color: location.pathname === '/compare' ? '#ffffff' : '#94a3b8',
                textDecoration: 'none',
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
                fontSize: '0.9rem',
                fontWeight: 500,
                transition: 'color 0.2s',
              }}
            >
              <GitCompare size={15} color="#f59e0b" /> Compare
            </Link>

            {user.role === 'ADMIN' && (
              <Link
                to="/admin"
                style={{
                  color: location.pathname === '/admin' ? '#fca5a5' : '#94a3b8',
                  textDecoration: 'none',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.4rem',
                  fontSize: '0.9rem',
                  fontWeight: 500,
                }}
              >
                <Lock size={15} color="#ef4444" /> Admin
              </Link>
            )}
          </nav>
        ) : (
          <nav style={{ display: 'flex', alignItems: 'center', gap: '2.25rem' }}>
            <Link
              to="/"
              style={{
                color: isHome ? '#ffffff' : '#9ca3af',
                textDecoration: 'none',
                fontSize: '0.925rem',
                fontWeight: 500,
                transition: 'color 0.2s',
              }}
            >
              Home
            </Link>
            <a
              href={isHome ? '#agents' : '/#agents'}
              style={{
                color: '#9ca3af',
                textDecoration: 'none',
                fontSize: '0.925rem',
                fontWeight: 500,
                transition: 'color 0.2s',
              }}
            >
              Agents
            </a>
            <a
              href={isHome ? '#contact' : '/#contact'}
              style={{
                color: '#9ca3af',
                textDecoration: 'none',
                fontSize: '0.925rem',
                fontWeight: 500,
                transition: 'color 0.2s',
              }}
            >
              Contact
            </a>
            <a
              href={isHome ? '#docs' : '/#docs'}
              style={{
                color: '#9ca3af',
                textDecoration: 'none',
                fontSize: '0.925rem',
                fontWeight: 500,
                transition: 'color 0.2s',
              }}
            >
              Docs
            </a>
          </nav>
        )}

        {/* Right: Actions */}
        {user ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <span
              style={{
                fontSize: '0.825rem',
                color: '#94a3b8',
                background: 'rgba(255, 255, 255, 0.04)',
                border: '1px solid rgba(255, 255, 255, 0.08)',
                padding: '0.35rem 0.85rem',
                borderRadius: '9999px',
              }}
            >
              {user.email}
            </span>
            <button
              onClick={handleLogout}
              style={{
                background: 'transparent',
                border: '1px solid rgba(255, 255, 255, 0.12)',
                color: '#f8fafc',
                padding: '0.4rem 0.85rem',
                borderRadius: '9999px',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '0.35rem',
                fontSize: '0.825rem',
                transition: 'all 0.2s',
              }}
            >
              <LogOut size={13} /> Logout
            </button>
          </div>
        ) : (
          <div style={{ display: 'flex', alignItems: 'center', gap: '1.75rem' }}>
            <Link
              to="/login"
              style={{
                color: '#e2e8f0',
                textDecoration: 'none',
                fontSize: '0.925rem',
                fontWeight: 500,
                transition: 'color 0.2s',
              }}
            >
              Login
            </Link>
            <Link to="/register" className="btn-start-free-sm">
              Start Free
            </Link>
          </div>
        )}
      </div>
    </header>
  );
};
