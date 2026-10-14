import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { LandingPage } from './pages/LandingPage';
import { LoginPage } from './pages/LoginPage';
import { RegisterPage } from './pages/RegisterPage';
import { DashboardPage } from './pages/DashboardPage';
import { NewScanPage } from './pages/NewScanPage';
import { ScanProgressPage } from './pages/ScanProgressPage';
import { ScanResultsPage } from './pages/ScanResultsPage';
import { ScanHistoryPage } from './pages/ScanHistoryPage';
import { ScanComparePage } from './pages/ScanComparePage';
import { AdminDashboardPage } from './pages/AdminDashboardPage';

const ProtectedRoute: React.FC<{ children: React.ReactNode; roles?: string[] }> = ({ children, roles }) => {
  const { user, loading } = useAuth();
  if (loading) return <div style={{ background: '#0b0f19', color: '#94a3b8', minHeight: '100vh', padding: '4rem', textAlign: 'center' }}>Authenticating...</div>;
  if (!user) return <Navigate to="/login" replace />;
  if (roles && !roles.includes(user.role)) return <Navigate to="/dashboard" replace />;
  return <>{children}</>;
};

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <Router>
        <Routes>
          {/* Public Routes */}
          <Route path="/" element={<LandingPage />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />

          {/* Authenticated Routes */}
          <Route path="/dashboard" element={<ProtectedRoute><DashboardPage /></ProtectedRoute>} />
          <Route path="/scans/new" element={<ProtectedRoute><NewScanPage /></ProtectedRoute>} />
          <Route path="/scans/:id/progress" element={<ProtectedRoute><ScanProgressPage /></ProtectedRoute>} />
          <Route path="/scans/:id" element={<ProtectedRoute><ScanResultsPage /></ProtectedRoute>} />
          <Route path="/history" element={<ProtectedRoute><ScanHistoryPage /></ProtectedRoute>} />
          <Route path="/compare" element={<ProtectedRoute><ScanComparePage /></ProtectedRoute>} />

          {/* Admin Routes */}
          <Route path="/admin" element={<ProtectedRoute roles={['ADMIN']}><AdminDashboardPage /></ProtectedRoute>} />

          {/* Fallback */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Router>
    </AuthProvider>
  );
};

export default App;
