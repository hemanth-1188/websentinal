import { Router } from 'express';
import * as authController from '../controllers/authController';
import * as scanController from '../controllers/scanController';
import * as reportController from '../controllers/reportController';
import * as dashboardController from '../controllers/dashboardController';
import * as adminController from '../controllers/adminController';
import { authenticateJwt, requireRole } from '../middleware/auth';
import { authRateLimiter, scanRateLimiter } from '../middleware/rateLimit';

const router = Router();

// --- Auth Routes ---
router.post('/auth/register', authRateLimiter, authController.register);
router.post('/auth/login', authRateLimiter, authController.login);
router.post('/auth/google', authRateLimiter, authController.googleAuth);
router.post('/auth/firebase', authRateLimiter, authController.firebaseAuth);
router.post('/auth/logout', authController.logout);
router.get('/auth/me', authenticateJwt, authController.me);

// --- Scan Routes ---
router.post('/scans', authenticateJwt, scanRateLimiter, scanController.createScan);
router.get('/scans', authenticateJwt, scanController.getScans);
router.get('/scans/compare', authenticateJwt, scanController.compareScans);
router.get('/scans/:id', authenticateJwt, scanController.getScanById);
router.get('/scans/:id/findings', authenticateJwt, scanController.getFindings);
router.get('/scans/:id/progress', authenticateJwt, scanController.getScanProgress);
router.post('/scans/:id/cancel', authenticateJwt, scanController.cancelScan);
router.post('/scans/:id/rescan', authenticateJwt, scanRateLimiter, scanController.rescanTarget);
router.get('/scans/:id/report', authenticateJwt, scanController.getReportJson);
router.post('/scans/:id/remediate-demo', authenticateJwt, scanController.remediateDemoTarget);

// --- Report Routes ---
router.post('/scans/:id/reports', authenticateJwt, reportController.createReport);
router.get('/reports/:id/download', authenticateJwt, reportController.downloadReport);

// --- Dashboard Routes ---
router.get('/dashboard/summary', authenticateJwt, dashboardController.getDashboardSummary);
router.get('/dashboard/trends', authenticateJwt, dashboardController.getDashboardTrends);

// --- Admin Routes ---
router.get('/admin/summary', authenticateJwt, requireRole(['ADMIN']), adminController.getAdminSummary);
router.get('/admin/users', authenticateJwt, requireRole(['ADMIN']), adminController.getUsers);
router.get('/admin/audit-logs', authenticateJwt, requireRole(['ADMIN']), adminController.getAuditLogs);

export default router;
