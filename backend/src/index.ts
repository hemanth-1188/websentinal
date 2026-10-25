import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import apiRouter from './routes/api';
import { initDb } from './database/initDb';
import { testDbConnection, isMongoAvailable, getDb, lastMongoError } from './database/db';
import { apiRateLimiter } from './middleware/rateLimit';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Security & Standard Middleware
app.use(helmet({ contentSecurityPolicy: false })); // Express helmet configuration
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// General Rate Limiting
app.use('/api', apiRateLimiter);

// API Routes
app.use('/api', apiRouter);

// Root API Info Route
app.get('/', (req: Request, res: Response) => {
  res.json({
    service: 'WebSentinel Security Assessment API',
    status: 'ONLINE',
    version: '1.0.0',
    endpoints: {
      health: '/health',
      database: '/health/db',
      api: '/api',
    },
    database: {
      engine: 'MongoDB',
      connected: isMongoAvailable,
      mode: isMongoAvailable ? 'MongoDB Live' : 'In-Memory Fallback',
    },
  });
});

// Healthcheck Route
app.get('/health', (req: Request, res: Response) => {
  res.json({
    status: 'UP',
    service: 'WebSentinel Backend API & Scanner Engine',
    database: {
      engine: 'MongoDB',
      connected: isMongoAvailable,
      mode: isMongoAvailable ? 'MongoDB Live' : 'In-Memory Fallback',
    },
  });
});

// Dedicated Database Verification Route
app.get('/health/db', async (req: Request, res: Response) => {
  try {
    if (!isMongoAvailable) {
      const hasUri = !!process.env.MONGODB_URI;
      return res.json({
        connected: false,
        mode: 'In-Memory Fallback',
        message: 'MongoDB is currently unreachable. Operating on fallback persistence.',
        diagnostics: {
          hasMongodbUriEnv: hasUri,
          uriProtocol: hasUri ? (process.env.MONGODB_URI!.startsWith('mongodb+srv') ? 'mongodb+srv' : 'mongodb') : 'NOT_SET',
          lastError: lastMongoError || 'Connection timed out or host unreachable',
          troubleshooting: !hasUri 
            ? 'Set MONGODB_URI in Render dashboard -> Environment tab.' 
            : 'In MongoDB Atlas -> Network Access: ensure 0.0.0.0/0 (allow from anywhere) is added. Verify password in MONGODB_URI.',
        },
      });
    }
    const db = getDb();
    const pingRes = await db.command({ ping: 1 });
    const userCount = await db.collection('users').countDocuments();
    const scanCount = await db.collection('scans').countDocuments();
    const findingCount = await db.collection('findings').countDocuments();
    return res.json({
      connected: true,
      mode: 'MongoDB Live',
      ping: pingRes.ok === 1 ? 'SUCCESS' : 'FAILED',
      database: db.databaseName,
      collections: {
        users: userCount,
        scans: scanCount,
        findings: findingCount,
      },
    });
  } catch (err: any) {
    return res.status(500).json({
      connected: false,
      error: err.message,
    });
  }
});

// Centralized Production Error Handler
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  console.error('[Error Handler]', err);

  const statusCode = err.statusCode || 500;
  const message = process.env.NODE_ENV === 'production' 
    ? 'An unexpected server error occurred.' 
    : err.message || 'Internal Server Error';

  res.status(statusCode).json({
    success: false,
    error: {
      code: err.code || 'SERVER_ERROR',
      message,
    },
  });
});

async function startServer() {
  try {
    await testDbConnection();
    await initDb();
    app.listen(PORT, () => {
      console.log(`[WebShield Backend] Server running on port ${PORT}`);
      console.log(`[WebShield Backend] Health check available at http://localhost:${PORT}/health`);
    });
  } catch (err) {
    console.error('[WebShield Backend] Server startup failed:', err);
    process.exit(1);
  }
}

startServer();
