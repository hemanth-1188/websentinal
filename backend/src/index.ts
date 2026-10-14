import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import apiRouter from './routes/api';
import { initDb } from './database/initDb';
import { testDbConnection } from './database/db';
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

// Healthcheck Route
app.get('/health', (req: Request, res: Response) => {
  res.json({ status: 'UP', service: 'WebSentinel Backend API & Scanner Engine' });
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
