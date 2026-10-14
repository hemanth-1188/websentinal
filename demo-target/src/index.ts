import express, { Request, Response } from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';

const app = express();
const PORT = process.env.PORT || 8080;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// State flag for demonstration remediate toggle
let isRemediated = false;

// Middleware to set headers dynamically based on remediation state
app.use((req: Request, res: Response, next) => {
  if (isRemediated) {
    // Secure Security Headers
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'");
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.removeHeader('X-Powered-By');
  } else {
    // Insecure / Missing Security Headers (Intentionally vulnerable for scanning)
    res.setHeader('X-Powered-By', 'Express/4.19.2 Node.js');
    res.setHeader('Server', 'Apache/2.4.41 (Ubuntu) PHP/7.4.3');
    // Note: CSP, HSTS, X-Frame-Options, X-Content-Type-Options intentionally omitted
  }
  next();
});

// Set demo session cookie
app.use((req: Request, res: Response, next) => {
  if (isRemediated) {
    res.cookie('demo_session', 'sec_token_998877665544', {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 3600000,
    });
  } else {
    // Insecure cookie: missing HttpOnly, Secure, SameSite
    res.cookie('demo_session', 'insecure_token_123456789', {
      httpOnly: false,
      secure: false,
    });
  }
  next();
});

// Home Page
app.get('/', (req: Request, res: Response) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Acme E-Commerce — Local Security Training Target</title>
      <meta name="generator" content="WordPress 5.8.1">
      <style>
        body { font-family: system-ui, sans-serif; background: #0f172a; color: #f8fafc; padding: 2rem; }
        .banner { background: ${isRemediated ? '#065f46' : '#991b1b'}; color: white; padding: 1rem; border-radius: 8px; margin-bottom: 2rem; font-weight: bold; }
        .card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; }
        code { background: #020617; padding: 0.2rem 0.4rem; border-radius: 4px; color: #38bdf8; }
        button { background: #3b82f6; color: white; border: none; padding: 0.5rem 1rem; border-radius: 6px; cursor: pointer; font-size: 1rem; }
        button:hover { background: #2563eb; }
      </style>
    </head>
    <body>
      <div class="banner">
        ⚠️ LOCAL SECURITY TRAINING TARGET — ${isRemediated ? 'REMEDIATED / SECURE MODE' : 'VULNERABLE MODE'}
      </div>
      <h1>Acme Corp Internal Portal</h1>
      <p>This application is designed specifically for testing WebShield automated security scanner.</p>
      
      <div class="card">
        <h3>Search Portal</h3>
        <form action="/search" method="GET">
          <input type="text" name="q" placeholder="Search products..." style="padding:0.5rem; width: 300px;">
          <button type="submit">Search</button>
        </form>
      </div>

      <div class="card">
        <h3>Demonstration Mode Toggle</h3>
        <p>Current Target Security State: <strong>${isRemediated ? 'SECURE (Headers & Cookies Configured)' : 'VULNERABLE (Missing Headers, Insecure Cookies, Disclosures)'}</strong></p>
        <button onclick="toggleMode()">Switch to ${isRemediated ? 'VULNERABLE Mode' : 'REMEDIATED Mode'}</button>
      </div>

      <div class="card">
        <h3>Exposed Test Paths</h3>
        <ul>
          <li><a href="/robots.txt" style="color:#38bdf8">/robots.txt</a></li>
          <li><a href="/.env.example" style="color:#38bdf8">/.env.example</a></li>
          <li><a href="/admin" style="color:#38bdf8">/admin</a></li>
          <li><a href="/backup/database.sql" style="color:#38bdf8">/backup/database.sql</a></li>
          <li><a href="/debug/info" style="color:#38bdf8">/debug/info</a></li>
        </ul>
      </div>

      <script>
        function toggleMode() {
          fetch('/api/demo/toggle', { method: 'POST' })
            .then(res => res.json())
            .then(data => location.reload());
        }
      </script>
    </body>
    </html>
  `);
});

// Reflected input search endpoint
app.get('/search', (req: Request, res: Response) => {
  const q = (req.query.q as string) || '';
  if (isRemediated) {
    // Escaped output
    const safeQ = q.replace(/</g, '&lt;').replace(/>/g, '&gt;');
    res.send(`<h1>Search Results</h1><p>You searched for: <code>${safeQ}</code></p><a href="/">Back</a>`);
  } else {
    // Intentionally unescaped input reflection
    res.send(`<h1>Search Results</h1><p>You searched for: ${q}</p><a href="/">Back</a>`);
  }
});

// Exposed robots.txt
app.get('/robots.txt', (req: Request, res: Response) => {
  if (isRemediated) {
    res.type('text/plain').send('User-agent: *\nDisallow: /');
  } else {
    res.type('text/plain').send(`User-agent: *
Disallow: /admin
Disallow: /backup/
Disallow: /.env.example
Disallow: /debug/info
`);
  }
});

// Exposed .env.example
app.get('/.env.example', (req: Request, res: Response) => {
  if (isRemediated) {
    res.status(404).send('Not Found');
  } else {
    res.type('text/plain').send(`PORT=8080
DATABASE_URL=postgres://db_user:password123@localhost:5432/acme_db
SECRET_KEY=super_secret_acme_api_token_2026
DEBUG=true
`);
  }
});

// Exposed backup file
app.get('/backup/database.sql', (req: Request, res: Response) => {
  if (isRemediated) {
    res.status(404).send('Not Found');
  } else {
    res.type('text/plain').send(`-- ACME Database Dump
CREATE TABLE users (id INT, username VARCHAR(50), password_hash VARCHAR(255));
INSERT INTO users VALUES (1, 'admin', '$2b$10$e8N8...hash');
`);
  }
});

// Debug endpoint exposing stack traces
app.get('/debug/info', (req: Request, res: Response) => {
  if (isRemediated) {
    res.status(403).json({ error: 'Access Denied' });
  } else {
    res.json({
      status: 'DEBUG_ACTIVE',
      environment: 'development',
      node_version: process.version,
      platform: process.platform,
      memory: process.memoryUsage(),
      stack_trace_example: 'Error: Database connection timeout at MySQLConnector.connect (/app/db/mysql.js:42:11)',
    });
  }
});

// Exposed Admin path
app.get('/admin', (req: Request, res: Response) => {
  if (isRemediated) {
    res.status(401).send('401 Unauthorized — Authentication Required');
  } else {
    res.send('<h1>Admin Panel (Exposed Administrative Endpoint)</h1><p>Welcome Admin. No authentication header detected.</p>');
  }
});

// Toggle endpoint for demonstration
app.post('/api/demo/toggle', (req: Request, res: Response) => {
  isRemediated = !isRemediated;
  res.json({ success: true, isRemediated });
});

app.listen(PORT, () => {
  console.log(`[Demo Target] Security Training Target running on http://localhost:${PORT}`);
  console.log(`[Demo Target] Initial State: ${isRemediated ? 'REMEDIATED' : 'VULNERABLE'}`);
});
