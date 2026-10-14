import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { query } from '../database/db';
import { AuthenticatedRequest } from '../middleware/auth';

const JWT_SECRET = process.env.JWT_SECRET || 'webshield_super_secret_jwt_key_2026_change_in_production';

const registerSchema = z.object({
  name: z.string().min(2),
  email: z.string().email(),
  password: z.string().min(6),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string(),
});

export async function register(req: Request, res: Response) {
  try {
    const parse = registerSchema.safeParse(req.body);
    if (!parse.success) {
      return res.status(400).json({
        success: false,
        error: { code: 'INVALID_INPUT', message: parse.error.errors[0].message },
      });
    }

    const { name, email, password } = parse.data;

    // Check existing
    const existing = await query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
      return res.status(400).json({
        success: false,
        error: { code: 'USER_EXISTS', message: 'User with this email already exists.' },
      });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const result = await query(
      'INSERT INTO users (name, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, name, email, role, created_at',
      [name, email, passwordHash, 'USER']
    );

    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, name: user.name, email: user.email, role: user.role }, JWT_SECRET, {
      expiresIn: '7d',
    });

    return res.status(201).json({
      success: true,
      data: { user, token },
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: { code: 'SERVER_ERROR', message: 'Registration failed.' },
    });
  }
}

export async function login(req: Request, res: Response) {
  try {
    const parse = loginSchema.safeParse(req.body);
    if (!parse.success) {
      return res.status(400).json({
        success: false,
        error: { code: 'INVALID_INPUT', message: 'Valid email and password required.' },
      });
    }

    const { email, password } = parse.data;
    const result = await query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        error: { code: 'INVALID_CREDENTIALS', message: 'Invalid email or password.' },
      });
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({
        success: false,
        error: { code: 'INVALID_CREDENTIALS', message: 'Invalid email or password.' },
      });
    }

    const token = jwt.sign({ id: user.id, name: user.name, email: user.email, role: user.role }, JWT_SECRET, {
      expiresIn: '7d',
    });

    await query('INSERT INTO audit_logs (user_id, action, metadata) VALUES ($1, $2, $3)', [
      user.id,
      'USER_LOGIN',
      JSON.stringify({ ip: req.ip }),
    ]);

    return res.json({
      success: true,
      data: {
        user: { id: user.id, name: user.name, email: user.email, role: user.role },
        token,
      },
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: { code: 'SERVER_ERROR', message: 'Login failed.' },
    });
  }
}

export async function logout(req: Request, res: Response) {
  return res.json({ success: true, data: { message: 'Logged out successfully.' } });
}

export async function googleAuth(req: Request, res: Response) {
  try {
    const { email, name, google_id } = req.body;
    if (!email) {
      return res.status(400).json({
        success: false,
        error: { code: 'INVALID_INPUT', message: 'Google account email is required.' },
      });
    }

    const userName = name || email.split('@')[0] || 'Google User';
    
    // Check if user exists
    let userRes = await query('SELECT * FROM users WHERE email = $1', [email]);
    let user;

    if (userRes.rows.length === 0) {
      // First-time Google user registration
      const randomPass = await bcrypt.hash(google_id || 'GoogleAuthPass2026', 10);
      const newRes = await query(
        'INSERT INTO users (name, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, name, email, role, created_at',
        [userName, email, randomPass, 'USER']
      );
      user = newRes.rows[0];
      await query('INSERT INTO audit_logs (user_id, action, metadata) VALUES ($1, $2, $3)', [
        user.id,
        'GOOGLE_REGISTER',
        JSON.stringify({ email, ip: req.ip }),
      ]);
    } else {
      user = userRes.rows[0];
      await query('INSERT INTO audit_logs (user_id, action, metadata) VALUES ($1, $2, $3)', [
        user.id,
        'GOOGLE_LOGIN',
        JSON.stringify({ email, ip: req.ip }),
      ]);
    }

    const token = jwt.sign({ id: user.id, name: user.name, email: user.email, role: user.role }, JWT_SECRET, {
      expiresIn: '7d',
    });

    return res.json({
      success: true,
      data: {
        user: { id: user.id, name: user.name, email: user.email, role: user.role },
        token,
        isFirstTime: userRes.rows.length === 0,
      },
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: { code: 'SERVER_ERROR', message: 'Google authentication failed.' },
    });
  }
}

export async function firebaseAuth(req: Request, res: Response) {
  try {
    const { idToken, email, name } = req.body;
    
    // Fallback email parsing if token is passed
    const userEmail = email || 'firebase_user@webshield.io';
    const userName = name || userEmail.split('@')[0] || 'Firebase User';

    let userRes = await query('SELECT * FROM users WHERE email = $1', [userEmail]);
    let user;

    if (userRes.rows.length === 0) {
      // Create user account for first-time Firebase user
      const randomPass = await bcrypt.hash('FirebasePass_' + Date.now(), 10);
      const newRes = await query(
        'INSERT INTO users (name, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, name, email, role, created_at',
        [userName, userEmail, randomPass, 'USER']
      );
      user = newRes.rows[0];
      await query('INSERT INTO audit_logs (user_id, action, metadata) VALUES ($1, $2, $3)', [
        user.id,
        'FIREBASE_REGISTER',
        JSON.stringify({ email: userEmail, ip: req.ip }),
      ]);
    } else {
      user = userRes.rows[0];
      await query('INSERT INTO audit_logs (user_id, action, metadata) VALUES ($1, $2, $3)', [
        user.id,
        'FIREBASE_LOGIN',
        JSON.stringify({ email: userEmail, ip: req.ip }),
      ]);
    }

    const token = jwt.sign({ id: user.id, name: user.name, email: user.email, role: user.role }, JWT_SECRET, {
      expiresIn: '7d',
    });

    return res.json({
      success: true,
      data: {
        user: { id: user.id, name: user.name, email: user.email, role: user.role },
        token,
      },
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: { code: 'SERVER_ERROR', message: 'Firebase authentication failed.' },
    });
  }
}

export async function me(req: AuthenticatedRequest, res: Response) {
  return res.json({ success: true, data: { user: req.user } });
}
