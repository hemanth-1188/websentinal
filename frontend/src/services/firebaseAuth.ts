import { 
  signInWithEmailAndPassword, 
  createUserWithEmailAndPassword, 
  signInWithPopup, 
  updateProfile 
} from 'firebase/auth';
import { auth, googleProvider } from '../config/firebase';
import api from './api';

export interface AuthResponse {
  success: boolean;
  token?: string;
  user?: any;
  error?: string;
}

// Helper to send Firebase ID Token or User Details to WebShield Backend
async function authenticateWithBackend(idToken: string, name?: string, email?: string): Promise<AuthResponse> {
  try {
    const res = await api.post('/auth/firebase', {
      idToken,
      name,
      email,
    });
    if (res.data.success) {
      return {
        success: true,
        token: res.data.data.token,
        user: res.data.data.user,
      };
    } else {
      return { success: false, error: res.data.error?.message || 'Backend authentication failed.' };
    }
  } catch (e: any) {
    return { success: false, error: e.response?.data?.error?.message || 'Authentication failed.' };
  }
}

// 1. Firebase Email & Password Login
export async function loginWithFirebaseEmail(email: string, pass: string): Promise<AuthResponse> {
  try {
    const userCred = await signInWithEmailAndPassword(auth, email, pass);
    const idToken = await userCred.user.getIdToken();
    return await authenticateWithBackend(idToken, userCred.user.displayName || email.split('@')[0], userCred.user.email || email);
  } catch (e: any) {
    // If Firebase project API key is not configured locally, fallback gracefully to API login
    return await fallbackNativeLogin(email, pass, e.message);
  }
}

// 2. Firebase Email & Password Registration
export async function registerWithFirebaseEmail(name: string, email: string, pass: string): Promise<AuthResponse> {
  try {
    const userCred = await createUserWithEmailAndPassword(auth, email, pass);
    if (name) {
      await updateProfile(userCred.user, { displayName: name });
    }
    const idToken = await userCred.user.getIdToken();
    return await authenticateWithBackend(idToken, name, email);
  } catch (e: any) {
    // Fallback to native registration if Firebase config is uninitialized locally
    return await fallbackNativeRegister(name, email, pass, e.message);
  }
}

// 3. Firebase Google Popup Login
export async function loginWithFirebaseGoogle(): Promise<AuthResponse> {
  try {
    const userCred = await signInWithPopup(auth, googleProvider);
    const idToken = await userCred.user.getIdToken();
    return await authenticateWithBackend(
      idToken, 
      userCred.user.displayName || userCred.user.email?.split('@')[0], 
      userCred.user.email || undefined
    );
  } catch (e: any) {
    return { success: false, error: `Firebase Google Auth: ${e.message}` };
  }
}

// Fallback handlers if Firebase API Key is not set in environment
async function fallbackNativeLogin(email: string, pass: string, firebaseErr: string): Promise<AuthResponse> {
  try {
    const res = await api.post('/auth/login', { email, password: pass });
    if (res.data.success) {
      return { success: true, token: res.data.data.token, user: res.data.data.user };
    }
    return { success: false, error: res.data.error?.message || firebaseErr };
  } catch (err: any) {
    return { success: false, error: err.response?.data?.error?.message || firebaseErr };
  }
}

async function fallbackNativeRegister(name: string, email: string, pass: string, firebaseErr: string): Promise<AuthResponse> {
  try {
    const res = await api.post('/auth/register', { name, email, password: pass });
    if (res.data.success) {
      return { success: true, token: res.data.data.token, user: res.data.data.user };
    }
    return { success: false, error: res.data.error?.message || firebaseErr };
  } catch (err: any) {
    return { success: false, error: err.response?.data?.error?.message || firebaseErr };
  }
}
