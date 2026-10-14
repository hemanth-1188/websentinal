import { initializeApp, getApps, getApp } from 'firebase/app';
import { getAuth, GoogleAuthProvider } from 'firebase/auth';

const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY || "AIzaSyA3Vx2x7tfD-Xa7jH52RYOHcb7bZqvQHaQ",
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN || "webshield-3f9cd.firebaseapp.com",
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID || "webshield-3f9cd",
  storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET || "webshield-3f9cd.firebasestorage.app",
  messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID || "109069939703",
  appId: import.meta.env.VITE_FIREBASE_APP_ID || "1:109069939703:web:f6e711f2aed979ee53f4f2",
};

// Initialize Firebase
const app = getApps().length > 0 ? getApp() : initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const googleProvider = new GoogleAuthProvider();

export default app;
