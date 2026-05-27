import { create } from 'zustand';
import type { User } from '../types/auth';
import { authService } from '../services/authService';

interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;

  // Actions
  setUser: (user: User | null) => void;
  setAuthenticated: (value: boolean) => void;
  setLoading: (value: boolean) => void;
  setError: (error: string | null) => void;

  // Async actions
  login: (username: string, password: string) => Promise<void>;
  register: (username: string, email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  fetchCurrentUser: () => Promise<void>;
  clearError: () => void;
}

// Dev-only bypass: set VITE_BYPASS_AUTH=true in .env.development.local to skip
// backend auth and inject a mock admin user. Disabled in production builds.
const BYPASS_AUTH = import.meta.env.VITE_BYPASS_AUTH === 'true';
const MOCK_ADMIN_USER: User = {
  id: 0,
  username: 'dev-admin',
  email: 'dev-admin@local',
  role: 'admin',
  is_active: true,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
};

export const useAuthStore = create<AuthState>((set) => {
  // Check if there's a token on initialization
  const hasToken = !!localStorage.getItem('access_token');

  return {
    user: BYPASS_AUTH ? MOCK_ADMIN_USER : null,
    isAuthenticated: BYPASS_AUTH,
    isLoading: BYPASS_AUTH ? false : hasToken, // If has token, start in loading state
    error: null,

    setUser: (user) => set({ user }),
    setAuthenticated: (value) => set({ isAuthenticated: value }),
    setLoading: (value) => set({ isLoading: value }),
    setError: (error) => set({ error }),
    clearError: () => set({ error: null }),

    login: async (username, password) => {
      set({ isLoading: true, error: null });
      try {
        await authService.login({ username, password });
        const user = await authService.getCurrentUser();
        set({ user, isAuthenticated: true, isLoading: false });
      } catch (err: any) {
        set({ 
          error: err.response?.data?.error || 'Login failed', 
          isLoading: false,
          isAuthenticated: false 
        });
        throw err;
      }
    },

    register: async (username, email, password) => {
      set({ isLoading: true, error: null });
      try {
        await authService.register({ username, email, password });
        // Auto login after registration
        await authService.login({ username, password });
        const user = await authService.getCurrentUser();
        set({ user, isAuthenticated: true, isLoading: false });
      } catch (err: any) {
        set({ 
          error: err.response?.data?.error || 'Registration failed', 
          isLoading: false 
        });
        throw err;
      }
    },

    logout: async () => {
      set({ isLoading: true });
      try {
        await authService.logout();
      } finally {
        set({ 
          user: null, 
          isAuthenticated: false, 
          isLoading: false,
          error: null 
        });
      }
    },

    fetchCurrentUser: async () => {
      if (BYPASS_AUTH) {
        set({ user: MOCK_ADMIN_USER, isAuthenticated: true, isLoading: false });
        return;
      }
      set({ isLoading: true });
      const token = localStorage.getItem('access_token');
      if (!token) {
        set({ isAuthenticated: false, user: null, isLoading: false });
        return;
      }

      try {
        const user = await authService.getCurrentUser();
        set({ user, isAuthenticated: true, isLoading: false });
      } catch (err) {
        set({ 
          user: null, 
          isAuthenticated: false, 
          isLoading: false 
        });
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
      }
    },
  };
});
