/**
 * Authentication state management with Zustand
 * - Manages user login/logout state and authentication status
 * - Integrates with authAPI for login, logout, and token management
 * - Provides error handling and loading states for auth operations
 * - Auto-initializes from localStorage tokens via authAPI.getCurrentUser()
 * - Only active when VITE_AUTH_ENABLED=true
 */
import { create } from 'zustand'
import { authAPI } from '../services/api'

/**
 * User data structure for authenticated users
 * Contains username, role list, and email address
 */
interface User {
  username: string
  roles: string[]
  email: string
}

/**
 * Authentication store state and actions
 * Manages user authentication lifecycle and session state
 */
interface AuthStore {
  user: User | null
  isAuthenticated: boolean
  isLoading: boolean
  error: string | null

  setUser: (user: User | null) => void
  setLoading: (loading: boolean) => void
  setError: (error: string | null) => void
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
  checkAuth: () => void
  clearError: () => void
}

/**
 * Zustand authentication store
 * Provides user authentication state and actions throughout the application
 * Initializes from authAPI.getCurrentUser() on store creation
 */
export const useAuthStore = create<AuthStore>((set) => ({
  user: authAPI.getCurrentUser(),
  isAuthenticated: authAPI.isAuthenticated(),
  isLoading: false,
  error: null,

  setUser: (user) =>
    set({
      user,
      isAuthenticated: !!user,
      error: null,
    }),

  setLoading: (loading) =>
    set({
      isLoading: loading,
    }),

  setError: (error) =>
    set({
      error,
      isLoading: false,
    }),

  clearError: () =>
    set({
      error: null,
    }),

  login: async (username, password) => {
    set({ isLoading: true, error: null })
    try {
      const data = await authAPI.login(username, password)
      set({
        user: data.user,
        isAuthenticated: true,
        isLoading: false,
        error: null,
      })
    } catch (error: any) {
      const errorMessage =
        error.response?.data?.message || 'Login failed. Please check your credentials.'
      set({
        isLoading: false,
        error: errorMessage,
      })
      throw error
    }
  },

  logout: async () => {
    set({ isLoading: true })
    try {
      await authAPI.logout()
      set({
        user: null,
        isAuthenticated: false,
        isLoading: false,
        error: null,
      })
    } catch (error: any) {
      set({
        user: null,
        isAuthenticated: false,
        isLoading: false,
        error: null,
      })
    }
  },

  checkAuth: () => {
    const user = authAPI.getCurrentUser()
    const isAuth = authAPI.isAuthenticated()
    set({
      user,
      isAuthenticated: isAuth,
    })
  },
}))
