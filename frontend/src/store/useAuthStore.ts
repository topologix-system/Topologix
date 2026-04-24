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
import { logger } from '../utils/logger'
import { extractErrorMessage } from '../types/errors'

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

function clearSnapshotClientState() {
  localStorage.removeItem('topologix-snapshot-storage')
  localStorage.removeItem('topologix-position-storage')
}

/**
 * Zustand authentication store
 * Provides user authentication state and actions throughout the application
 * Initializes from authAPI.getCurrentUser() on store creation
 */
export const useAuthStore = create<AuthStore>((set, get) => ({
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
      clearSnapshotClientState()
      set({
        user: data.user,
        isAuthenticated: true,
        isLoading: false,
        error: null,
      })
    } catch (error: unknown) {
      const errorMessage = extractErrorMessage(error, 'Login failed. Please check your credentials.')
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
      clearSnapshotClientState()
      set({
        user: null,
        isAuthenticated: false,
        isLoading: false,
        error: null,
      })
    } catch (_error: unknown) {
      clearSnapshotClientState()
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

    const currentState = get()

    // If was authenticated but now not, log the change
    if (currentState.isAuthenticated && !isAuth) {
      logger.info('[AuthStore] Authentication expired')
    }

    set({
      user,
      isAuthenticated: isAuth,
    })
  },
}))
