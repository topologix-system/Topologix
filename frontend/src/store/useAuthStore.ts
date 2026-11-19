/**
 * Authentication state management with Zustand
 */
import { create } from 'zustand'
import i18n from 'i18next'
import { authAPI } from '../services/api'
import { logger } from '../utils/logger'
import { extractErrorMessage } from '../types/errors'
import { queryClient } from '../queryClient'
import { INVALIDATION_SIGNAL_KEY, resetSnapshotTriggerState } from '../hooks/snapshotTriggerState'
import { useSnapshotStore } from './useSnapshotStore'

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
  queryClient.clear()
  resetSnapshotTriggerState(queryClient)
  useSnapshotStore.setState({
    currentSnapshotName: null,
    isSnapshotActivationInProgress: false,
    activatingSnapshotName: null,
  })
  localStorage.removeItem('topologix-snapshot-storage')
  localStorage.removeItem('topologix-position-storage')
  localStorage.removeItem(INVALIDATION_SIGNAL_KEY)
}

/**
 * Zustand authentication store
 * Provides user authentication state and actions throughout the application
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
      const errorMessage = extractErrorMessage(error, i18n.t('auth.loginFailed'))
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
    } catch {
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

    if (currentState.isAuthenticated && !isAuth) {
      logger.info('[AuthStore] Authentication expired')
    }

    set({
      user,
      isAuthenticated: isAuth,
    })
  },
}))
