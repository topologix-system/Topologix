import { Navigate, useLocation } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { authAPI } from '../services/api'
import { useAuthStore } from '../store/useAuthStore'
import { logger } from '../utils/logger'

/**
 * Protected route wrapper component for authentication guard
 * Protects routes from unauthenticated access by redirecting to login
 *
 * Flow:
 * 1. If authentication is disabled (AUTH_ENABLED=false), allow access
 * 2. If authentication is enabled but user not authenticated, redirect to /login
 * 3. If authenticated, render protected children components
 * 4. Periodically checks token expiration every 5 seconds using React Query
 *
 * Preserves original route location in state for post-login redirect
 */

interface ProtectedRouteProps {
  children: React.ReactNode
}

export function ProtectedRoute({ children }: ProtectedRouteProps) {
  const location = useLocation()
  const checkAuth = useAuthStore((state) => state.checkAuth)

  // Periodically check authentication status using React Query (every 5 seconds)
  useQuery({
    queryKey: ['auth', 'status'],
    queryFn: () => {
      checkAuth()
      const isAuth = authAPI.isAuthenticated()

      if (!isAuth) {
        logger.info('[ProtectedRoute] Token expired, will redirect to login')
      }

      return isAuth
    },
    refetchInterval: 5 * 1000, // Check every 5 seconds for faster timeout detection
    enabled: authAPI.isAuthEnabled(),
    staleTime: 0, // Always consider data stale to ensure fresh checks
    gcTime: 0, // Don't cache authentication status
  })

  // Skip authentication check if auth is disabled (development mode)
  if (!authAPI.isAuthEnabled()) {
    return <>{children}</>
  }

  // Redirect to login if not authenticated, preserving original location
  if (!authAPI.isAuthenticated()) {
    return <Navigate to="/login" state={{ from: location }} replace />
  }

  return <>{children}</>
}
