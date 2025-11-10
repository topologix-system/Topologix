import { useEffect } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
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
 * 4. Periodically checks token expiration every 30 seconds
 *
 * Preserves original route location in state for post-login redirect
 */

interface ProtectedRouteProps {
  children: React.ReactNode
}

export function ProtectedRoute({ children }: ProtectedRouteProps) {
  const location = useLocation()
  const checkAuth = useAuthStore((state) => state.checkAuth)

  // Periodically check authentication status (every 30 seconds)
  useEffect(() => {
    if (!authAPI.isAuthEnabled()) return

    // Initial check
    checkAuth()

    // Set up interval to check every 30 seconds
    const interval = setInterval(() => {
      checkAuth()

      // If not authenticated, the component will re-render and redirect
      if (!authAPI.isAuthenticated()) {
        logger.info('[ProtectedRoute] Token expired, will redirect to login')
      }
    }, 30 * 1000)

    return () => clearInterval(interval)
  }, [checkAuth])

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
