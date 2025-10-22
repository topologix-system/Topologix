import { Navigate, useLocation } from 'react-router-dom'
import { authAPI } from '../services/api'

/**
 * Protected route wrapper component for authentication guard
 * Protects routes from unauthenticated access by redirecting to login
 *
 * Flow:
 * 1. If authentication is disabled (AUTH_ENABLED=false), allow access
 * 2. If authentication is enabled but user not authenticated, redirect to /login
 * 3. If authenticated, render protected children components
 *
 * Preserves original route location in state for post-login redirect
 */

interface ProtectedRouteProps {
  children: React.ReactNode
}

export function ProtectedRoute({ children }: ProtectedRouteProps) {
  const location = useLocation()

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
