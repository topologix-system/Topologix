import { Navigate, useLocation } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { authAPI } from '../services/api'
import { useAuthStore } from '../store/useAuthStore'
import { logger } from '../utils/logger'

/**
 * Protected route wrapper component for authentication guard
 * Protects routes from unauthenticated access by redirecting to login
 */

interface ProtectedRouteProps {
  children: React.ReactNode
}

export function ProtectedRoute({ children }: ProtectedRouteProps) {
  const location = useLocation()
  const checkAuth = useAuthStore((state) => state.checkAuth)

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
    refetchInterval: 5 * 1000,
    enabled: authAPI.isAuthEnabled(),
    staleTime: 0,
    gcTime: 0,
  })

  if (!authAPI.isAuthEnabled()) {
    return <>{children}</>
  }

  if (!authAPI.isAuthenticated()) {
    return <Navigate to="/login" state={{ from: location }} replace />
  }

  return <>{children}</>
}
