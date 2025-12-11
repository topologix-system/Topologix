/**
 * Application entry point with optimized code splitting strategy
 * - Lazy loads all routes and panels to reduce initial bundle size for faster startup
 * - Configures React Query: 5min stale time, 10min cache, smart retry logic with exponential backoff
 * - React StrictMode intentionally double-mounts components in dev (see TopologyViewer cleanup hooks)
 * - Conditional React Query DevTools for development environment only
 * - Async i18n initialization for non-blocking language file loading
 */
import React, { Suspense, lazy } from 'react'
import ReactDOM from 'react-dom/client'
import { createBrowserRouter, RouterProvider } from 'react-router-dom'
import { QueryClient, QueryClientProvider, QueryCache, MutationCache } from '@tanstack/react-query'
import './index.css'
import { authAPI } from './services/api'
import { logger } from './utils/logger'

// Lazy load components for code splitting
const Layout = lazy(() => import('./components/Layout').then(m => ({ default: m.Layout })))
const TopologyView = lazy(() => import('./pages/TopologyView').then(m => ({ default: m.TopologyView })))
const SnapshotManagement = lazy(() => import('./pages/SnapshotManagement').then(m => ({ default: m.SnapshotManagement })))
const SnapshotComparison = lazy(() => import('./pages/SnapshotComparison').then(m => ({ default: m.SnapshotComparison })))
const Layer1TopologyEditor = lazy(() => import('./pages/Layer1TopologyEditor').then(m => ({ default: m.Layer1TopologyEditor })))
const SidebarPopout = lazy(() => import('./pages/SidebarPopout').then(m => ({ default: m.SidebarPopout })))
const LoginPage = lazy(() => import('./pages/LoginPage').then(m => ({ default: m.LoginPage })))
const RegisterPage = lazy(() => import('./pages/RegisterPage').then(m => ({ default: m.RegisterPage })))
const PasswordResetRequestPage = lazy(() => import('./pages/PasswordResetRequestPage').then(m => ({ default: m.PasswordResetRequestPage })))
const PasswordResetPage = lazy(() => import('./pages/PasswordResetPage').then(m => ({ default: m.PasswordResetPage })))
const ProfilePage = lazy(() => import('./pages/ProfilePage').then(m => ({ default: m.ProfilePage })))
const UserManagementPage = lazy(() => import('./pages/UserManagementPage').then(m => ({ default: m.UserManagementPage })))
const UserEditPage = lazy(() => import('./pages/UserEditPage').then(m => ({ default: m.UserEditPage })))
const SecurityLogsPage = lazy(() => import('./pages/SecurityLogsPage').then(m => ({ default: m.SecurityLogsPage })))
const ProtectedRoute = lazy(() => import('./components/ProtectedRoute').then(m => ({ default: m.ProtectedRoute })))

// Lazy load React Query DevTools (only in development)
const ReactQueryDevtools = lazy(() =>
  import('@tanstack/react-query-devtools').then(m => ({ default: m.ReactQueryDevtools }))
)

// Lazy load i18n configuration
const loadI18n = () => import('./i18n/config')
loadI18n() // Initialize i18n asynchronously

// Type guard for axios error
function isAxiosError(error: unknown): error is { response?: { status?: number } } {
  return typeof error === 'object' && error !== null && 'response' in error
}

// Global error handler for 401 Unauthorized errors and token expiration
const handleUnauthorizedError = (error: unknown) => {
  // Check for Axios 401 errors
  if (isAxiosError(error) && error.response?.status === 401) {
    logger.error('[Global Error Handler] 401 Unauthorized - clearing auth state')

    // Trigger custom event for unauthorized access (no API call to prevent infinite loop)
    window.dispatchEvent(new CustomEvent('auth:unauthorized', {
      detail: { source: 'global_handler', timestamp: Date.now() }
    }))
    return
  }

  // Check for token expiration errors from request interceptor
  if (error instanceof Error && error.message === 'Token expired') {
    logger.error('[Global Error Handler] Token expired error - clearing auth state')

    // Trigger custom event for token expiration (same as 401 handling)
    window.dispatchEvent(new CustomEvent('auth:unauthorized', {
      detail: { source: 'interceptor_rejection', timestamp: Date.now() }
    }))
    return
  }
}

// Create React Query client with global error handling and optimized cache strategy
const queryClient = new QueryClient({
  queryCache: new QueryCache({
    onError: (error) => {
      handleUnauthorizedError(error)
    },
  }),
  mutationCache: new MutationCache({
    onError: (error) => {
      handleUnauthorizedError(error)
    },
  }),
  defaultOptions: {
    queries: {
      staleTime: 5 * 60 * 1000, // 5 minutes - increased for better performance
      gcTime: 10 * 60 * 1000, // 10 minutes - keep data in cache longer (renamed from cacheTime in v5)
      refetchOnWindowFocus: false,
      refetchOnReconnect: 'always',
      retry: (failureCount, error: any) => {
        // Only retry on network errors, not on 4xx errors (including 401)
        if (error?.response?.status >= 400 && error?.response?.status < 500) {
          return false
        }
        return failureCount < 2
      },
    },
  },
})

// Loading component for route transitions
const RouteLoadingFallback = () => (
  <div className="flex items-center justify-center h-screen bg-gray-50">
    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600" />
  </div>
)

// Create router with lazy loaded components
const router = createBrowserRouter([
  {
    path: '/login',
    element: (
      <Suspense fallback={<RouteLoadingFallback />}>
        <LoginPage />
      </Suspense>
    ),
  },
  {
    path: '/register',
    element: (
      <Suspense fallback={<RouteLoadingFallback />}>
        <RegisterPage />
      </Suspense>
    ),
  },
  {
    path: '/password-reset-request',
    element: (
      <Suspense fallback={<RouteLoadingFallback />}>
        <PasswordResetRequestPage />
      </Suspense>
    ),
  },
  {
    path: '/password-reset/:token',
    element: (
      <Suspense fallback={<RouteLoadingFallback />}>
        <PasswordResetPage />
      </Suspense>
    ),
  },
  {
    path: '/',
    element: (
      <Suspense fallback={<RouteLoadingFallback />}>
        <ProtectedRoute>
          <Layout />
        </ProtectedRoute>
      </Suspense>
    ),
    children: [
      {
        index: true,
        element: (
          <Suspense fallback={<RouteLoadingFallback />}>
            <TopologyView />
          </Suspense>
        ),
      },
    ],
  },
  {
    path: '/snapshots/compare',
    element: (
      <Suspense fallback={<RouteLoadingFallback />}>
        <ProtectedRoute>
          <SnapshotComparison />
        </ProtectedRoute>
      </Suspense>
    ),
  },
  {
    path: '/snapshots',
    element: (
      <Suspense fallback={<RouteLoadingFallback />}>
        <ProtectedRoute>
          <SnapshotManagement />
        </ProtectedRoute>
      </Suspense>
    ),
  },
  {
    path: '/snapshots/:snapshotName/layer1-topology',
    element: (
      <Suspense fallback={<RouteLoadingFallback />}>
        <ProtectedRoute>
          <Layer1TopologyEditor />
        </ProtectedRoute>
      </Suspense>
    ),
  },
  {
    path: '/profile',
    element: (
      <Suspense fallback={<RouteLoadingFallback />}>
        <ProtectedRoute>
          <ProfilePage />
        </ProtectedRoute>
      </Suspense>
    ),
  },
  {
    path: '/admin/users',
    element: (
      <Suspense fallback={<RouteLoadingFallback />}>
        <ProtectedRoute>
          <UserManagementPage />
        </ProtectedRoute>
      </Suspense>
    ),
  },
  {
    path: '/admin/users/:id/edit',
    element: (
      <Suspense fallback={<RouteLoadingFallback />}>
        <ProtectedRoute>
          <UserEditPage />
        </ProtectedRoute>
      </Suspense>
    ),
  },
  {
    path: '/admin/security-logs',
    element: (
      <Suspense fallback={<RouteLoadingFallback />}>
        <ProtectedRoute>
          <SecurityLogsPage />
        </ProtectedRoute>
      </Suspense>
    ),
  },
  {
    path: '/sidebar-popout',
    element: (
      <Suspense fallback={<RouteLoadingFallback />}>
        <ProtectedRoute>
          <SidebarPopout />
        </ProtectedRoute>
      </Suspense>
    ),
  },
])

// Component to handle global unauthorized events
function AuthEventListener() {
  React.useEffect(() => {
    const handleUnauthorized = () => {
      // Redirect to login page
      window.location.href = '/login'
    }

    window.addEventListener('auth:unauthorized', handleUnauthorized)

    return () => {
      window.removeEventListener('auth:unauthorized', handleUnauthorized)
    }
  }, [])

  return null
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  // StrictMode intentionally double-mounts components in development
  // This is normal React behavior - see TopologyViewer cleanup hooks for handling
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <AuthEventListener />
      <RouterProvider router={router} />
      {import.meta.env.DEV && (
        <Suspense fallback={null}>
          <ReactQueryDevtools initialIsOpen={false} />
        </Suspense>
      )}
    </QueryClientProvider>
  </React.StrictMode>
)