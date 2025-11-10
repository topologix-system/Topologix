/**
 * User authentication login page
 * - Username/password form with validation and error display
 * - Zustand authentication store integration with login state management
 * - Redirect-to-from location handling: preserves original destination after login
 * - Links to registration and password reset flows for user convenience
 * - Displays app version in development mode only
 */
import { useState } from 'react'
import { useNavigate, useLocation, Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Network, AlertCircle } from 'lucide-react'
import { useAuthStore } from '../store/useAuthStore'
import { APP_VERSION, IS_PRODUCTION } from '../constants'
import { logger } from '../utils/logger'

export function LoginPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const location = useLocation()
  const login = useAuthStore((state) => state.login)
  const isLoading = useAuthStore((state) => state.isLoading)
  const error = useAuthStore((state) => state.error)
  const clearError = useAuthStore((state) => state.clearError)

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')

  /**
   * Redirect destination after successful login
   * Preserves original route from ProtectedRoute or defaults to home
   */
  const from = (location.state as any)?.from?.pathname || '/'

  /**
   * Handle login form submission
   * Calls Zustand login action and navigates to preserved destination on success
   */
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    clearError()

    try {
      await login(username, password)
      navigate(from, { replace: true })
    } catch (err) {
      logger.error('Login failed:', err)
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-primary-50 to-primary-100 flex items-center justify-center px-4">
      <div className="max-w-md w-full bg-white rounded-lg shadow-xl p-8">
        {/* Logo and Title */}
        <div className="flex flex-col items-center mb-8">
          <Network className="w-16 h-16 text-primary-600 mb-4" aria-hidden="true" />
          <h1 className="text-2xl font-bold text-gray-900">{t('app.title')}</h1>
          <p className="text-sm text-gray-600 mt-2">{t('app.subtitle')}</p>
          {!IS_PRODUCTION && <p className="text-sm text-gray-600 mt-1">v{APP_VERSION}</p>}
        </div>

        {/* Login Form */}
        <form onSubmit={handleSubmit} className="space-y-6">
          {error && (
            <div
              className="bg-red-50 border border-red-200 rounded-lg p-3 flex items-start gap-2"
              role="alert"
            >
              <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" aria-hidden="true" />
              <p className="text-sm text-red-800">{error}</p>
            </div>
          )}

          <div>
            <label htmlFor="username" className="block text-sm font-medium text-gray-700 mb-2">
              {t('auth.username')}
            </label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              autoFocus
              autoComplete="username"
              disabled={isLoading}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-600 disabled:opacity-50 disabled:cursor-not-allowed"
              aria-required="true"
            />
          </div>

          <div>
            <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-2">
              {t('auth.password')}
            </label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              autoComplete="current-password"
              disabled={isLoading}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-600 disabled:opacity-50 disabled:cursor-not-allowed"
              aria-required="true"
            />
          </div>

          <div className="flex items-center justify-end">
            <Link
              to="/password-reset-request"
              className="text-sm text-primary-600 hover:text-primary-700 focus:outline-none focus:underline"
            >
              {t('auth.forgotPassword')}
            </Link>
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className="w-full bg-primary-600 text-white py-2 px-4 rounded-lg hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            aria-label={isLoading ? t('auth.loggingIn') : t('auth.login')}
          >
            {isLoading ? t('auth.loggingIn') : t('auth.login')}
          </button>
        </form>

        {/* Link to Register */}
        <div className="mt-6 text-center">
          <p className="text-sm text-gray-600">
            {t('register.noAccount')}{' '}
            <Link to="/register" className="text-primary-600 hover:text-primary-700 font-medium">
              {t('register.createAccount')}
            </Link>
          </p>
        </div>
      </div>
    </div>
  )
}
