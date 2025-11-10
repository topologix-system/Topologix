/**
 * New user registration page with password policy enforcement
 * - Form validation with username, email, password, and full name fields
 * - Integrated PasswordPolicyHelper component for real-time password strength feedback
 * - React Query mutation with success message and auto-redirect to login (2s delay)
 * - Error handling with user-friendly messages from API responses
 * - Links back to login page for existing users
 */
import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Network, AlertCircle, CheckCircle } from 'lucide-react'
import { useRegister } from '../hooks/useUsers'
import { APP_VERSION, IS_PRODUCTION } from '../constants'
import { PasswordPolicyHelper } from '../components/PasswordPolicyHelper'
import { logger } from '../utils/logger'

export function RegisterPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const registerMutation = useRegister()

  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [fullName, setFullName] = useState('')
  const [successMessage, setSuccessMessage] = useState('')

  /**
   * Handle registration form submission
   * Creates new user account via React Query mutation
   * Shows success message and redirects to login after 2s
   */
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSuccessMessage('')

    try {
      await registerMutation.mutateAsync({
        username,
        email,
        password,
        full_name: fullName || undefined,
      })

      // Show success message
      setSuccessMessage(t('register.success'))

      // Redirect to login after 2 seconds
      setTimeout(() => {
        navigate('/login')
      }, 2000)
    } catch (err: any) {
      // Error is stored in mutation.error
      logger.error('Registration failed:', err)
    }
  }

  /**
   * Extract error message from registration mutation error
   * Priority: API response message > error.message > translation fallback
   */
  const errorMessage = registerMutation.error
    ? (registerMutation.error as any)?.response?.data?.message ||
      (registerMutation.error as any)?.message ||
      t('register.failed')
    : null

  return (
    <div className="min-h-screen bg-gradient-to-br from-primary-50 to-primary-100 flex items-center justify-center px-4">
      <div className="max-w-md w-full bg-white rounded-lg shadow-xl p-8">
        {/* Logo and Title */}
        <div className="flex flex-col items-center mb-8">
          <Network className="w-16 h-16 text-primary-600 mb-4" aria-hidden="true" />
          <h1 className="text-2xl font-bold text-gray-900">{t('register.title')}</h1>
          {!IS_PRODUCTION && <p className="text-sm text-gray-600 mt-1">v{APP_VERSION}</p>}
        </div>

        {/* Registration Form */}
        <form onSubmit={handleSubmit} className="space-y-6">
          {errorMessage && (
            <div
              className="bg-red-50 border border-red-200 rounded-lg p-3 flex items-start gap-2"
              role="alert"
            >
              <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" aria-hidden="true" />
              <p className="text-sm text-red-800">{errorMessage}</p>
            </div>
          )}

          {successMessage && (
            <div
              className="bg-green-50 border border-green-200 rounded-lg p-3 flex items-start gap-2"
              role="alert"
            >
              <CheckCircle className="w-5 h-5 text-green-600 flex-shrink-0 mt-0.5" aria-hidden="true" />
              <p className="text-sm text-green-800">{successMessage}</p>
            </div>
          )}

          <div>
            <label htmlFor="username" className="block text-sm font-medium text-gray-700 mb-2">
              {t('register.username')}
            </label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              autoFocus
              autoComplete="username"
              disabled={registerMutation.isPending}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-600 disabled:opacity-50 disabled:cursor-not-allowed"
              aria-required="true"
            />
          </div>

          <div>
            <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-2">
              {t('register.email')}
            </label>
            <input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              autoComplete="email"
              disabled={registerMutation.isPending}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-600 disabled:opacity-50 disabled:cursor-not-allowed"
              aria-required="true"
            />
          </div>

          <div>
            <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-2">
              {t('register.password')}
            </label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              autoComplete="new-password"
              disabled={registerMutation.isPending}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-600 disabled:opacity-50 disabled:cursor-not-allowed"
              aria-required="true"
            />
            <PasswordPolicyHelper password={password} className="mt-3" />
          </div>

          <div>
            <label htmlFor="fullName" className="block text-sm font-medium text-gray-700 mb-2">
              {t('register.fullName')}
            </label>
            <input
              id="fullName"
              type="text"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              autoComplete="name"
              disabled={registerMutation.isPending}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-600 disabled:opacity-50 disabled:cursor-not-allowed"
            />
          </div>

          <button
            type="submit"
            disabled={registerMutation.isPending}
            className="w-full bg-primary-600 text-white py-2 px-4 rounded-lg hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            aria-label={registerMutation.isPending ? t('register.creating') : t('register.createAccount')}
          >
            {registerMutation.isPending ? t('register.creating') : t('register.createAccount')}
          </button>
        </form>

        {/* Link to Login */}
        <div className="mt-6 text-center">
          <p className="text-sm text-gray-600">
            {t('register.haveAccount')}{' '}
            <Link to="/login" className="text-primary-600 hover:text-primary-700 font-medium">
              {t('register.backToLogin')}
            </Link>
          </p>
        </div>
      </div>
    </div>
  )
}
