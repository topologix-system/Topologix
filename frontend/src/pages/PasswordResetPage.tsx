/**
 * Password reset confirmation page (step 2 of password reset flow)
 * - Token-based password reset from email link (/password-reset/:token route)
 * - Password/confirm password fields with show/hide toggles (Eye/EyeOff icons)
 * - Integrated PasswordPolicyHelper for real-time password strength feedback
 * - Client-side validation: password mismatch detection before API call
 * - Token validation: shows error page if token missing or invalid
 * - Auto-redirect to login page after successful reset (2s delay)
 */
import { useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation } from '@tanstack/react-query'
import { Network, AlertCircle, Eye, EyeOff } from 'lucide-react'
import { authAPI } from '../services/api'
import { PasswordPolicyHelper } from '../components/PasswordPolicyHelper'
import { APP_VERSION, IS_PRODUCTION } from '../constants'

export function PasswordResetPage() {
  const { t } = useTranslation()
  const { token } = useParams<{ token: string }>()
  const navigate = useNavigate()

  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)
  const [passwordMismatch, setPasswordMismatch] = useState(false)

  /**
   * React Query mutation for password reset API call
   * On success: redirects to login page after 2s delay
   * On error: displays error message from API
   */
  const mutation = useMutation({
    mutationFn: ({ token, password }: { token: string; password: string }) =>
      authAPI.resetPassword(token, password),
    onSuccess: () => {
      // Redirect to login after a brief delay
      setTimeout(() => {
        navigate('/login', { state: { message: t('passwordReset.resetSuccess') } })
      }, 2000)
    },
    onError: (error: any) => {
      console.error('Password reset failed:', error)
    }
  })

  /**
   * Handle password reset form submission
   * Validates password match before calling mutation
   * Requires valid token from URL params
   */
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    // Check if passwords match
    if (password !== confirmPassword) {
      setPasswordMismatch(true)
      return
    }

    setPasswordMismatch(false)

    if (!token) {
      return
    }

    mutation.mutate({ token, password })
  }

  // Show error if token is missing
  if (!token) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-primary-50 to-primary-100 flex items-center justify-center px-4">
        <div className="max-w-md w-full bg-white rounded-lg shadow-xl p-8">
          <div className="flex flex-col items-center mb-8">
            <Network className="w-16 h-16 text-primary-600 mb-4" aria-hidden="true" />
            <h1 className="text-2xl font-bold text-gray-900">{t('passwordReset.invalidToken')}</h1>
          </div>
          <div
            className="bg-red-50 border border-red-200 rounded-lg p-3 flex items-start gap-2 mb-6"
            role="alert"
          >
            <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" aria-hidden="true" />
            <p className="text-sm text-red-800">{t('passwordReset.invalidTokenMessage')}</p>
          </div>
          <Link
            to="/password-reset-request"
            className="w-full block text-center py-2 px-4 bg-primary-600 text-white rounded-lg hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-2"
          >
            {t('passwordReset.requestNewLink')}
          </Link>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-primary-50 to-primary-100 flex items-center justify-center px-4">
      <div className="max-w-md w-full bg-white rounded-lg shadow-xl p-8">
        {/* Logo and Title */}
        <div className="flex flex-col items-center mb-8">
          <Network className="w-16 h-16 text-primary-600 mb-4" aria-hidden="true" />
          <h1 className="text-2xl font-bold text-gray-900">{t('passwordReset.resetTitle')}</h1>
          <p className="text-sm text-gray-600 mt-2 text-center">
            {t('passwordReset.resetDescription')}
          </p>
          {!IS_PRODUCTION && <p className="text-sm text-gray-600 mt-1">v{APP_VERSION}</p>}
        </div>

        {mutation.isSuccess ? (
          /* Success Message */
          <div
            className="bg-green-50 border border-green-200 rounded-lg p-4 flex items-start gap-3"
            role="alert"
          >
            <div>
              <p className="text-sm font-medium text-green-800">
                {t('passwordReset.resetSuccessTitle')}
              </p>
              <p className="text-sm text-green-700 mt-1">
                {t('passwordReset.redirectingToLogin')}
              </p>
            </div>
          </div>
        ) : (
          /* Reset Form */
          <form onSubmit={handleSubmit} className="space-y-6">
            {mutation.isError && (
              <div
                className="bg-red-50 border border-red-200 rounded-lg p-3 flex items-start gap-2"
                role="alert"
              >
                <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" aria-hidden="true" />
                <p className="text-sm text-red-800">
                  {mutation.error instanceof Error
                    ? mutation.error.message
                    : t('passwordReset.resetError')}
                </p>
              </div>
            )}

            {passwordMismatch && (
              <div
                className="bg-red-50 border border-red-200 rounded-lg p-3 flex items-start gap-2"
                role="alert"
              >
                <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" aria-hidden="true" />
                <p className="text-sm text-red-800">{t('passwordReset.passwordMismatch')}</p>
              </div>
            )}

            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-2">
                {t('passwordReset.newPassword')}
              </label>
              <div className="relative">
                <input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  autoFocus
                  autoComplete="new-password"
                  disabled={mutation.isPending}
                  className="w-full px-3 py-2 pr-10 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-600 disabled:opacity-50 disabled:cursor-not-allowed"
                  aria-required="true"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-700"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? (
                    <EyeOff className="w-5 h-5" aria-hidden="true" />
                  ) : (
                    <Eye className="w-5 h-5" aria-hidden="true" />
                  )}
                </button>
              </div>
            </div>

            <div>
              <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700 mb-2">
                {t('passwordReset.confirmPassword')}
              </label>
              <div className="relative">
                <input
                  id="confirmPassword"
                  type={showConfirmPassword ? 'text' : 'password'}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  required
                  autoComplete="new-password"
                  disabled={mutation.isPending}
                  className="w-full px-3 py-2 pr-10 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-600 disabled:opacity-50 disabled:cursor-not-allowed"
                  aria-required="true"
                />
                <button
                  type="button"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-700"
                  aria-label={showConfirmPassword ? 'Hide password' : 'Show password'}
                >
                  {showConfirmPassword ? (
                    <EyeOff className="w-5 h-5" aria-hidden="true" />
                  ) : (
                    <Eye className="w-5 h-5" aria-hidden="true" />
                  )}
                </button>
              </div>
            </div>

            {/* Password Policy Helper */}
            <PasswordPolicyHelper password={password} />

            <button
              type="submit"
              disabled={mutation.isPending}
              className="w-full py-2 px-4 bg-primary-600 text-white rounded-lg hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {mutation.isPending ? t('passwordReset.resetting') : t('passwordReset.resetPassword')}
            </button>

            <div className="text-center">
              <Link
                to="/login"
                className="text-sm text-primary-600 hover:text-primary-700 focus:outline-none focus:underline"
              >
                {t('passwordReset.backToLogin')}
              </Link>
            </div>
          </form>
        )}
      </div>
    </div>
  )
}
