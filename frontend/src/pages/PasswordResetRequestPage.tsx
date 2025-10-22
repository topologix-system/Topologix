/**
 * Password reset request page (step 1 of password reset flow)
 * - Email input form that sends password reset link via email
 * - React Query mutation with success/error state management
 * - Conditional rendering: shows success message after submission
 * - Backend sends reset token via email for step 2 (PasswordResetPage)
 * - Links back to login page for easy navigation
 */
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation } from '@tanstack/react-query'
import { Network, AlertCircle, CheckCircle, ArrowLeft } from 'lucide-react'
import { authAPI } from '../services/api'
import { APP_VERSION, IS_PRODUCTION } from '../constants'

export function PasswordResetRequestPage() {
  const { t } = useTranslation()
  const [email, setEmail] = useState('')

  /**
   * React Query mutation for password reset request API call
   * Sends reset link email to provided address
   * On success: displays confirmation message
   */
  const mutation = useMutation({
    mutationFn: (email: string) => authAPI.requestPasswordReset(email),
    onSuccess: () => {
      // Keep email visible for user confirmation
    },
    onError: (error: any) => {
      console.error('Password reset request failed:', error)
    }
  })

  /**
   * Handle password reset request form submission
   * Triggers mutation with email address to send reset link
   */
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    mutation.mutate(email)
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-primary-50 to-primary-100 flex items-center justify-center px-4">
      <div className="max-w-md w-full bg-white rounded-lg shadow-xl p-8">
        {/* Logo and Title */}
        <div className="flex flex-col items-center mb-8">
          <Network className="w-16 h-16 text-primary-600 mb-4" aria-hidden="true" />
          <h1 className="text-2xl font-bold text-gray-900">{t('passwordReset.title')}</h1>
          <p className="text-sm text-gray-600 mt-2 text-center">
            {t('passwordReset.description')}
          </p>
          {!IS_PRODUCTION && <p className="text-sm text-gray-600 mt-1">v{APP_VERSION}</p>}
        </div>

        {mutation.isSuccess ? (
          /* Success Message */
          <div className="space-y-6">
            <div
              className="bg-green-50 border border-green-200 rounded-lg p-4 flex items-start gap-3"
              role="alert"
            >
              <CheckCircle className="w-5 h-5 text-green-600 flex-shrink-0 mt-0.5" aria-hidden="true" />
              <div>
                <p className="text-sm font-medium text-green-800">
                  {t('passwordReset.successTitle')}
                </p>
                <p className="text-sm text-green-700 mt-1">
                  {t('passwordReset.successMessage')}
                </p>
              </div>
            </div>

            <Link
              to="/login"
              className="flex items-center justify-center gap-2 w-full py-2 px-4 bg-primary-600 text-white rounded-lg hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-2 transition-colors"
            >
              <ArrowLeft className="w-4 h-4" aria-hidden="true" />
              {t('passwordReset.backToLogin')}
            </Link>
          </div>
        ) : (
          /* Request Form */
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
                    : t('passwordReset.error')}
                </p>
              </div>
            )}

            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-2">
                {t('passwordReset.email')}
              </label>
              <input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoFocus
                autoComplete="email"
                disabled={mutation.isPending}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-600 disabled:opacity-50 disabled:cursor-not-allowed"
                aria-required="true"
                placeholder={t('passwordReset.emailPlaceholder')}
              />
            </div>

            <button
              type="submit"
              disabled={mutation.isPending}
              className="w-full py-2 px-4 bg-primary-600 text-white rounded-lg hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {mutation.isPending ? t('passwordReset.sending') : t('passwordReset.sendResetLink')}
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
