/**
 * Password change form component for user profile page
 * - Three-field validation: current password, new password, confirm password
 * - Client-side validation: password mismatch detection, minimum 12 characters
 * - Integrated PasswordPolicyHelper for real-time password strength feedback
 * - React Query mutation with success message and field clearing on success
 * - Used in ProfilePage for authenticated users to change their own password
 */
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { AlertCircle, CheckCircle, Lock } from 'lucide-react'
import { useChangePassword } from '../hooks/useUsers'
import { PasswordPolicyHelper } from './PasswordPolicyHelper'
import { logger } from '../utils/logger'

interface PasswordChangeFormProps {
  userId: number
}

export function PasswordChangeForm({ userId }: PasswordChangeFormProps) {
  const { t } = useTranslation()
  const changePasswordMutation = useChangePassword()

  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [validationError, setValidationError] = useState('')
  const [successMessage, setSuccessMessage] = useState('')

  /**
   * Handle password change form submission
   * Validates password match and minimum length before submitting
   * Clears form fields on success
   */
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setValidationError('')
    setSuccessMessage('')

    if (newPassword !== confirmPassword) {
      setValidationError(t('profile.passwordMismatch'))
      return
    }

    if (newPassword.length < 12) {
      setValidationError('Password must be at least 12 characters')
      return
    }

    try {
      await changePasswordMutation.mutateAsync({
        id: userId,
        data: {
          current_password: currentPassword,
          new_password: newPassword,
        },
      })

      setSuccessMessage(t('profile.passwordChanged'))

      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')
    } catch (err: any) {
      logger.error('Password change failed:', err)
    }
  }

  /**
   * Unified error message display
   * Priority: validation error > API error response > generic error message
   */
  const errorMessage =
    validationError ||
    (changePasswordMutation.error
      ? (changePasswordMutation.error as any)?.response?.data?.message ||
        (changePasswordMutation.error as any)?.message ||
        'Password change failed'
      : null)

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <div className="flex items-center gap-2 mb-6">
        <Lock className="w-5 h-5 text-gray-700" aria-hidden="true" />
        <h2 className="text-lg font-semibold text-gray-900">{t('profile.changePassword')}</h2>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
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
          <label htmlFor="currentPassword" className="block text-sm font-medium text-gray-700 mb-2">
            {t('profile.currentPassword')}
          </label>
          <input
            id="currentPassword"
            type="password"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            required
            autoComplete="current-password"
            disabled={changePasswordMutation.isPending}
            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-600 disabled:opacity-50 disabled:cursor-not-allowed"
            aria-required="true"
          />
        </div>

        <div>
          <label htmlFor="newPassword" className="block text-sm font-medium text-gray-700 mb-2">
            {t('profile.newPassword')}
          </label>
          <input
            id="newPassword"
            type="password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            required
            autoComplete="new-password"
            disabled={changePasswordMutation.isPending}
            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-600 disabled:opacity-50 disabled:cursor-not-allowed"
            aria-required="true"
          />
          <PasswordPolicyHelper password={newPassword} className="mt-3" />
        </div>

        <div>
          <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700 mb-2">
            {t('profile.confirmPassword')}
          </label>
          <input
            id="confirmPassword"
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            required
            autoComplete="new-password"
            disabled={changePasswordMutation.isPending}
            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-600 disabled:opacity-50 disabled:cursor-not-allowed"
            aria-required="true"
          />
        </div>

        <button
          type="submit"
          disabled={changePasswordMutation.isPending}
          className="w-full bg-primary-600 text-white py-2 px-4 rounded-lg hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          {changePasswordMutation.isPending ? t('common.loading') : t('profile.changePassword')}
        </button>
      </form>
    </div>
  )
}
