/**
 * User profile management page for current authenticated user
 * - Self-service profile editing: email, full name (username immutable)
 * - Integrated password change form component with separate section
 * - Form state management with controlled inputs and isEditing tracking
 * - React Query mutations with success messages and auto-clearing timeouts
 * - Displays user roles (read-only) - only admins can modify roles via UserEditPage
 */
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { User, AlertCircle, CheckCircle, ArrowLeft } from 'lucide-react'
import { useCurrentUser, useUpdateUser } from '../hooks/useUsers'
import { PasswordChangeForm } from '../components/PasswordChangeForm'
import { logger } from '../utils/logger'

export function ProfilePage() {
  const { t } = useTranslation()
  const { data: currentUser, isLoading, error } = useCurrentUser()
  const updateUserMutation = useUpdateUser()

  const [email, setEmail] = useState('')
  const [fullName, setFullName] = useState('')
  const [successMessage, setSuccessMessage] = useState('')
  const [isEditing, setIsEditing] = useState(false)

  // Initialize form values when user data loads
  if (currentUser && !isEditing && !email && !fullName) {
    setEmail(currentUser.email)
    setFullName(currentUser.full_name || '')
  }

  /**
   * Handle profile update form submission
   * Updates email and full name via React Query mutation
   * Shows success message with 3s auto-clear timeout
   */
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSuccessMessage('')

    if (!currentUser) return

    try {
      await updateUserMutation.mutateAsync({
        id: currentUser.id,
        data: {
          email,
          full_name: fullName || undefined,
        },
      })

      // Show success message
      setSuccessMessage(t('profile.updated'))
      setIsEditing(false)

      // Clear success message after 3 seconds
      setTimeout(() => {
        setSuccessMessage('')
      }, 3000)
    } catch (err: any) {
      // Error is stored in mutation.error
      logger.error('Profile update failed:', err)
    }
  }

  /**
   * Handle cancel button - reset form to original values
   * Reverts changes, exits edit mode, and clears mutation state
   */
  const handleCancel = () => {
    if (currentUser) {
      setEmail(currentUser.email)
      setFullName(currentUser.full_name || '')
      setIsEditing(false)
      updateUserMutation.reset()
    }
  }

  /**
   * Extract error message from mutation error
   * Priority: API response message > error.message > generic fallback
   */
  const errorMessage = updateUserMutation.error
    ? (updateUserMutation.error as any)?.response?.data?.message ||
      (updateUserMutation.error as any)?.message ||
      'Update failed'
    : null

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-screen bg-gray-50">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600" />
      </div>
    )
  }

  if (error || !currentUser) {
    return (
      <div className="flex items-center justify-center h-screen bg-gray-50">
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 flex items-start gap-2">
          <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" aria-hidden="true" />
          <p className="text-sm text-red-800">Failed to load user profile</p>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-4xl mx-auto px-4 space-y-6">
        {/* Page Header */}
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <User className="w-8 h-8 text-primary-600" aria-hidden="true" />
              <div>
                <h1 className="text-2xl font-bold text-gray-900">{t('profile.title')}</h1>
                <p className="text-sm text-gray-600">
                  @{currentUser.username} • {currentUser.roles.join(', ')}
                </p>
              </div>
            </div>
            <Link
              to="/"
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-2 transition-colors"
            >
              <ArrowLeft className="w-4 h-4" aria-hidden="true" />
              {t('common.backToDashboard')}
            </Link>
          </div>
        </div>

        {/* Basic Information Section */}
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-6">{t('profile.basicInfo')}</h2>

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
              <label htmlFor="username" className="block text-sm font-medium text-gray-700 mb-2">
                {t('register.username')}
              </label>
              <input
                id="username"
                type="text"
                value={currentUser.username}
                disabled
                className="w-full px-3 py-2 border border-gray-300 rounded-lg bg-gray-50 text-gray-500 cursor-not-allowed"
              />
              <p className="mt-1 text-xs text-gray-500">Username cannot be changed</p>
            </div>

            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-2">
                {t('register.email')}
              </label>
              <input
                id="email"
                type="email"
                value={email}
                onChange={(e) => {
                  setEmail(e.target.value)
                  setIsEditing(true)
                }}
                required
                disabled={updateUserMutation.isPending}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-600 disabled:opacity-50 disabled:cursor-not-allowed"
              />
            </div>

            <div>
              <label htmlFor="fullName" className="block text-sm font-medium text-gray-700 mb-2">
                {t('register.fullName')}
              </label>
              <input
                id="fullName"
                type="text"
                value={fullName}
                onChange={(e) => {
                  setFullName(e.target.value)
                  setIsEditing(true)
                }}
                disabled={updateUserMutation.isPending}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-600 disabled:opacity-50 disabled:cursor-not-allowed"
              />
            </div>

            {isEditing && (
              <div className="flex gap-3">
                <button
                  type="submit"
                  disabled={updateUserMutation.isPending}
                  className="flex-1 bg-primary-600 text-white py-2 px-4 rounded-lg hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {updateUserMutation.isPending ? t('common.loading') : t('profile.updateProfile')}
                </button>
                <button
                  type="button"
                  onClick={handleCancel}
                  disabled={updateUserMutation.isPending}
                  className="flex-1 bg-gray-200 text-gray-700 py-2 px-4 rounded-lg hover:bg-gray-300 focus:outline-none focus:ring-2 focus:ring-gray-400 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {t('common.cancel')}
                </button>
              </div>
            )}
          </form>
        </div>

        {/* Password Change Section */}
        <PasswordChangeForm userId={currentUser.id} />
      </div>
    </div>
  )
}
