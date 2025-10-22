/**
 * Admin-only user management page for editing other users
 * - Role-based access control: requires admin role to access
 * - Manages user email, full name, roles (admin/engineer/viewer), and account status
 * - Form state management with controlled inputs and isEditing tracking
 * - React Query mutations for optimistic updates with auto-navigation after success
 * - Cannot modify username (immutable) or superuser status
 */
import { useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { User, AlertCircle, CheckCircle, ArrowLeft } from 'lucide-react'
import { useUser, useUpdateUser } from '../hooks/useUsers'
import { authAPI } from '../services/api'

export function UserEditPage() {
  const { t } = useTranslation()
  const { id } = useParams<{ id: string }>()
  const userId = parseInt(id || '0', 10)
  const navigate = useNavigate()

  const { data: user, isLoading, error } = useUser(userId)
  const updateUserMutation = useUpdateUser()

  const [email, setEmail] = useState('')
  const [fullName, setFullName] = useState('')
  const [selectedRoles, setSelectedRoles] = useState<string[]>([])
  const [isActive, setIsActive] = useState(true)
  const [successMessage, setSuccessMessage] = useState('')
  const [isEditing, setIsEditing] = useState(false)

  /**
   * Check if current user has admin role for access control
   * Non-admin users will see access denied message
   */
  const isAdmin = authAPI.hasRole('admin')

  /**
   * Initialize form fields from user data when component mounts
   * Only runs once when user data first loads (checks empty state)
   * Populates email, full name, roles, and active status
   */
  if (user && !isEditing && !email && !fullName) {
    setEmail(user.email)
    setFullName(user.full_name || '')
    setSelectedRoles(user.roles)
    setIsActive(user.is_active)
  }

  /**
   * Handle user update form submission
   * Updates user email, full name, roles, and active status via React Query
   * Shows success message and navigates back to user management page after 2s
   */
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSuccessMessage('')

    if (!user) return

    try {
      await updateUserMutation.mutateAsync({
        id: userId,
        data: {
          email,
          full_name: fullName || undefined,
          roles: selectedRoles,
          is_active: isActive,
        },
      })

      // Show success message
      setSuccessMessage(t('userEdit.updated'))
      setIsEditing(false)

      // Clear success message and navigate back after 2 seconds
      setTimeout(() => {
        setSuccessMessage('')
        navigate('/admin/users')
      }, 2000)
    } catch (err: any) {
      console.error('User update failed:', err)
    }
  }

  /**
   * Handle cancel button - revert all changes to original values
   * Resets form fields to user data and clears mutation error state
   */
  const handleCancel = () => {
    if (user) {
      setEmail(user.email)
      setFullName(user.full_name || '')
      setSelectedRoles(user.roles)
      setIsActive(user.is_active)
      setIsEditing(false)
      updateUserMutation.reset()
    }
  }

  /**
   * Toggle role selection for user
   * Adds or removes role from selectedRoles array based on current state
   * Sets isEditing flag to enable save/cancel buttons
   */
  const handleRoleToggle = (role: string) => {
    setIsEditing(true)
    if (selectedRoles.includes(role)) {
      setSelectedRoles(selectedRoles.filter((r) => r !== role))
    } else {
      setSelectedRoles([...selectedRoles, role])
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

  if (!isAdmin) {
    return (
      <div className="flex items-center justify-center h-screen bg-gray-50">
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 flex items-start gap-2">
          <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" aria-hidden="true" />
          <div>
            <p className="text-sm font-medium text-red-800">Access Denied</p>
            <p className="text-xs text-red-600 mt-1">
              You need admin privileges to access this page.
            </p>
          </div>
        </div>
      </div>
    )
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-screen bg-gray-50">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600" />
      </div>
    )
  }

  if (error || !user) {
    return (
      <div className="flex items-center justify-center h-screen bg-gray-50">
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 flex items-start gap-2">
          <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" aria-hidden="true" />
          <p className="text-sm text-red-800">Failed to load user</p>
        </div>
      </div>
    )
  }

  /**
   * Available role options for user assignment
   * - admin: Full system access including user management
   * - engineer: Network configuration and analysis access
   * - viewer: Read-only access to topology and analysis
   */
  const availableRoles = ['admin', 'engineer', 'viewer']

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-4xl mx-auto px-4 space-y-6">
        {/* Back Navigation */}
        <Link
          to="/admin/users"
          className="inline-flex items-center gap-2 text-sm text-gray-600 hover:text-gray-900 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" aria-hidden="true" />
          {t('common.back')}
        </Link>

        {/* Page Header */}
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center gap-3">
            <User className="w-8 h-8 text-primary-600" aria-hidden="true" />
            <div>
              <h1 className="text-2xl font-bold text-gray-900">{t('userEdit.title')}</h1>
              <p className="text-sm text-gray-600">
                @{user.username}
                {user.is_superuser && (
                  <span className="ml-2 text-xs text-primary-600 font-medium">(Superuser)</span>
                )}
              </p>
            </div>
          </div>
        </div>

        {/* User Information Form */}
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-6">{t('userEdit.basicInfo')}</h2>

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
                value={user.username}
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

            {/* Roles Selection */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                {t('userEdit.roles')}
              </label>
              <div className="flex flex-wrap gap-2">
                {availableRoles.map((role) => (
                  <button
                    key={role}
                    type="button"
                    onClick={() => handleRoleToggle(role)}
                    disabled={updateUserMutation.isPending}
                    className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${
                      selectedRoles.includes(role)
                        ? 'bg-primary-600 text-white'
                        : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
                    }`}
                  >
                    {role}
                  </button>
                ))}
              </div>
              <p className="mt-1 text-xs text-gray-500">
                {t('userEdit.rolesHelp')}
              </p>
            </div>

            {/* Account Status */}
            <div>
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={isActive}
                  onChange={(e) => {
                    setIsActive(e.target.checked)
                    setIsEditing(true)
                  }}
                  disabled={updateUserMutation.isPending}
                  className="w-4 h-4 text-primary-600 border-gray-300 rounded focus:ring-primary-600 disabled:opacity-50 disabled:cursor-not-allowed"
                />
                <span className="text-sm font-medium text-gray-700">{t('userEdit.accountActive')}</span>
              </label>
              <p className="mt-1 text-xs text-gray-500 ml-6">
                {t('userEdit.accountActiveHelp')}
              </p>
            </div>

            {isEditing && (
              <div className="flex gap-3 pt-4">
                <button
                  type="submit"
                  disabled={updateUserMutation.isPending}
                  className="flex-1 bg-primary-600 text-white py-2 px-4 rounded-lg hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {updateUserMutation.isPending ? t('common.loading') : t('userEdit.saveChanges')}
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
      </div>
    </div>
  )
}
