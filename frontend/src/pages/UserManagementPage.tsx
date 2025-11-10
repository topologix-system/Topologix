/**
 * Admin-only user list management page
 * - Role-based access control: requires admin role to access
 * - Displays all registered users in UserTable component with role badges
 * - Delete user functionality with confirmation dialogs (handled by UserTable)
 * - React Query for user list fetching and delete mutations
 * - Current user cannot delete themselves (enforced in UserTable)
 */
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { Users, AlertCircle, ArrowLeft } from 'lucide-react'
import { useUsers, useCurrentUser, useDeleteUser } from '../hooks/useUsers'
import { UserTable } from '../components/UserTable'
import { authAPI } from '../services/api'
import { logger } from '../utils/logger'

export function UserManagementPage() {
  const { t } = useTranslation()
  const { data: currentUser } = useCurrentUser()
  const { data: users, isLoading, error } = useUsers()
  const deleteUserMutation = useDeleteUser()

  /**
   * Check if current user has admin role for access control
   * Non-admin users will see access denied message
   */
  const isAdmin = authAPI.hasRole('admin')

  /**
   * Handle user deletion via React Query mutation
   * Called by UserTable component after confirmation dialog
   * Error messages are displayed from mutation.error state
   */
  const handleDelete = async (userId: number) => {
    try {
      await deleteUserMutation.mutateAsync(userId)
    } catch (err: any) {
      logger.error('User deletion failed:', err)
    }
  }

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

  if (error) {
    return (
      <div className="flex items-center justify-center h-screen bg-gray-50">
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 flex items-start gap-2">
          <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" aria-hidden="true" />
          <p className="text-sm text-red-800">Failed to load users</p>
        </div>
      </div>
    )
  }

  /**
   * Extract error message from delete mutation error
   * Priority: API response message > error.message > translation fallback
   */
  const errorMessage = deleteUserMutation.error
    ? (deleteUserMutation.error as any)?.response?.data?.message ||
      (deleteUserMutation.error as any)?.message ||
      t('users.deleteFailed')
    : null

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-7xl mx-auto px-4 space-y-6">
        {/* Page Header */}
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Users className="w-8 h-8 text-primary-600" aria-hidden="true" />
              <div>
                <h1 className="text-2xl font-bold text-gray-900">{t('users.title')}</h1>
                <p className="text-sm text-gray-600 mt-1">
                  {users?.length || 0} {users?.length === 1 ? 'user' : 'users'} registered
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

        {/* Error Message */}
        {errorMessage && (
          <div
            className="bg-red-50 border border-red-200 rounded-lg p-4 flex items-start gap-2"
            role="alert"
          >
            <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" aria-hidden="true" />
            <p className="text-sm text-red-800">{errorMessage}</p>
          </div>
        )}

        {/* User Table */}
        {users && currentUser && (
          <UserTable
            users={users}
            currentUserId={currentUser.id}
            onDelete={handleDelete}
            isDeleting={deleteUserMutation.isPending}
          />
        )}
      </div>
    </div>
  )
}
