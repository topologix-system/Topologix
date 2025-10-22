/**
 * User management table component for admin dashboard
 * - Displays user list with ID, username, email, roles, and active status
 * - Edit user functionality via React Router Link
 * - Delete confirmation flow with two-step process (prevents accidental deletion)
 * - Prevents users from deleting themselves (safety check)
 * - Visual indicators: Shield icon for superusers, "(You)" label for current user
 * - Used in UserManagementPage for admin user CRUD operations
 */
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Edit2, Trash2, Shield, CheckCircle, XCircle } from 'lucide-react'
import type { User } from '../types'

interface UserTableProps {
  users: User[]
  currentUserId: number
  onDelete: (userId: number) => void
  isDeleting: boolean
}

export function UserTable({ users, currentUserId, onDelete, isDeleting }: UserTableProps) {
  const { t } = useTranslation()
  const [deleteConfirmId, setDeleteConfirmId] = useState<number | null>(null)

  /**
   * Initiates delete confirmation flow by setting deleteConfirmId
   * Shows confirm/cancel buttons for the specific user row
   */
  const handleDeleteClick = (userId: number) => {
    setDeleteConfirmId(userId)
  }

  /**
   * Confirms deletion and triggers parent onDelete callback
   * Resets confirmation state after initiating deletion
   */
  const handleDeleteConfirm = (userId: number) => {
    onDelete(userId)
    setDeleteConfirmId(null)
  }

  /**
   * Cancels delete operation and returns to normal table view
   * Clears deleteConfirmId to hide confirm/cancel buttons
   */
  const handleDeleteCancel = () => {
    setDeleteConfirmId(null)
  }

  return (
    <div className="bg-white rounded-lg shadow overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead className="bg-gray-50 border-b border-gray-200">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                ID
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                {t('register.username')}
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                {t('register.email')}
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Roles
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                {t('common.status')}
              </th>
              <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {users.map((user) => (
              <tr key={user.id} className="hover:bg-gray-50">
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{user.id}</td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-gray-900">{user.username}</span>
                    {user.is_superuser && (
                      <Shield className="w-4 h-4 text-primary-600" title="Superuser" aria-label="Superuser" />
                    )}
                    {user.id === currentUserId && (
                      <span className="text-xs text-primary-600 font-medium">(You)</span>
                    )}
                  </div>
                  {user.full_name && (
                    <div className="text-xs text-gray-500">{user.full_name}</div>
                  )}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{user.email}</td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="flex flex-wrap gap-1">
                    {user.roles.map((role) => (
                      <span
                        key={role}
                        className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-primary-100 text-primary-800"
                      >
                        {role}
                      </span>
                    ))}
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  {user.is_active ? (
                    <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                      <CheckCircle className="w-3 h-3" aria-hidden="true" />
                      Active
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium bg-red-100 text-red-800">
                      <XCircle className="w-3 h-3" aria-hidden="true" />
                      Inactive
                    </span>
                  )}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                  {deleteConfirmId === user.id ? (
                    <div className="flex items-center justify-end gap-2">
                      <button
                        onClick={() => handleDeleteConfirm(user.id)}
                        disabled={isDeleting}
                        className="text-red-600 hover:text-red-900 disabled:opacity-50 disabled:cursor-not-allowed"
                        aria-label="Confirm delete"
                      >
                        {t('common.confirm')}
                      </button>
                      <button
                        onClick={handleDeleteCancel}
                        disabled={isDeleting}
                        className="text-gray-600 hover:text-gray-900 disabled:opacity-50 disabled:cursor-not-allowed"
                        aria-label="Cancel delete"
                      >
                        {t('common.cancel')}
                      </button>
                    </div>
                  ) : (
                    <div className="flex items-center justify-end gap-3">
                      <Link
                        to={`/admin/users/${user.id}/edit`}
                        className="text-gray-600 hover:text-gray-900 transition-colors"
                        aria-label={`Edit user ${user.username}`}
                        title={t('users.editUser')}
                      >
                        <Edit2 className="w-4 h-4" aria-hidden="true" />
                      </Link>
                      <button
                        onClick={() => handleDeleteClick(user.id)}
                        disabled={user.id === currentUserId || isDeleting}
                        className="text-red-600 hover:text-red-900 disabled:opacity-30 disabled:cursor-not-allowed"
                        aria-label={`Delete user ${user.username}`}
                        title={
                          user.id === currentUserId
                            ? t('users.cannotDeleteSelf')
                            : t('users.deleteUser')
                        }
                      >
                        <Trash2 className="w-4 h-4" aria-hidden="true" />
                      </button>
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {users.length === 0 && (
        <div className="text-center py-12">
          <p className="text-gray-500">{t('common.noResults')}</p>
        </div>
      )}
    </div>
  )
}
