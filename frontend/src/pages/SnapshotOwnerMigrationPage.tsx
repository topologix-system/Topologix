import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { AlertCircle, ArrowLeft, CheckCircle, Loader2, RefreshCw, ShieldCheck } from 'lucide-react'

import { useAssignSnapshotOwner, useUnownedSnapshotMigrations } from '../hooks'
import { useUsers } from '../hooks/useUsers'
import { authAPI } from '../services/api'
import { extractErrorMessage } from '../types/errors'
import type { SnapshotOwnerMigrationCandidate, User } from '../types'

interface MigrationRowProps {
  candidate: SnapshotOwnerMigrationCandidate
  users: User[]
}

function MigrationRow({ candidate, users }: MigrationRowProps) {
  const { t } = useTranslation()
  const assignOwner = useAssignSnapshotOwner()
  const [ownerUserId, setOwnerUserId] = useState('')
  const [folderName, setFolderName] = useState(candidate.folder_name ?? '')
  const [localError, setLocalError] = useState('')

  const selectedOwnerId = ownerUserId ? Number(ownerUserId) : null
  const selectedOwner = users.find((user) => user.id === selectedOwnerId)
  const isSubmitting = assignOwner.isPending
  const mutationError = assignOwner.error
    ? extractErrorMessage(assignOwner.error, t('snapshotMigration.assignFailed'))
    : null
  const latestResult = assignOwner.data

  const submitAssignment = async (dryRun: boolean) => {
    setLocalError('')
    assignOwner.reset()

    if (!selectedOwner) {
      setLocalError(t('snapshotMigration.ownerRequired'))
      return
    }

    try {
      await assignOwner.mutateAsync({
        snapshot_name: candidate.name,
        owner_user_id: selectedOwner.id,
        folder_name: folderName.trim() || null,
        dry_run: dryRun,
      })
    } catch {
      // React Query exposes the sanitized error through mutation state for rendering.
    }
  }

  return (
    <tr className="border-t border-gray-200">
      <td className="px-4 py-3 align-top">
        <div className="font-medium text-gray-900">{candidate.name}</div>
        <div className="mt-1 text-xs text-gray-500">
          {candidate.legacy_unowned
            ? t('snapshotMigration.legacyUnowned')
            : t('snapshotMigration.metadataUnowned')}
        </div>
      </td>
      <td className="px-4 py-3 align-top text-sm text-gray-700">
        {candidate.file_count}
      </td>
      <td className="px-4 py-3 align-top">
        <select
          value={ownerUserId}
          onChange={(event) => setOwnerUserId(event.target.value)}
          className="w-full min-w-48 px-3 py-2 text-sm border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-600"
          aria-label={t('snapshotMigration.ownerSelectAria', { snapshot: candidate.name })}
        >
          <option value="">{t('snapshotMigration.selectOwner')}</option>
          {users.map((user) => (
            <option key={user.id} value={user.id}>
              {user.username}
            </option>
          ))}
        </select>
      </td>
      <td className="px-4 py-3 align-top">
        <input
          type="text"
          value={folderName}
          onChange={(event) => setFolderName(event.target.value)}
          placeholder={t('snapshotMigration.folderPlaceholder')}
          className="w-full min-w-44 px-3 py-2 text-sm border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-600"
          aria-label={t('snapshotMigration.folderAria', { snapshot: candidate.name })}
        />
      </td>
      <td className="px-4 py-3 align-top">
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => void submitAssignment(true)}
            disabled={isSubmitting || !selectedOwner}
            className="inline-flex items-center gap-2 px-3 py-2 text-sm font-medium text-primary-700 bg-primary-50 border border-primary-200 rounded-lg hover:bg-primary-100 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isSubmitting ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
            {t('snapshotMigration.dryRun')}
          </button>
          <button
            type="button"
            onClick={() => void submitAssignment(false)}
            disabled={isSubmitting || !selectedOwner}
            className="inline-flex items-center gap-2 px-3 py-2 text-sm font-medium text-white bg-primary-600 rounded-lg hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isSubmitting ? <Loader2 className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />}
            {t('snapshotMigration.assignOwner')}
          </button>
        </div>
        {(localError || mutationError) && (
          <p className="mt-2 text-xs text-red-700">{localError || mutationError}</p>
        )}
        {latestResult && (
          <p className="mt-2 text-xs text-green-700">
            {latestResult.dry_run
              ? t('snapshotMigration.dryRunPassed', { owner: latestResult.owner_username })
              : t('snapshotMigration.assigned', { owner: latestResult.owner_username })}
          </p>
        )}
      </td>
    </tr>
  )
}

export function SnapshotOwnerMigrationPage() {
  const { t } = useTranslation()
  const isAdmin = authAPI.hasRole('admin')
  const { data: users, isLoading: loadingUsers, error: usersError } = useUsers(isAdmin)
  const {
    data: candidates,
    isLoading: loadingCandidates,
    error: candidatesError,
  } = useUnownedSnapshotMigrations(isAdmin)

  const activeUsers = useMemo(
    () => (users ?? []).filter((user) => user.is_active),
    [users]
  )
  const isLoading = loadingUsers || loadingCandidates
  const error = usersError || candidatesError

  if (!isAdmin) {
    return (
      <div className="flex items-center justify-center h-screen bg-gray-50">
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 flex items-start gap-2">
          <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" aria-hidden="true" />
          <div>
            <p className="text-sm font-medium text-red-800">{t('common.accessDenied')}</p>
            <p className="text-xs text-red-600 mt-1">{t('common.adminRequired')}</p>
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
          <p className="text-sm text-red-800">{t('snapshotMigration.failedToLoad')}</p>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-7xl mx-auto px-4 space-y-6">
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-3">
              <ShieldCheck className="w-8 h-8 text-primary-600" aria-hidden="true" />
              <div>
                <h1 className="text-2xl font-bold text-gray-900">{t('snapshotMigration.title')}</h1>
                <p className="text-sm text-gray-600 mt-1">
                  {t('snapshotMigration.summary', { count: candidates?.length ?? 0 })}
                </p>
              </div>
            </div>
            <Link
              to="/"
              className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-2 transition-colors"
            >
              <ArrowLeft className="w-4 h-4" aria-hidden="true" />
              {t('common.backToDashboard')}
            </Link>
          </div>
        </div>

        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <p className="text-sm text-blue-900">{t('snapshotMigration.help')}</p>
        </div>

        <div className="bg-white rounded-lg shadow overflow-hidden">
          {!candidates || candidates.length === 0 ? (
            <div className="p-8 text-center">
              <CheckCircle className="w-10 h-10 mx-auto text-green-600" aria-hidden="true" />
              <p className="mt-3 text-sm font-medium text-gray-900">{t('snapshotMigration.noCandidates')}</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead className="bg-gray-50 border-b border-gray-200">
                  <tr>
                    <th className="px-4 py-3 text-xs font-semibold text-gray-600 uppercase tracking-wide">
                      {t('snapshotMigration.table.snapshot')}
                    </th>
                    <th className="px-4 py-3 text-xs font-semibold text-gray-600 uppercase tracking-wide">
                      {t('snapshotMigration.table.files')}
                    </th>
                    <th className="px-4 py-3 text-xs font-semibold text-gray-600 uppercase tracking-wide">
                      {t('snapshotMigration.table.owner')}
                    </th>
                    <th className="px-4 py-3 text-xs font-semibold text-gray-600 uppercase tracking-wide">
                      {t('snapshotMigration.table.folder')}
                    </th>
                    <th className="px-4 py-3 text-xs font-semibold text-gray-600 uppercase tracking-wide">
                      {t('snapshotMigration.table.actions')}
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {candidates.map((candidate) => (
                    <MigrationRow
                      key={candidate.name}
                      candidate={candidate}
                      users={activeUsers}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
