import { RefreshCw } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { useActivateSnapshot } from '../hooks'
import { useSnapshotStore } from '../store'

/**
 * Notice for a hash-keyed response that belongs to another snapshot, with a forced re-activation
 */
export function SnapshotMismatchNotice() {
  const { t } = useTranslation()
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)
  const isSnapshotActivationInProgress = useSnapshotStore((state) => state.isSnapshotActivationInProgress)
  const activateMutation = useActivateSnapshot()
  const reloadPending = isSnapshotActivationInProgress || activateMutation.isPending

  return (
    <div className="flex items-center justify-center h-full" role="alert" aria-live="assertive">
      <div className="max-w-md text-center">
        <p className="font-semibold text-red-600">{t('overview.version.snapshotMismatch')}</p>
        <button
          type="button"
          onClick={() => {
            if (currentSnapshotName && !reloadPending) activateMutation.mutate(currentSnapshotName)
          }}
          disabled={!currentSnapshotName || reloadPending}
          className="mt-4 inline-flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-2 transition-colors disabled:cursor-not-allowed disabled:opacity-50"
        >
          <RefreshCw className={`h-4 w-4 ${reloadPending ? 'animate-spin' : ''}`} aria-hidden="true" />
          {t('overview.version.reload')}
        </button>
      </div>
    </div>
  )
}
