import { useMemo, useState, type KeyboardEvent, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { useQueryClient } from '@tanstack/react-query'
import { Dialog, DialogPanel, DialogTitle } from '@headlessui/react'
import { AlertTriangle, Eraser, GitCommit, History, Loader2, RotateCcw, Trash2 } from 'lucide-react'

import {
  WORKING_TREE,
  getPathClashPath,
  getVersionErrorCode,
  getVersionErrorStatus,
  getVersioningUnavailableReason,
  isVersionNotFoundError,
  isVersionStateNoDataError,
  snapshotVersionKeys,
  useClearResultCache,
  useCommitVersion,
  useDeleteVersions,
  useRestoreVersion,
  useSnapshotVersion,
  useSnapshotVersionState,
  useSnapshotVersions,
  useVersionDiff,
} from '../hooks/useSnapshotVersions'
import { useActivateSnapshot } from '../hooks/useSnapshots'
import { useSnapshotStore } from '../store'
import type { SnapshotVersion, SnapshotVersionState, VersionDeleteMode } from '../types'
import {
  byteSizeLabel,
  historyErrorText,
  joinLabels,
  shortContentHash,
  versionAuthorLabel,
  versionKindBadgeClass,
  versionKindLabel,
  versionMessageLabel,
  versionRefLabel,
  versioningReasonLabel,
} from './snapshotVersionLabels'
import { VersionDiffView } from './VersionDiffView'

const COMMIT_MESSAGE_MAX_LENGTH = 500

interface SnapshotHistoryPanelProps {
  snapshotName: string
  actionsBlocked?: boolean
  onFileChangeStart?: (snapshotName: string) => boolean
  onFileChangeEnd?: (snapshotName: string) => void
}

interface HistoryDialogProps {
  open: boolean
  title: string
  onClose: () => void
  wide?: boolean
  children: ReactNode
}

function HistoryDialog({ open, title, onClose, wide = false, children }: HistoryDialogProps) {
  return (
    <Dialog open={open} onClose={onClose} className="relative z-50">
      <div className="fixed inset-0 bg-gray-500 bg-opacity-75" aria-hidden="true" />
      <div className="fixed inset-0 z-10 overflow-y-auto">
        <div className="flex min-h-full items-center justify-center p-4">
          <DialogPanel
            className={`w-full ${wide ? 'max-w-2xl' : 'max-w-lg'} rounded-lg bg-white p-6 text-left shadow-xl`}
          >
            <DialogTitle as="h3" className="text-base font-semibold leading-6 text-gray-900">
              {title}
            </DialogTitle>
            <div className="mt-3 space-y-3 text-sm text-gray-700">{children}</div>
          </DialogPanel>
        </div>
      </div>
    </Dialog>
  )
}

/**
 * Marks an Escape that ends an IME composition as handled so the dialog's Escape handler ignores it
 */
function keepOpenOnImeEscape(event: KeyboardEvent<HTMLElement>) {
  if (event.key === 'Escape' && (event.nativeEvent.isComposing || event.keyCode === 229)) {
    event.preventDefault()
  }
}

const buttonBase =
  'inline-flex items-center justify-center gap-2 rounded-md px-3 py-2 text-sm font-semibold focus:outline-none focus:ring-2 focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50'
const secondaryButton = `${buttonBase} bg-white text-gray-900 ring-1 ring-inset ring-gray-300 hover:bg-gray-50 focus:ring-gray-500`
const primaryButton = `${buttonBase} bg-blue-600 text-white hover:bg-blue-700 focus:ring-primary-600`
const dangerButton = `${buttonBase} bg-red-600 text-white hover:bg-red-700 focus:ring-red-500`
const warningButton = `${buttonBase} bg-yellow-600 text-white hover:bg-yellow-700 focus:ring-yellow-500`

function DialogActions({ children }: { children: ReactNode }) {
  return <div className="mt-5 flex flex-wrap justify-end gap-3">{children}</div>
}

function ErrorText({ message }: { message: string }) {
  if (!message) return null
  return (
    <p className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm font-medium text-red-700" role="alert">
      {message}
    </p>
  )
}

function NoticeText({ message }: { message: string }) {
  if (!message) return null
  return (
    <p className="rounded-md border border-blue-200 bg-blue-50 px-3 py-2 text-sm text-blue-900" role="status">
      {message}
    </p>
  )
}

interface RestoreDialogProps {
  snapshotName: string
  version: SnapshotVersion
  loseUncommittedWork: boolean
  disabled: boolean
  pending: boolean
  error: string
  notice: string
  clashPath: string | null
  onClose: () => void
  onCommitFirst: () => void
  onConfirm: (expectedWorkingHash: string) => void
}

function RestoreDialog({
  snapshotName,
  version,
  loseUncommittedWork,
  disabled,
  pending,
  error,
  notice,
  clashPath,
  onClose,
  onCommitFirst,
  onConfirm,
}: RestoreDialogProps) {
  const { t } = useTranslation()
  const summaryQuery = useVersionDiff(snapshotName, version.version_id, WORKING_TREE, { staleTime: 0 })

  const summary = summaryQuery.data
  const filesToDelete = summary?.files.filter((file) => file.status === 'added').map((file) => file.path) ?? []
  const filesToOverwrite =
    summary?.files
      .filter((file) => file.status === 'modified' || file.status === 'removed')
      .map((file) => file.path) ?? []
  const versionLabel = t('overview.version.versionLabel', { seq: version.seq })
  const workingHash = summary?.working_content_hash
  const canConfirm = !disabled && !pending && !summaryQuery.isFetching && !!workingHash && clashPath === null

  return (
    <HistoryDialog open title={t('snapshots.history.restore.title', { version: versionLabel })} onClose={onClose} wide>
      <p>{t('snapshots.history.restore.description', { version: versionLabel })}</p>
      {loseUncommittedWork && (
        <div className="rounded-md border border-yellow-200 bg-yellow-50 px-3 py-2 text-yellow-900" role="alert">
          <p className="flex items-start gap-2">
            <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0" aria-hidden="true" />
            <span>{t('snapshots.history.restore.uncommittedWarning')}</span>
          </p>
          <button type="button" onClick={onCommitFirst} disabled={pending} className={`${secondaryButton} mt-2`}>
            <GitCommit className="h-4 w-4" aria-hidden="true" />
            {t('snapshots.history.restore.commitFirst')}
          </button>
        </div>
      )}
      {summaryQuery.isFetching && (
        <p className="flex items-center gap-2" role="status">
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
          {t('snapshots.history.restore.loadingSummary', { version: versionLabel })}
        </p>
      )}
      {summaryQuery.isError && !summaryQuery.isFetching && (
        <ErrorText message={historyErrorText(t, summaryQuery.error, 'snapshots.history.errors.summaryAction')} />
      )}
      {summary && !summaryQuery.isFetching && (
        <div className="space-y-2">
          <div>
            <p className="font-medium text-gray-900">
              {t('snapshots.history.restore.overwriteTitle', { count: filesToOverwrite.length })}
            </p>
            {filesToOverwrite.length > 0 ? (
              <ul className="mt-1 max-h-40 overflow-y-auto rounded border border-gray-200 bg-gray-50 px-3 py-1 font-mono text-xs">
                {filesToOverwrite.map((path) => (
                  <li key={path} className="break-all">{path}</li>
                ))}
              </ul>
            ) : (
              <p className="text-xs text-gray-600">{t('snapshots.history.restore.none')}</p>
            )}
          </div>
          <div>
            <p className="font-medium text-gray-900">
              {t('snapshots.history.restore.deleteTitle', { count: filesToDelete.length })}
            </p>
            {filesToDelete.length > 0 ? (
              <ul className="mt-1 max-h-40 overflow-y-auto rounded border border-gray-200 bg-gray-50 px-3 py-1 font-mono text-xs">
                {filesToDelete.map((path) => (
                  <li key={path} className="break-all">{path}</li>
                ))}
              </ul>
            ) : (
              <p className="text-xs text-gray-600">{t('snapshots.history.restore.none')}</p>
            )}
          </div>
          <p className="text-xs text-gray-600">{t('snapshots.history.restore.uncommittedResult')}</p>
        </div>
      )}
      <NoticeText message={notice} />
      {clashPath !== null && <ErrorText message={t('snapshots.history.restore.pathClash', { path: clashPath })} />}
      <ErrorText message={error} />
      <DialogActions>
        <button type="button" onClick={onClose} disabled={pending} className={secondaryButton} autoFocus>
          {t('common.cancel')}
        </button>
        <button
          type="button"
          onClick={() => {
            if (canConfirm && workingHash) onConfirm(workingHash)
          }}
          disabled={!canConfirm}
          className={warningButton}
          aria-busy={pending}
        >
          {pending && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
          {t('snapshots.history.restore.confirm')}
        </button>
      </DialogActions>
    </HistoryDialog>
  )
}

interface DeleteSnapshot {
  expectedHead: string | null
  total: number
}

interface RestoreTarget {
  version: SnapshotVersion
  loseUncommittedWork: boolean
}

/**
 * Version history panel of one snapshot: version list and detail, diff, commit, restore, deletion and result-cache
 * clearing
 */
export function SnapshotHistoryPanel({
  snapshotName,
  actionsBlocked = false,
  onFileChangeStart,
  onFileChangeEnd,
}: SnapshotHistoryPanelProps) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const errorText = (error: unknown, fallbackKey: string) => historyErrorText(t, error, fallbackKey)
  const versionState = useSnapshotVersionState(snapshotName)
  const unavailableReason = versionState.isError ? getVersioningUnavailableReason(versionState.error) : null
  const missingObjects = unavailableReason === 'missing_objects'
  const state = versionState.isSuccess ? versionState.data : undefined
  const versionsQuery = useSnapshotVersions(snapshotName, !unavailableReason)
  const commitMutation = useCommitVersion()
  const restoreMutation = useRestoreVersion()
  const deleteMutation = useDeleteVersions()
  const clearMutation = useClearResultCache()
  const activateMutation = useActivateSnapshot()

  const [panelError, setPanelError] = useState('')
  const [panelNotice, setPanelNotice] = useState('')
  const [commitOpen, setCommitOpen] = useState(false)
  const [commitMessage, setCommitMessage] = useState('')
  const [commitExpectedHead, setCommitExpectedHead] = useState<string | null>(null)
  const [commitError, setCommitError] = useState('')
  const [restoreTarget, setRestoreTarget] = useState<RestoreTarget | null>(null)
  const [restoreError, setRestoreError] = useState('')
  const [restoreNotice, setRestoreNotice] = useState('')
  const [restoreClash, setRestoreClash] = useState<string | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<{ version: SnapshotVersion; captured: DeleteSnapshot } | null>(null)
  const [bulkDelete, setBulkDelete] = useState<DeleteSnapshot | null>(null)
  const [bulkMode, setBulkMode] = useState<VersionDeleteMode>('oldest')
  const [bulkCount, setBulkCount] = useState('1')
  const [missingDeleteOpen, setMissingDeleteOpen] = useState(false)
  const [deleteError, setDeleteError] = useState('')
  const [deleteNotice, setDeleteNotice] = useState('')
  const [selectedVersionId, setSelectedVersionId] = useState<string | null>(null)
  const [compareAgainst, setCompareAgainst] = useState<string>(WORKING_TREE)

  const versions = useMemo(() => {
    const seen = new Set<string>()
    const items: SnapshotVersion[] = []
    for (const page of versionsQuery.data?.pages ?? []) {
      for (const item of page.items) {
        if (seen.has(item.version_id)) continue
        seen.add(item.version_id)
        items.push(item)
      }
    }
    return items
  }, [versionsQuery.data])
  const pages = versionsQuery.data?.pages
  const total = pages && pages.length > 0 ? pages[pages.length - 1].total : undefined
  const selectedVersion = versions.find((version) => version.version_id === selectedVersionId) ?? null
  const detailQuery = useSnapshotVersion(snapshotName, selectedVersion?.version_id ?? null)

  const canMutate = !!state && !actionsBlocked
  const commitDisabledReason = actionsBlocked
    ? t('snapshots.history.commitDisabled.busy')
    : !state
      ? versionState.isPending
        ? t('snapshots.history.commitDisabled.loading')
        : t('snapshots.history.commitDisabled.unavailable')
      : state.content_hash === null
        ? t('snapshots.history.commitDisabled.notSettled')
        : !state.uncommitted
          ? t('snapshots.history.commitDisabled.noChanges')
          : ''
  const commitDisabled = commitDisabledReason !== ''
  const commitHelpId = `snapshot-history-commit-help-${snapshotName}`

  const versionLabel = (version: Pick<SnapshotVersion, 'seq'>) => t('overview.version.versionLabel', { seq: version.seq })

  const captureDeleteSnapshot = (): DeleteSnapshot | null => {
    if (!state || total === undefined) return null
    return { expectedHead: state.head?.version_id ?? null, total }
  }

  const openCommitDialog = () => {
    if (commitDisabled || !state) return
    setCommitMessage('')
    setCommitError('')
    setCommitExpectedHead(state.head?.version_id ?? null)
    setCommitOpen(true)
  }

  const closeCommitDialog = () => {
    if (commitMutation.isPending) return
    setCommitOpen(false)
  }

  const submitCommit = () => {
    const message = commitMessage.trim()
    if (!message) {
      setCommitError(t('snapshots.history.commit.messageRequired'))
      return
    }
    if (message.length > COMMIT_MESSAGE_MAX_LENGTH) {
      setCommitError(t('snapshots.history.commit.messageTooLong', { max: COMMIT_MESSAGE_MAX_LENGTH }))
      return
    }
    setCommitError('')
    commitMutation.mutate(
      { name: snapshotName, message, expectedHead: commitExpectedHead },
      {
        onSuccess: (version) => {
          setCommitOpen(false)
          setPanelError('')
          setPanelNotice(version ? t('snapshots.history.commit.created', { version: versionLabel(version) }) : '')
        },
        onError: (error) => {
          if (getVersionErrorCode(error) === 'version_conflict') {
            const refreshed = queryClient.getQueryData<SnapshotVersionState>(snapshotVersionKeys.state(snapshotName))
            setCommitExpectedHead(refreshed?.head?.version_id ?? null)
          }
          setCommitError(errorText(error, 'snapshots.history.errors.commitAction'))
        },
      }
    )
  }

  const startRestore = (version: SnapshotVersion) => {
    if (!canMutate || !state) return
    setPanelError('')
    setPanelNotice('')
    setRestoreError('')
    setRestoreNotice('')
    setRestoreClash(null)
    setRestoreTarget({ version, loseUncommittedWork: state.uncommitted || state.pending_external })
  }

  const closeRestoreDialog = () => {
    if (restoreMutation.isPending) return
    setRestoreTarget(null)
  }

  const confirmRestore = (version: SnapshotVersion, expectedWorkingHash: string) => {
    if (restoreMutation.isPending) return
    if (onFileChangeStart && !onFileChangeStart(snapshotName)) {
      setRestoreError(t('snapshots.history.errors.busy'))
      return
    }
    setRestoreError('')
    setRestoreNotice('')
    void restoreMutation
      .mutateAsync({ name: snapshotName, versionId: version.version_id, expectedWorkingHash })
      .then(
        async ({ response, respondedAt }) => {
          setRestoreTarget(null)
          const refetched = queryClient.getQueryState<SnapshotVersionState>(snapshotVersionKeys.state(snapshotName))
          const refetchedState =
            refetched?.status === 'success' && refetched.dataUpdatedAt >= respondedAt ? refetched.data : undefined
          setPanelNotice(
            t(
              !refetchedState
                ? 'snapshots.history.restore.doneUnknownState'
                : refetchedState.uncommitted
                  ? 'snapshots.history.restore.done'
                  : 'snapshots.history.restore.doneEqualsHead',
              { version: versionLabel(version) }
            )
          )
          if (response?.requires_reinitialize === false) return
          if (useSnapshotStore.getState().currentSnapshotName !== snapshotName) return
          try {
            await activateMutation.mutateAsync({ name: snapshotName, ifStale: true })
          } catch {
            setPanelError(t('snapshots.history.restore.reactivateFailed'))
          }
        },
        (error: unknown) => {
          const clash = getPathClashPath(error)
          if (clash !== null) {
            setRestoreClash(clash)
            return
          }
          if (isVersionNotFoundError(error)) {
            setRestoreTarget(null)
            setPanelError(t('snapshots.history.errors.versionNotFound'))
            return
          }
          if (getVersionErrorStatus(error) === 409) {
            setRestoreNotice(t('snapshots.history.restore.changedReview'))
            void queryClient.refetchQueries({
              queryKey: snapshotVersionKeys.diff(snapshotName, version.version_id, WORKING_TREE),
              exact: true,
            })
            return
          }
          setRestoreError(errorText(error, 'snapshots.history.errors.restoreAction'))
        }
      )
      .finally(() => onFileChangeEnd?.(snapshotName))
  }

  const openDeleteVersion = (version: SnapshotVersion) => {
    const captured = captureDeleteSnapshot()
    if (!canMutate || !captured) return
    setDeleteError('')
    setDeleteNotice('')
    setDeleteTarget({ version, captured })
  }

  const openBulkDelete = (mode: VersionDeleteMode = 'oldest') => {
    const captured = captureDeleteSnapshot()
    if (!canMutate || !captured) return
    setDeleteError('')
    setDeleteNotice('')
    setBulkMode(mode)
    setBulkCount('1')
    setBulkDelete(captured)
  }

  const closeDeleteDialogs = () => {
    if (deleteMutation.isPending) return
    setDeleteTarget(null)
    setBulkDelete(null)
    setMissingDeleteOpen(false)
  }

  const recaptureAfterConflict = () => {
    const refreshedState = queryClient.getQueryData<SnapshotVersionState>(snapshotVersionKeys.state(snapshotName))
    setDeleteNotice(t('snapshots.history.delete.changedReview'))
    return refreshedState
  }

  const handleDeleteError = (error: unknown, retry: (refreshed: SnapshotVersionState | undefined) => void) => {
    if (getVersionErrorStatus(error) === 409 || isVersionNotFoundError(error)) {
      retry(recaptureAfterConflict())
      return
    }
    setDeleteError(errorText(error, 'snapshots.history.errors.deleteAction'))
  }

  const deletedNotice = (deleted: number | undefined) => t('snapshots.history.delete.done', { count: deleted ?? 0 })

  const cachedListTotal = (): number | undefined => {
    const cachedPages = queryClient.getQueryData<{ pages: { total: number }[] }>(
      snapshotVersionKeys.list(snapshotName)
    )?.pages
    return cachedPages && cachedPages.length > 0 ? cachedPages[cachedPages.length - 1].total : undefined
  }

  const confirmDeleteVersion = () => {
    if (!deleteTarget) return
    const { version, captured } = deleteTarget
    deleteMutation.mutate(
      { name: snapshotName, versionId: version.version_id, expectedHead: captured.expectedHead },
      {
        onSuccess: (result) => {
          setDeleteTarget(null)
          if (selectedVersionId === version.version_id) setSelectedVersionId(null)
          setPanelNotice(deletedNotice(result?.deleted))
        },
        onError: (error) =>
          handleDeleteError(error, (refreshed) => {
            if (isVersionNotFoundError(error)) {
              setDeleteTarget(null)
              setPanelNotice(t('snapshots.history.errors.versionNotFound'))
              return
            }
            setDeleteTarget({
              version,
              captured: { expectedHead: refreshed?.head?.version_id ?? null, total: captured.total },
            })
          }),
      }
    )
  }

  const bulkCountValue = Number(bulkCount)
  const bulkCountValid = bulkMode === 'all' || (Number.isInteger(bulkCountValue) && bulkCountValue >= 1)
  const bulkDeleteCount = bulkDelete
    ? bulkMode === 'all'
      ? bulkDelete.total
      : Math.min(bulkCountValid ? bulkCountValue : 0, bulkDelete.total)
    : 0
  const bulkIncludesHead =
    !!bulkDelete &&
    bulkDelete.total > 0 &&
    (bulkMode === 'all' || bulkMode === 'newest' || (bulkCountValid && bulkCountValue >= bulkDelete.total))

  const confirmBulkDelete = () => {
    if (!bulkDelete || !bulkCountValid || bulkDeleteCount === 0) return
    const captured = bulkDelete
    const request =
      bulkMode === 'all'
        ? { mode: bulkMode, expected_head: captured.expectedHead }
        : { mode: bulkMode, count: bulkCountValue, expected_head: captured.expectedHead, expected_total: captured.total }
    deleteMutation.mutate(
      { name: snapshotName, request },
      {
        onSuccess: (result) => {
          setBulkDelete(null)
          setSelectedVersionId(null)
          setPanelNotice(deletedNotice(result?.deleted))
        },
        onError: (error) =>
          handleDeleteError(error, (refreshed) => {
            setBulkDelete({
              expectedHead: refreshed?.head?.version_id ?? null,
              total: cachedListTotal() ?? captured.total,
            })
          }),
      }
    )
  }

  const confirmMissingObjectsDelete = () => {
    deleteMutation.mutate(
      { name: snapshotName, request: { mode: 'all', expected_unavailable: 'missing_objects' } },
      {
        onSuccess: (result) => {
          setMissingDeleteOpen(false)
          setSelectedVersionId(null)
          setPanelNotice(deletedNotice(result?.deleted))
        },
        onError: (error) => {
          if (getVersionErrorStatus(error) !== 409) {
            setDeleteError(errorText(error, 'snapshots.history.errors.deleteAction'))
            return
          }
          setMissingDeleteOpen(false)
          const refreshedState = queryClient.getQueryState<SnapshotVersionState>(snapshotVersionKeys.state(snapshotName))
          const refreshedHead = refreshedState?.status === 'success' ? refreshedState.data?.head : undefined
          if (refreshedHead === undefined) {
            setPanelNotice(t('snapshots.history.delete.changedRetry'))
            return
          }
          void versionsQuery.refetch().then((listResult) => {
            const refreshedPages = listResult.data?.pages
            if (!refreshedPages || refreshedPages.length === 0) {
              setPanelNotice(t('snapshots.history.delete.changedRetry'))
              return
            }
            setDeleteNotice(t('snapshots.history.delete.changedReview'))
            setBulkMode('all')
            setBulkCount('1')
            setBulkDelete({
              expectedHead: refreshedHead?.version_id ?? null,
              total: refreshedPages[refreshedPages.length - 1].total,
            })
          })
        },
      }
    )
  }

  const clearCache = () => {
    if (!canMutate) return
    setPanelError('')
    setPanelNotice('')
    clearMutation.mutate(snapshotName, {
      onSuccess: (result) => {
        const current = queryClient.getQueryData<SnapshotVersionState>(snapshotVersionKeys.state(snapshotName))
        setPanelNotice(
          result?.cleared
            ? t('snapshots.history.clearCache.cleared')
            : current?.result_cache_enabled === false
              ? useSnapshotStore.getState().currentSnapshotName === snapshotName
                ? t('snapshots.history.clearCache.disabled')
                : t('snapshots.history.clearCache.disabledNotCurrent')
              : t('snapshots.history.clearCache.notSettled')
        )
      },
      onError: (error) => setPanelError(errorText(error, 'snapshots.history.errors.clearAction')),
    })
  }

  const headWhileUncommittedText = (remainingAfterHead: SnapshotVersion | undefined, noneRemains: boolean) =>
    noneRemains
      ? t('snapshots.history.delete.headWhileUncommittedNone')
      : remainingAfterHead
        ? t('snapshots.history.delete.headWhileUncommitted', { version: versionLabel(remainingAfterHead) })
        : t('snapshots.history.delete.headWhileUncommittedPrevious')

  const singleDeleteIsHead = !!deleteTarget && deleteTarget.version.version_id === deleteTarget.captured.expectedHead
  const singleDeleteNextHead = deleteTarget
    ? versions.find((version) => version.version_id !== deleteTarget.version.version_id)
    : undefined
  const bulkNextHead = bulkDelete && bulkMode === 'newest' && bulkCountValid ? versions[bulkCountValue] : undefined

  const compareAgainstVersion = versions.find((version) => version.version_id === compareAgainst)
  const compareAgainstLabel =
    compareAgainst === WORKING_TREE
      ? t('snapshots.history.workingTree')
      : compareAgainstVersion
        ? versionLabel(compareAgainstVersion)
        : t('snapshots.history.unknownVersion')

  const versionStateUnavailable = versionState.isError && !unavailableReason
  const listLoadFailed = versionsQuery.isError && !unavailableReason
  const restorePending = restoreMutation.isPending

  return (
    <section
      className="mt-6 rounded-lg border border-gray-200 bg-white p-4"
      aria-labelledby={`snapshot-history-title-${snapshotName}`}
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 id={`snapshot-history-title-${snapshotName}`} className="flex items-center gap-2 text-lg font-semibold text-gray-900">
            <History className="h-5 w-5 text-gray-600" aria-hidden="true" />
            {t('snapshots.history.title')}
          </h3>
          {state && (
            <p className="mt-1 text-sm text-gray-700">
              {joinLabels(t, [
                state.head
                  ? t('snapshots.history.headLine', { version: versionLabel(state.head) })
                  : t('overview.version.noVersions'),
                state.content_hash &&
                  t('snapshots.history.workingHash', { hash: shortContentHash(state.content_hash) }),
                state.uncommitted && t('overview.version.uncommitted'),
                state.pending_external && t('snapshots.history.pendingExternal'),
                state.external_settling && t('overview.version.settling'),
                state.restored_from &&
                  t('overview.version.workingRestoredFrom', { version: versionRefLabel(t, state.restored_from) }),
              ])}
            </p>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={openCommitDialog}
            disabled={commitDisabled}
            aria-describedby={commitDisabled ? commitHelpId : undefined}
            className={primaryButton}
          >
            <GitCommit className="h-4 w-4" aria-hidden="true" />
            {t('snapshots.history.commit.open')}
          </button>
          <button
            type="button"
            onClick={clearCache}
            disabled={!canMutate || clearMutation.isPending}
            aria-busy={clearMutation.isPending}
            className={secondaryButton}
          >
            <Eraser className="h-4 w-4" aria-hidden="true" />
            {t('snapshots.history.clearCache.open')}
          </button>
          {missingObjects ? (
            <button
              type="button"
              onClick={() => {
                setDeleteError('')
                setDeleteNotice('')
                setMissingDeleteOpen(true)
              }}
              disabled={actionsBlocked}
              className={dangerButton}
            >
              <Trash2 className="h-4 w-4" aria-hidden="true" />
              {t('snapshots.history.delete.allOpen')}
            </button>
          ) : (
            <button
              type="button"
              onClick={() => openBulkDelete()}
              disabled={!canMutate || !total}
              className={dangerButton}
            >
              <Trash2 className="h-4 w-4" aria-hidden="true" />
              {t('snapshots.history.delete.historyOpen')}
            </button>
          )}
        </div>
      </div>

      {commitDisabled && (
        <p id={commitHelpId} className="mt-2 text-xs text-gray-600">
          {commitDisabledReason}
        </p>
      )}

      <div className="mt-3 space-y-2">
        {missingObjects && (
          <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800" role="alert">
            {t('snapshots.history.missingObjects')}
          </div>
        )}
        {unavailableReason && !missingObjects && (
          <div className="rounded-md border border-yellow-200 bg-yellow-50 px-3 py-2 text-sm text-yellow-900" role="alert">
            {t('snapshots.history.unavailable', { reason: versioningReasonLabel(t, unavailableReason) })}
          </div>
        )}
        {versionStateUnavailable && (
          <div className="rounded-md border border-yellow-200 bg-yellow-50 px-3 py-2 text-sm text-yellow-900" role="alert">
            {isVersionStateNoDataError(versionState.error)
              ? t('snapshots.history.errors.snapshotUnavailable')
              : t('overview.version.unavailable')}
          </div>
        )}
        <NoticeText message={panelNotice} />
        <ErrorText message={panelError} />
      </div>

      {versionState.isPending && (
        <p className="mt-3 flex items-center gap-2 text-sm text-gray-700" role="status">
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
          {t('snapshots.history.loading')}
        </p>
      )}

      {listLoadFailed && <ErrorText message={errorText(versionsQuery.error, 'snapshots.history.errors.listAction')} />}

      {!unavailableReason && versionsQuery.data && (
        <div className="mt-4">
          {versions.length === 0 ? (
            <p className="text-sm text-gray-700">{t('overview.version.noVersions')}</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200 text-sm">
                <caption className="sr-only">{t('snapshots.history.listCaption', { count: total ?? versions.length })}</caption>
                <thead className="bg-gray-50">
                  <tr>
                    {['seq', 'kind', 'message', 'author', 'time', 'files', 'lineage', 'actions'].map((column) => (
                      <th
                        key={column}
                        scope="col"
                        className="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wider text-gray-700"
                      >
                        {t(`snapshots.history.columns.${column}`)}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {versions.map((version) => {
                    const isHead = state?.head?.version_id === version.version_id
                    return (
                      <tr key={version.version_id} className={selectedVersionId === version.version_id ? 'bg-blue-50' : ''}>
                        <td className="whitespace-nowrap px-3 py-2 font-mono font-medium text-gray-900">
                          {versionLabel(version)}
                          {isHead && (
                            <span className="ml-1 rounded bg-green-100 px-1.5 py-0.5 text-xs font-semibold text-green-800">
                              {t('snapshots.history.headBadge')}
                            </span>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2">
                          <span className={`rounded border px-1.5 py-0.5 text-xs font-medium ${versionKindBadgeClass[version.kind]}`}>
                            {versionKindLabel(t, version.kind)}
                          </span>
                        </td>
                        <td className="max-w-xs break-words px-3 py-2 text-gray-900">{versionMessageLabel(t, version)}</td>
                        <td className="whitespace-nowrap px-3 py-2 text-gray-700">{versionAuthorLabel(t, version)}</td>
                        <td className="whitespace-nowrap px-3 py-2 text-gray-700">{new Date(version.created_at).toLocaleString()}</td>
                        <td className="whitespace-nowrap px-3 py-2 text-gray-700">{version.file_count}</td>
                        <td className="whitespace-nowrap px-3 py-2 text-xs text-gray-600">
                          {joinLabels(t, [
                            version.parent && t('snapshots.history.parent', { version: versionRefLabel(t, version.parent) }),
                            version.restored_from &&
                              t('overview.version.headRestoredFrom', { version: versionRefLabel(t, version.restored_from) }),
                          ])}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2">
                          <div className="flex items-center gap-1">
                            <button
                              type="button"
                              onClick={() => {
                                setSelectedVersionId(selectedVersionId === version.version_id ? null : version.version_id)
                                setCompareAgainst(WORKING_TREE)
                              }}
                              aria-pressed={selectedVersionId === version.version_id}
                              className="rounded-md border border-gray-300 px-2 py-1 text-xs font-medium text-gray-800 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-primary-600"
                              aria-label={t('snapshots.history.detailsAria', { version: versionLabel(version) })}
                            >
                              {t('snapshots.history.details')}
                            </button>
                            <button
                              type="button"
                              onClick={() => startRestore(version)}
                              disabled={!canMutate}
                              className="inline-flex h-7 w-7 items-center justify-center rounded-md border border-amber-200 text-amber-700 hover:bg-amber-50 focus:outline-none focus:ring-2 focus:ring-amber-600 disabled:cursor-not-allowed disabled:opacity-50"
                              aria-label={t('snapshots.history.restore.openAria', { version: versionLabel(version) })}
                              title={t('snapshots.history.restore.open')}
                            >
                              <RotateCcw className="h-4 w-4" aria-hidden="true" />
                            </button>
                            <button
                              type="button"
                              onClick={() => openDeleteVersion(version)}
                              disabled={!canMutate || total === undefined}
                              className="inline-flex h-7 w-7 items-center justify-center rounded-md border border-red-200 text-red-600 hover:bg-red-50 focus:outline-none focus:ring-2 focus:ring-red-600 disabled:cursor-not-allowed disabled:opacity-50"
                              aria-label={t('snapshots.history.delete.versionAria', { version: versionLabel(version) })}
                              title={t('snapshots.history.delete.version')}
                            >
                              <Trash2 className="h-4 w-4" aria-hidden="true" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
          {versions.length > 0 && total !== undefined && (
            <div className="mt-2 flex items-center justify-between gap-3 text-xs text-gray-600">
              <span>{t('snapshots.history.shownCount', { shown: versions.length, count: total })}</span>
              {versionsQuery.hasNextPage && (
                <button
                  type="button"
                  onClick={() => void versionsQuery.fetchNextPage()}
                  disabled={versionsQuery.isFetchingNextPage}
                  className={secondaryButton}
                >
                  {versionsQuery.isFetchingNextPage && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
                  {t('snapshots.history.loadMore')}
                </button>
              )}
            </div>
          )}
        </div>
      )}

      {selectedVersion && !unavailableReason && (
        <div className="mt-4 space-y-3 rounded-lg border border-gray-200 bg-gray-50 p-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="text-sm font-semibold text-gray-900">
              {t('snapshots.history.detailTitle', { version: versionLabel(selectedVersion) })}
            </p>
            <label className="flex items-center gap-2 text-sm text-gray-800">
              {t('snapshots.history.compareWith')}
              <select
                value={compareAgainst}
                onChange={(event) => setCompareAgainst(event.target.value)}
                className="rounded-md border border-gray-300 bg-white px-2 py-1 text-sm focus:outline-none focus:ring-2 focus:ring-primary-600"
              >
                <option value={WORKING_TREE}>{t('snapshots.history.workingTree')}</option>
                {versions
                  .filter((version) => version.version_id !== selectedVersion.version_id)
                  .map((version) => (
                    <option key={version.version_id} value={version.version_id}>
                      {versionLabel(version)}
                    </option>
                  ))}
              </select>
            </label>
          </div>
          {detailQuery.data && (
            <details className="text-xs text-gray-700">
              <summary className="cursor-pointer">
                {t('snapshots.history.detailSummary', {
                  count: detailQuery.data.file_count,
                  size: byteSizeLabel(t, detailQuery.data.total_bytes),
                })}
              </summary>
              <ul className="mt-1 max-h-40 overflow-y-auto rounded border border-gray-200 bg-white px-3 py-1 font-mono">
                {detailQuery.data.files.map((file) => (
                  <li key={file.path} className="flex justify-between gap-3">
                    <span className="break-all">{file.path}</span>
                    <span className="whitespace-nowrap text-gray-600">{byteSizeLabel(t, file.size)}</span>
                  </li>
                ))}
              </ul>
            </details>
          )}
          {detailQuery.isError && (
            <ErrorText message={errorText(detailQuery.error, 'snapshots.history.errors.detailAction')} />
          )}
          <VersionDiffView
            key={`${selectedVersion.version_id}-${compareAgainst}`}
            snapshotName={snapshotName}
            versionId={selectedVersion.version_id}
            against={compareAgainst}
            fromLabel={versionLabel(selectedVersion)}
            againstLabel={compareAgainstLabel}
          />
        </div>
      )}

      <HistoryDialog open={commitOpen} title={t('snapshots.history.commit.title')} onClose={closeCommitDialog}>
        <label htmlFor={`snapshot-commit-message-${snapshotName}`} className="block font-medium text-gray-800">
          {t('snapshots.history.commit.messageLabel')}
        </label>
        <textarea
          id={`snapshot-commit-message-${snapshotName}`}
          value={commitMessage}
          onChange={(event) => {
            setCommitMessage(event.target.value)
            setCommitError('')
          }}
          onKeyDown={keepOpenOnImeEscape}
          maxLength={COMMIT_MESSAGE_MAX_LENGTH}
          rows={3}
          autoFocus
          aria-describedby={`snapshot-commit-message-help-${snapshotName}`}
          className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-900 focus:border-primary-600 focus:outline-none focus:ring-2 focus:ring-primary-600"
        />
        <p id={`snapshot-commit-message-help-${snapshotName}`} className="text-xs text-gray-600">
          {t('snapshots.history.commit.messageHelp', { length: commitMessage.trim().length, max: COMMIT_MESSAGE_MAX_LENGTH })}
        </p>
        <ErrorText message={commitError} />
        <DialogActions>
          <button type="button" onClick={closeCommitDialog} disabled={commitMutation.isPending} className={secondaryButton}>
            {t('common.cancel')}
          </button>
          <button
            type="button"
            onClick={submitCommit}
            disabled={commitMutation.isPending || !commitMessage.trim()}
            aria-busy={commitMutation.isPending}
            className={primaryButton}
          >
            {commitMutation.isPending && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
            {t('snapshots.history.commit.submit')}
          </button>
        </DialogActions>
      </HistoryDialog>

      {restoreTarget && (
        <RestoreDialog
          snapshotName={snapshotName}
          version={restoreTarget.version}
          loseUncommittedWork={
            state ? state.uncommitted || state.pending_external : restoreTarget.loseUncommittedWork
          }
          disabled={actionsBlocked || !state}
          pending={restorePending}
          error={restoreError}
          notice={restoreNotice}
          clashPath={restoreClash}
          onClose={closeRestoreDialog}
          onCommitFirst={() => {
            if (restorePending) return
            setRestoreTarget(null)
            openCommitDialog()
          }}
          onConfirm={(expectedWorkingHash) => confirmRestore(restoreTarget.version, expectedWorkingHash)}
        />
      )}

      <HistoryDialog
        open={!!deleteTarget}
        title={t('snapshots.history.delete.versionTitle', {
          version: deleteTarget ? versionLabel(deleteTarget.version) : '',
        })}
        onClose={closeDeleteDialogs}
      >
        <p>{t('snapshots.history.delete.versionMessage', { version: deleteTarget ? versionLabel(deleteTarget.version) : '' })}</p>
        <p>{t('snapshots.history.delete.irreversible')}</p>
        {singleDeleteIsHead && state?.uncommitted && (
          <p className="rounded-md border border-yellow-200 bg-yellow-50 px-3 py-2 text-yellow-900" role="alert">
            {headWhileUncommittedText(singleDeleteNextHead, (deleteTarget?.captured.total ?? 0) <= 1)}
          </p>
        )}
        <NoticeText message={deleteNotice} />
        <ErrorText message={deleteError} />
        <DialogActions>
          <button type="button" onClick={closeDeleteDialogs} disabled={deleteMutation.isPending} className={secondaryButton} autoFocus>
            {t('common.cancel')}
          </button>
          <button
            type="button"
            onClick={confirmDeleteVersion}
            disabled={deleteMutation.isPending}
            aria-busy={deleteMutation.isPending}
            className={dangerButton}
          >
            {deleteMutation.isPending && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
            {t('snapshots.history.delete.confirm')}
          </button>
        </DialogActions>
      </HistoryDialog>

      <HistoryDialog open={!!bulkDelete} title={t('snapshots.history.delete.historyTitle')} onClose={closeDeleteDialogs}>
        <fieldset className="space-y-2">
          <legend className="font-medium text-gray-800">{t('snapshots.history.delete.modeLabel')}</legend>
          {(['oldest', 'newest', 'all'] as const).map((mode) => (
            <label key={mode} className="flex items-center gap-2">
              <input
                type="radio"
                name={`snapshot-history-delete-mode-${snapshotName}`}
                value={mode}
                checked={bulkMode === mode}
                onChange={() => setBulkMode(mode)}
                className="h-4 w-4 border-gray-300"
              />
              {t(`snapshots.history.delete.modes.${mode}`)}
            </label>
          ))}
        </fieldset>
        {bulkMode !== 'all' && (
          <div>
            <label htmlFor={`snapshot-history-delete-count-${snapshotName}`} className="block font-medium text-gray-800">
              {t('snapshots.history.delete.countLabel')}
            </label>
            <input
              id={`snapshot-history-delete-count-${snapshotName}`}
              type="number"
              min={1}
              step={1}
              value={bulkCount}
              onChange={(event) => setBulkCount(event.target.value)}
              onKeyDown={keepOpenOnImeEscape}
              aria-invalid={!bulkCountValid}
              className="mt-1 w-32 rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-primary-600 focus:outline-none focus:ring-2 focus:ring-primary-600"
            />
          </div>
        )}
        {bulkDelete && (
          <p className="font-medium text-gray-900">
            {t('snapshots.history.delete.historyCount', { deleted: bulkDeleteCount, count: bulkDelete.total })}
          </p>
        )}
        <p>{t('snapshots.history.delete.irreversible')}</p>
        {bulkIncludesHead && state?.uncommitted && (
          <p className="rounded-md border border-yellow-200 bg-yellow-50 px-3 py-2 text-yellow-900" role="alert">
            {headWhileUncommittedText(bulkNextHead, bulkMode === 'all' || bulkDeleteCount >= (bulkDelete?.total ?? 0))}
          </p>
        )}
        <NoticeText message={deleteNotice} />
        <ErrorText message={deleteError} />
        <DialogActions>
          <button type="button" onClick={closeDeleteDialogs} disabled={deleteMutation.isPending} className={secondaryButton} autoFocus>
            {t('common.cancel')}
          </button>
          <button
            type="button"
            onClick={confirmBulkDelete}
            disabled={deleteMutation.isPending || !bulkCountValid || bulkDeleteCount === 0}
            aria-busy={deleteMutation.isPending}
            className={dangerButton}
          >
            {deleteMutation.isPending && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
            {t('snapshots.history.delete.confirm')}
          </button>
        </DialogActions>
      </HistoryDialog>

      <HistoryDialog open={missingDeleteOpen} title={t('snapshots.history.delete.missingTitle')} onClose={closeDeleteDialogs}>
        <p>{t('snapshots.history.delete.missingMessage')}</p>
        <p>{t('snapshots.history.delete.irreversible')}</p>
        <ErrorText message={deleteError} />
        <DialogActions>
          <button type="button" onClick={closeDeleteDialogs} disabled={deleteMutation.isPending} className={secondaryButton} autoFocus>
            {t('common.cancel')}
          </button>
          <button
            type="button"
            onClick={confirmMissingObjectsDelete}
            disabled={deleteMutation.isPending}
            aria-busy={deleteMutation.isPending}
            className={dangerButton}
          >
            {deleteMutation.isPending && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
            {t('snapshots.history.delete.confirm')}
          </button>
        </DialogActions>
      </HistoryDialog>
    </section>
  )
}
