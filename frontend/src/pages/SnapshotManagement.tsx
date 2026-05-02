/**
 * Snapshot CRUD management page
 * - Create, delete, upload configuration or log files, and activate snapshots for Batfish analysis
 * - Drag-and-drop file upload with progress tracking and validation
 * - Form validation and React Query mutations for optimistic UI updates
 * - Zustand store integration for current snapshot state synchronization
 * - Handles multiple file uploads and snapshot lifecycle management
 */
import { useState, useCallback, useMemo, useRef } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import {
  Plus,
  Upload,
  Trash2,
  CheckCircle,
  FolderOpen,
  ChevronDown,
  ChevronRight,
  ArrowLeft,
  X,
  Loader2,
  GitCompare,
  Cable,
  FileText,
} from 'lucide-react'

import {
  useSnapshots,
  useSnapshotFiles,
  useCreateSnapshot,
  useDeleteSnapshot,
  useUpdateSnapshot,
  useUploadFile,
  useUpdateSnapshotFileFormat,
  useDeleteSnapshotFile,
  useActivateSnapshot,
  useParseResultSummary,
} from '../hooks'
import { useSnapshotStore } from '../store'
import { ConfirmDialog } from '../components/ConfirmDialog'
import { SnapshotFolderCombobox } from '../components/SnapshotFolderCombobox'
import { AdvancedArtifactPanel } from '../components/AdvancedArtifactPanel'
import { ParseResultSummaryCard } from '../components/validation/ParseResultDetails'
import type { Snapshot, SnapshotFile } from '../types'
import { extractErrorMessage } from '../types/errors'

const UNGROUPED_GROUP_KEY = 'ungrouped'
const AUTO_FORMAT_VALUE = 'auto'
const UNSUPPORTED_FORMAT_PREFIX = 'unsupported:'
const RANCID_FORMAT_OPTIONS = [
  { value: 'a10', labelKey: 'snapshots.format.options.a10' },
  { value: 'arista', labelKey: 'snapshots.format.options.arista' },
  { value: 'bigip', labelKey: 'snapshots.format.options.bigip' },
  { value: 'ios', labelKey: 'snapshots.format.options.ios' },
  { value: 'cisco-nx', labelKey: 'snapshots.format.options.ciscoNx' },
  { value: 'cisco-xr', labelKey: 'snapshots.format.options.ciscoXr' },
  { value: 'force10', labelKey: 'snapshots.format.options.force10' },
  { value: 'fortigate', labelKey: 'snapshots.format.options.fortigate' },
  { value: 'foundry', labelKey: 'snapshots.format.options.foundry' },
  { value: 'juniper', labelKey: 'snapshots.format.options.juniper' },
  { value: 'mrv', labelKey: 'snapshots.format.options.mrv' },
  { value: 'paloalto', labelKey: 'snapshots.format.options.paloAlto' },
] as const

const encodeGroupKeySegment = (value: string) =>
  Array.from(value)
    .map((char) => char.codePointAt(0)?.toString(36) ?? '0')
    .join('-')

const getSnapshotGroupKey = (folderName: string | null) =>
  folderName ? `folder:${encodeGroupKeySegment(folderName)}` : UNGROUPED_GROUP_KEY

const getFolderGroupPanelId = (groupKey: string) =>
  `snapshot-folder-group-${encodeGroupKeySegment(groupKey)}`

const getFileFormatControlId = (snapshotName: string, fileName: string) =>
  `snapshot-file-format-${encodeGroupKeySegment(snapshotName)}-${encodeGroupKeySegment(fileName)}`

const getFileFormatSelectValue = (file: SnapshotFile) => {
  if (
    file.unsupported_configuration_format_override !== null &&
    file.unsupported_configuration_format_override !== undefined
  ) {
    return `${UNSUPPORTED_FORMAT_PREFIX}${file.unsupported_configuration_format_override}`
  }

  return file.configuration_format_override || AUTO_FORMAT_VALUE
}

interface SnapshotGroup {
  key: string
  label: string
  isUngrouped: boolean
  snapshots: Snapshot[]
}

export function SnapshotManagement() {
  const { t } = useTranslation()
  const [selectedSnapshot, setSelectedSnapshot] = useState<string | null>(null)
  const [showCreateDialog, setShowCreateDialog] = useState(false)
  const [newSnapshotName, setNewSnapshotName] = useState('')
  const [newSnapshotFolder, setNewSnapshotFolder] = useState('')
  const [dragOver, setDragOver] = useState(false)
  const [validationError, setValidationError] = useState('')
  const [folderValidationError, setFolderValidationError] = useState('')
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false)
  const [snapshotToDelete, setSnapshotToDelete] = useState<string | null>(null)
  const [folderDraft, setFolderDraft] = useState('')
  const [uploadError, setUploadError] = useState('')
  const [fileFormatError, setFileFormatError] = useState('')
  const [fileDeleteError, setFileDeleteError] = useState('')
  const [fileReinitializeError, setFileReinitializeError] = useState('')
  const [fileDeleteConfirmOpen, setFileDeleteConfirmOpen] = useState(false)
  const [fileToDelete, setFileToDelete] = useState<{ snapshotName: string; file: SnapshotFile } | null>(null)
  const [fileChangeInProgressSnapshot, setFileChangeInProgressSnapshot] = useState<string | null>(null)
  const fileChangeInProgressRef = useRef<string | null>(null)
  const [collapsedFolderKeys, setCollapsedFolderKeys] = useState<Set<string>>(() => new Set())

  /**
   * Global Zustand state for active snapshot tracking
   * Synchronized across components to maintain consistent snapshot selection
   */
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)
  const setCurrentSnapshotName = useSnapshotStore((state) => state.setCurrentSnapshotName)
  const isSelectedSnapshotActive = !!selectedSnapshot && selectedSnapshot === currentSnapshotName

  /**
   * React Query data fetching hooks
   * - useSnapshots: Fetches all available snapshots list
   * - useSnapshotFiles: Fetches file list for selected snapshot (conditional query)
   */
  const { data: snapshots, isLoading: loadingSnapshots } = useSnapshots()
  const { data: files } = useSnapshotFiles(selectedSnapshot || '', !!selectedSnapshot)
  const parseResult = useParseResultSummary(isSelectedSnapshotActive)

  /**
   * React Query mutation hooks for snapshot operations
   * - useCreateSnapshot: Creates new empty snapshot
   * - useDeleteSnapshot: Deletes snapshot and all files
   * - useUploadFile: Uploads configuration file to snapshot
   * - useActivateSnapshot: Activates snapshot for Batfish analysis
   */
  const createMutation = useCreateSnapshot()
  const deleteMutation = useDeleteSnapshot()
  const updateMutation = useUpdateSnapshot()
  const uploadMutation = useUploadFile()
  const updateFileFormatMutation = useUpdateSnapshotFileFormat()
  const deleteFileMutation = useDeleteSnapshotFile()
  const activateMutation = useActivateSnapshot()

  const selectedSnapshotDetails = useMemo(
    () => snapshots?.find((snapshot) => snapshot.name === selectedSnapshot) ?? null,
    [selectedSnapshot, snapshots]
  )

  const folderOptions = useMemo(() => {
    const folders = new Set<string>()

    for (const snapshot of snapshots ?? []) {
      const folderName = snapshot.folder_name?.trim()
      if (folderName) {
        folders.add(folderName)
      }
    }

    return Array.from(folders).sort((left, right) => left.localeCompare(right))
  }, [snapshots])

  const groupedSnapshots = useMemo<SnapshotGroup[]>(() => {
    const groups = new Map<string, SnapshotGroup>()

    for (const snapshot of snapshots ?? []) {
      const folderName = snapshot.folder_name?.trim() || null
      const key = getSnapshotGroupKey(folderName)
      const existing = groups.get(key)

      if (existing) {
        existing.snapshots.push(snapshot)
      } else {
        groups.set(key, {
          key,
          label: folderName || t('snapshots.ungroupedFolder'),
          isUngrouped: !folderName,
          snapshots: [snapshot],
        })
      }
    }

    return Array.from(groups.values())
      .sort((left, right) => {
        if (left.isUngrouped) return 1
        if (right.isUngrouped) return -1
        return left.label.localeCompare(right.label)
      })
  }, [snapshots, t])

  const getFolderDisplayName = useCallback(
    (folderName?: string | null) => folderName || t('snapshots.ungroupedFolder'),
    [t]
  )

  const toggleFolderGroup = useCallback((groupKey: string) => {
    setCollapsedFolderKeys((current) => {
      const next = new Set(current)
      if (next.has(groupKey)) {
        next.delete(groupKey)
      } else {
        next.add(groupKey)
      }
      return next
    })
  }, [])

  /**
   * Handle snapshot creation with validation
   * Validates name (min 3 chars, alphanumeric+underscore+hyphen only)
   * On success: closes dialog, resets form, and selects new snapshot
   */
  const handleCreate = useCallback(() => {
    const trimmedName = newSnapshotName.trim()
    const trimmedFolder = newSnapshotFolder.trim()

    if (!trimmedName) {
      setValidationError('Snapshot name is required')
      return
    }

    if (trimmedName.length < 3) {
      setValidationError('Snapshot name must be at least 3 characters')
      return
    }

    if (!/^[a-zA-Z0-9_-]+$/.test(trimmedName)) {
      setValidationError('Only letters, numbers, hyphens, and underscores allowed')
      return
    }

    setValidationError('')
    createMutation.mutate(
      { name: trimmedName, folder_name: trimmedFolder || null },
      {
        onSuccess: (snapshot) => {
          if (!snapshot) {
            setValidationError('Failed to create snapshot')
            return
          }

          setShowCreateDialog(false)
          setNewSnapshotName('')
          setNewSnapshotFolder('')
          setValidationError('')
          setSelectedSnapshot(snapshot.name)
          setFolderDraft(snapshot.folder_name || '')
        },
        onError: (error: unknown) => {
          setValidationError(extractErrorMessage(error, 'Failed to create snapshot'))
        },
      }
    )
  }, [newSnapshotName, newSnapshotFolder, createMutation])

  /**
   * Persist folder classification for the selected snapshot
   */
  const handleFolderSave = useCallback(() => {
    if (!selectedSnapshot) return

    updateMutation.mutate(
      {
        name: selectedSnapshot,
        request: {
          folder_name: folderDraft.trim() || null,
        },
      },
      {
        onSuccess: (snapshot) => {
          if (!snapshot) {
            setFolderValidationError('Failed to update snapshot folder')
            return
          }

          setFolderDraft(snapshot.folder_name || '')
          setFolderValidationError('')
        },
        onError: (error: unknown) => {
          setFolderValidationError(extractErrorMessage(error, 'Failed to update snapshot folder'))
        },
      }
    )
  }, [folderDraft, selectedSnapshot, updateMutation])

  /**
   * Handle snapshot deletion with confirmation dialog
   * Opens ConfirmDialog instead of native window.confirm
   */
  const handleDelete = useCallback((name: string) => {
    setSnapshotToDelete(name)
    setDeleteConfirmOpen(true)
  }, [])

  /**
   * Confirm and execute snapshot deletion
   * Updates selected snapshot and current snapshot state if deleted snapshot was active
   */
  const confirmDelete = useCallback(() => {
    if (!snapshotToDelete) return

    deleteMutation.mutate(snapshotToDelete, {
      onSuccess: () => {
        if (selectedSnapshot === snapshotToDelete) {
          setSelectedSnapshot(null)
        }
        if (currentSnapshotName === snapshotToDelete) {
          setCurrentSnapshotName(null)
        }
        if (selectedSnapshot === snapshotToDelete) {
          setFolderDraft('')
          setFolderValidationError('')
        }
        setDeleteConfirmOpen(false)
        setSnapshotToDelete(null)
      },
      onError: () => {
        setDeleteConfirmOpen(false)
        setSnapshotToDelete(null)
      },
    })
  }, [deleteMutation, snapshotToDelete, selectedSnapshot, currentSnapshotName, setCurrentSnapshotName])

  /**
   * Cancel snapshot deletion
   */
  const cancelDelete = useCallback(() => {
    setDeleteConfirmOpen(false)
    setSnapshotToDelete(null)
  }, [])

  /**
   * Handle file upload to selected snapshot
   * Processes multiple files concurrently via React Query mutation
   */
  const handleFileUpload = useCallback(
    (files: FileList | null) => {
      if (!files || !selectedSnapshot) return
      const uploadFiles = Array.from(files)
      if (uploadFiles.length === 0) return
      const changedSnapshotName = selectedSnapshot
      const shouldReactivate = useSnapshotStore.getState().currentSnapshotName === changedSnapshotName

      if (shouldReactivate) {
        if (activateMutation.isPending || fileChangeInProgressRef.current !== null) {
          setUploadError(t('snapshots.fileChangeBusy'))
          return
        }
        fileChangeInProgressRef.current = changedSnapshotName
        setFileChangeInProgressSnapshot(changedSnapshotName)
        setFileReinitializeError('')
      }

      setUploadError('')
      let remainingUploads = uploadFiles.length
      let requiresReinitialize = false
      const finishUpload = () => {
        remainingUploads -= 1
        if (remainingUploads > 0) return

        if (!shouldReactivate) return

        if (!requiresReinitialize) {
          fileChangeInProgressRef.current = null
          setFileChangeInProgressSnapshot(null)
          return
        }

        activateMutation.mutate(changedSnapshotName, {
          onSuccess: () => {
            setCurrentSnapshotName(changedSnapshotName)
            setFileReinitializeError('')
          },
          onError: (error: unknown) => {
            setFileReinitializeError(
              extractErrorMessage(error, t('snapshots.reinitializeFailedAfterFileChange'))
            )
          },
          onSettled: () => {
            fileChangeInProgressRef.current = null
            setFileChangeInProgressSnapshot(null)
          },
        })
      }

      uploadFiles.forEach((file) => {
        uploadMutation.mutate(
          {
            name: changedSnapshotName,
            file,
          },
          {
            onSuccess: (response) => {
              if (response?.requires_reinitialize) {
                requiresReinitialize = true
              }
              finishUpload()
            },
            onError: (error: unknown) => {
              setUploadError((currentError) => (
                currentError || extractErrorMessage(error, `Failed to upload file '${file.name}'`)
              ))
              finishUpload()
            },
          }
        )
      })
    },
    [activateMutation, selectedSnapshot, setCurrentSnapshotName, t, uploadMutation]
  )

  /**
   * Drag and drop event handlers for file upload
   * - handleDragOver: Prevents default and sets visual feedback
   * - handleDragLeave: Removes visual feedback when drag leaves area
   * - handleDrop: Processes dropped files and triggers upload
   */
  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragOver(true)
  }, [])

  const handleDragLeave = useCallback(() => {
    setDragOver(false)
  }, [])

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault()
      setDragOver(false)
      handleFileUpload(e.dataTransfer.files)
    },
    [handleFileUpload]
  )

  /**
   * Activate snapshot for Batfish analysis
   * Updates global state to make this snapshot the current active one
   * Triggers Batfish initialization for network analysis queries
   */
  const handleActivate = useCallback(
    (name: string) => {
      activateMutation.mutate(name, {
        onSuccess: () => {
          setCurrentSnapshotName(name)
        },
      })
    },
    [activateMutation, setCurrentSnapshotName]
  )

  const startFileChangeOperation = useCallback((snapshotName: string) => {
    if (fileChangeInProgressRef.current !== null) {
      return false
    }

    fileChangeInProgressRef.current = snapshotName
    setFileChangeInProgressSnapshot(snapshotName)
    return true
  }, [])

  const finishFileChangeOperation = useCallback((snapshotName: string) => {
    if (fileChangeInProgressRef.current !== snapshotName) {
      return
    }

    fileChangeInProgressRef.current = null
    setFileChangeInProgressSnapshot(null)
  }, [])

  /**
   * Re-activate the current snapshot after file content changes so Batfish cache is refreshed.
   */
  const reactivateCurrentSnapshotAfterFileChange = useCallback(
    (snapshotName: string, onSettled?: () => void) => {
      if (useSnapshotStore.getState().currentSnapshotName !== snapshotName) {
        onSettled?.()
        return
      }

      activateMutation.mutate(snapshotName, {
        onSuccess: () => {
          setCurrentSnapshotName(snapshotName)
          setFileReinitializeError('')
        },
        onError: (error: unknown) => {
          setFileReinitializeError(
            extractErrorMessage(error, t('snapshots.reinitializeFailedAfterFileChange'))
          )
        },
        onSettled: () => {
          onSettled?.()
        },
      })
    },
    [activateMutation, setCurrentSnapshotName, t]
  )

  /**
   * Persist Batfish vendor format override for a single uploaded file.
   */
  const handleFileFormatChange = useCallback(
    (file: SnapshotFile, value: string) => {
      if (!selectedSnapshot || value.startsWith(UNSUPPORTED_FORMAT_PREFIX)) return
      if (activateMutation.isPending) return
      if (!startFileChangeOperation(selectedSnapshot)) return

      setFileFormatError('')
      setFileReinitializeError('')

      const changedSnapshotName = selectedSnapshot
      const configurationFormatOverride = value === AUTO_FORMAT_VALUE ? null : value
      updateFileFormatMutation.mutate(
        {
          name: changedSnapshotName,
          filename: file.name,
          configurationFormatOverride,
        },
        {
          onSuccess: (response) => {
            if (response?.requires_reinitialize) {
              reactivateCurrentSnapshotAfterFileChange(changedSnapshotName, () =>
                finishFileChangeOperation(changedSnapshotName)
              )
              return
            }

            finishFileChangeOperation(changedSnapshotName)
          },
          onError: (error: unknown) => {
            setFileFormatError(extractErrorMessage(error, t('snapshots.format.updateFailed')))
            finishFileChangeOperation(changedSnapshotName)
          },
        }
      )
    },
    [
      activateMutation.isPending,
      finishFileChangeOperation,
      reactivateCurrentSnapshotAfterFileChange,
      selectedSnapshot,
      startFileChangeOperation,
      t,
      updateFileFormatMutation,
    ]
  )

  /**
   * Open file delete confirmation for one uploaded file.
   */
  const handleFileDelete = useCallback(
    (file: SnapshotFile) => {
      if (!selectedSnapshot) return
      if (activateMutation.isPending) return
      if (fileChangeInProgressRef.current !== null) return

      setFileDeleteError('')
      setFileReinitializeError('')
      setFileToDelete({ snapshotName: selectedSnapshot, file })
      setFileDeleteConfirmOpen(true)
    },
    [activateMutation.isPending, selectedSnapshot]
  )

  /**
   * Confirm and execute uploaded file deletion.
   */
  const confirmFileDelete = useCallback(() => {
    if (!fileToDelete) return
    if (activateMutation.isPending) return
    if (!startFileChangeOperation(fileToDelete.snapshotName)) return

    const changedSnapshotName = fileToDelete.snapshotName
    deleteFileMutation.mutate(
      {
        name: changedSnapshotName,
        filename: fileToDelete.file.name,
      },
      {
        onSuccess: (response) => {
          setFileDeleteConfirmOpen(false)
          setFileToDelete(null)

          if (response?.requires_reinitialize) {
            reactivateCurrentSnapshotAfterFileChange(changedSnapshotName, () =>
              finishFileChangeOperation(changedSnapshotName)
            )
            return
          }

          finishFileChangeOperation(changedSnapshotName)
        },
        onError: (error: unknown) => {
          setFileDeleteError(extractErrorMessage(error, t('snapshots.deleteFileFailed')))
          setFileDeleteConfirmOpen(false)
          setFileToDelete(null)
          finishFileChangeOperation(changedSnapshotName)
        },
      }
    )
  }, [
    activateMutation.isPending,
    deleteFileMutation,
    fileToDelete,
    finishFileChangeOperation,
    reactivateCurrentSnapshotAfterFileChange,
    startFileChangeOperation,
    t,
  ])

  /**
   * Cancel uploaded file deletion.
   */
  const cancelFileDelete = useCallback(() => {
    setFileDeleteConfirmOpen(false)
    setFileToDelete(null)
  }, [])

  /**
   * Handle snapshot selection and synchronize editable folder state
   */
  const handleSnapshotSelection = useCallback(
    (snapshot: Snapshot) => {
      if (fileChangeInProgressRef.current !== null) return

      setSelectedSnapshot(snapshot.name)
      setFolderDraft(snapshot.folder_name || '')
      setFolderValidationError('')
      setFileFormatError('')
      setFileDeleteError('')
      setFileReinitializeError('')
      setFileDeleteConfirmOpen(false)
      setFileToDelete(null)

      if (currentSnapshotName !== snapshot.name) {
        handleActivate(snapshot.name)
      }
    },
    [currentSnapshotName, handleActivate]
  )

  /**
   * Format byte size to human-readable string
   * Converts raw bytes to appropriate unit (B, KB, MB, GB) with 2 decimal places
   * @param bytes - Raw byte count to format
   * @returns Formatted string like "1.25 MB" or "512 KB"
   */
  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`
  }

  const currentFolderValue = selectedSnapshotDetails?.folder_name || ''
  const parseResultSubtitle =
    selectedSnapshot && fileChangeInProgressSnapshot === selectedSnapshot
      ? t('snapshots.parseResult.refreshing')
      : fileReinitializeError
      ? t('snapshots.parseResult.stale')
      : parseResult.isError
      ? t('snapshots.parseResult.loadFailed')
      : t('snapshots.parseResult.activeHelp')
  const parseResultSummaryForDisplay = parseResult.isError
    ? { ...parseResult.summary, severity: 'error' as const }
    : parseResult.summary
  const isFolderDirty = currentFolderValue !== (folderDraft.trim() || '')
  const isSnapshotActivationPending = activateMutation.isPending
  const isFileChangeInProgress = fileChangeInProgressSnapshot !== null
  const isFileDeleteDialogOpenForSelectedSnapshot = !!(
    selectedSnapshot &&
    fileDeleteConfirmOpen &&
    fileToDelete?.snapshotName === selectedSnapshot
  )
  const isSelectedSnapshotFileActionBlocked =
    isSnapshotActivationPending || isFileChangeInProgress || isFileDeleteDialogOpenForSelectedSnapshot

  return (
    <div className="flex flex-col h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b border-gray-200 px-6 py-4" role="banner">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Link
              to="/"
              className="p-2 hover:bg-gray-100 rounded-lg transition-colors focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-2"
              aria-label={t('snapshots.backToTopology')}
            >
              <ArrowLeft className="w-5 h-5" aria-hidden="true" />
              <span className="sr-only">{t('snapshots.backToTopology')}</span>
            </Link>
            <h1 className="text-2xl font-bold text-gray-900">{t('snapshots.title')}</h1>
          </div>
          <div className="flex items-center gap-3">
            <Link
              to="/snapshots/compare"
              className="flex items-center gap-2 px-4 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 transition-colors font-medium shadow-sm hover:shadow-md focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-2"
              aria-label={t('snapshots.compareSnapshots')}
            >
              <GitCompare className="w-4 h-4" aria-hidden="true" />
              {t('snapshots.compareSnapshots')}
            </Link>
            <button
              onClick={() => setShowCreateDialog(true)}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-medium shadow-sm hover:shadow-md focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-2"
              aria-label={t('snapshots.newSnapshot')}
            >
              <Plus className="w-4 h-4" aria-hidden="true" />
              {t('snapshots.newSnapshot')}
            </button>
          </div>
        </div>
      </header>

      {/* Main content */}
      <div className="flex-1 flex overflow-hidden">
        {/* Snapshots list */}
        <nav className="w-96 bg-white border-r border-gray-200 overflow-y-auto" aria-label={t('snapshots.listTitle')}>
          <div className="p-4">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">{t('snapshots.listTitle')}</h2>

            {loadingSnapshots ? (
              <div className="text-center py-8 text-gray-700 font-medium" role="status" aria-live="polite">
                <span className="sr-only">{t('snapshots.loading')}</span>
                {t('common.loading')}
              </div>
            ) : !snapshots || snapshots.length === 0 ? (
              <div className="text-center py-8 text-gray-700">
                <FolderOpen className="w-12 h-12 mx-auto mb-3 text-gray-500" aria-hidden="true" />
                <p className="font-semibold text-base">{t('snapshots.noSnapshots')}</p>
                <p className="text-sm mt-2 text-gray-700">{t('snapshots.createToStart')}</p>
              </div>
            ) : (
              <div className="space-y-4" role="list" aria-label="Available snapshots">
                {groupedSnapshots.map((group) => {
                  const groupHasSelectedOrCurrent = group.snapshots.some(
                    (snapshot) => snapshot.name === selectedSnapshot || snapshot.name === currentSnapshotName
                  )
                  const isGroupOpen = groupHasSelectedOrCurrent || !collapsedFolderKeys.has(group.key)
                  const folderPanelId = getFolderGroupPanelId(group.key)
                  const folderHeadingId = `${folderPanelId}-heading`
                  const folderToggleLabel = groupHasSelectedOrCurrent
                    ? t('snapshots.folderKeptOpen', { folder: group.label })
                    : t(isGroupOpen ? 'snapshots.collapseFolder' : 'snapshots.expandFolder', {
                        folder: group.label,
                      })

                  return (
                    <section key={group.key} role="listitem" className="space-y-2" aria-labelledby={folderHeadingId}>
                      <button
                        type="button"
                        onClick={() => toggleFolderGroup(group.key)}
                        disabled={groupHasSelectedOrCurrent}
                        className="w-full flex items-center gap-2 px-1 py-1 text-left rounded focus:outline-none focus:ring-2 focus:ring-primary-600 disabled:cursor-default"
                        aria-expanded={isGroupOpen}
                        aria-controls={folderPanelId}
                        aria-label={folderToggleLabel}
                        title={folderToggleLabel}
                      >
                        {isGroupOpen ? (
                          <ChevronDown className="w-4 h-4 text-gray-500 flex-shrink-0" aria-hidden="true" />
                        ) : (
                          <ChevronRight className="w-4 h-4 text-gray-500 flex-shrink-0" aria-hidden="true" />
                        )}
                        <FolderOpen className="w-4 h-4 text-gray-500 flex-shrink-0" aria-hidden="true" />
                        <span id={folderHeadingId} className="text-sm font-semibold text-gray-700 truncate">
                          {group.label}
                        </span>
                        <span
                          className="ml-auto inline-flex min-w-6 justify-center rounded-full bg-gray-100 px-2 py-0.5 text-xs font-medium text-gray-700"
                          aria-label={t('snapshots.folderSnapshotCount', { count: group.snapshots.length })}
                        >
                          {group.snapshots.length}
                        </span>
                      </button>

                      <div id={folderPanelId} role="group" aria-labelledby={folderHeadingId} hidden={!isGroupOpen} className="space-y-2">
                        {group.snapshots.map((snapshot: Snapshot) => (
                          <div
                            key={snapshot.name}
                            role="button"
                            className={`p-4 rounded-lg border-2 ${
                              isFileChangeInProgress ? 'cursor-not-allowed opacity-75' : 'cursor-pointer'
                            } transition-colors focus-within:ring-2 focus-within:ring-primary-600 ${
                              currentSnapshotName === snapshot.name
                                ? 'border-green-500 bg-green-50'
                                : activateMutation.isPending && activateMutation.variables === snapshot.name
                                ? 'border-blue-400 bg-blue-50 opacity-75'
                                : selectedSnapshot === snapshot.name
                                ? 'border-blue-500 bg-blue-50'
                                : 'border-gray-200 hover:border-gray-300 hover:shadow-sm'
                            }`}
                            onClick={() => handleSnapshotSelection(snapshot)}
                            tabIndex={0}
                            aria-pressed={selectedSnapshot === snapshot.name}
                            aria-disabled={isFileChangeInProgress}
                            aria-label={`Snapshot ${snapshot.name} in folder ${getFolderDisplayName(snapshot.folder_name)} with ${snapshot.file_count} files${
                              currentSnapshotName === snapshot.name
                                ? ' - currently active'
                                : activateMutation.isPending && activateMutation.variables === snapshot.name
                                ? ' - activating...'
                                : ''
                            }. Click to activate and view files`}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter' || e.key === ' ') {
                                e.preventDefault()
                                handleSnapshotSelection(snapshot)
                              }
                            }}
                          >
                            <div className="flex items-start justify-between mb-2 gap-3">
                              <div className="min-w-0">
                                <p className="text-xs font-medium uppercase tracking-wide text-gray-500">
                                  {getFolderDisplayName(snapshot.folder_name)}
                                </p>
                                <h4 className="font-semibold text-gray-900 truncate">{snapshot.name}</h4>
                              </div>
                              {currentSnapshotName === snapshot.name ? (
                                <CheckCircle className="w-5 h-5 text-green-600 flex-shrink-0" aria-hidden="true" />
                              ) : activateMutation.isPending && activateMutation.variables === snapshot.name ? (
                                <Loader2 className="w-5 h-5 text-blue-600 flex-shrink-0 animate-spin" aria-hidden="true" />
                              ) : null}
                            </div>
                            <div className="text-sm text-gray-800 space-y-1 font-medium">
                              <p>{t('snapshots.fileCount', { count: snapshot.file_count })}</p>
                              <p>{formatBytes(snapshot.size_bytes)}</p>
                              <p className="text-xs text-gray-700 font-normal">
                                {new Date(snapshot.created_at).toLocaleString()}
                              </p>
                            </div>
                            <div className="flex justify-end mt-3">
                              <button
                                onClick={(e) => {
                                  e.stopPropagation()
                                  handleDelete(snapshot.name)
                                }}
                                disabled={deleteMutation.isPending}
                                className="px-3 py-1.5 text-sm bg-red-600 text-white rounded hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors focus:outline-none focus:ring-2 focus:ring-red-600 focus:ring-offset-1"
                                aria-label={`Delete snapshot ${snapshot.name}`}
                                aria-busy={deleteMutation.isPending}
                              >
                                <Trash2 className="w-4 h-4" aria-hidden="true" />
                                <span className="sr-only">Delete</span>
                              </button>
                            </div>
                          </div>
                        ))}
                      </div>
                    </section>
                  )
                })}
              </div>
            )}
          </div>
        </nav>

        {/* File management */}
        <div className="flex-1 overflow-y-auto p-6">
          {selectedSnapshot ? (
            <>
              <div className="flex items-center justify-between mb-4">
                <div>
                  <p className="text-sm font-medium text-gray-500">
                    {getFolderDisplayName(selectedSnapshotDetails?.folder_name)}
                  </p>
                  <h2 className="text-xl font-semibold text-gray-900">
                    {t('snapshots.filesIn', { name: selectedSnapshot })}
                  </h2>
                </div>
                <Link
                  to={`/snapshots/${selectedSnapshot}/layer1-editor`}
                  className="inline-flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
                >
                  <Cable className="w-4 h-4" />
                  {t('snapshots.editLayer1')}
                </Link>
              </div>

              <div className="bg-white border border-gray-200 rounded-lg p-4 mb-6">
                <div className="flex flex-col gap-4 md:flex-row md:items-end">
                  <div className="flex-1">
                    <label htmlFor="snapshot-folder-input" className="block text-sm font-medium text-gray-800 mb-1">
                      {t('snapshots.folderLabel')}
                    </label>
                    <SnapshotFolderCombobox
                      id="snapshot-folder-input"
                      value={folderDraft}
                      onChange={(value) => {
                        setFolderDraft(value)
                        setFolderValidationError('')
                      }}
                      options={folderOptions}
                      placeholder={t('snapshots.folderPlaceholder')}
                      hasError={!!folderValidationError}
                      ariaDescribedBy={`snapshot-folder-help${folderValidationError ? ' snapshot-folder-error' : ''}`}
                    />
                    <p id="snapshot-folder-help" className="mt-2 text-xs text-gray-600">{t('snapshots.folderHelp')}</p>
                    {folderValidationError && (
                      <p id="snapshot-folder-error" className="mt-2 text-sm text-red-600 font-medium" role="alert">
                        {folderValidationError}
                      </p>
                    )}
                  </div>
                  <button
                    onClick={handleFolderSave}
                    disabled={updateMutation.isPending || !isFolderDirty}
                    className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors font-medium"
                  >
                    {updateMutation.isPending ? t('snapshots.savingFolder') : t('snapshots.saveFolder')}
                  </button>
                </div>
              </div>

              <div className="mb-6">
                {isSelectedSnapshotActive ? (
                  <>
                    <ParseResultSummaryCard
                      title={t('snapshots.parseResult.title')}
                      subtitle={parseResultSubtitle}
                      summary={parseResultSummaryForDisplay}
                      isLoading={parseResult.isLoading || fileChangeInProgressSnapshot === selectedSnapshot}
                      compact
                    />
                    {parseResult.isError && (
                      <p className="mt-2 rounded-lg border border-yellow-200 bg-yellow-50 px-4 py-3 text-sm font-medium text-yellow-800" role="alert">
                        {t('snapshots.parseResult.loadFailed')}
                      </p>
                    )}
                  </>
                ) : (
                  <div className="rounded-lg border border-gray-200 bg-white p-4 text-sm text-gray-700">
                    <div className="flex items-center gap-2">
                      <FileText className="h-5 w-5 text-gray-500" aria-hidden="true" />
                      <span className="font-medium">{t('snapshots.parseResult.inactive')}</span>
                    </div>
                  </div>
                )}
              </div>

              {/* Upload area */}
              <div
                className={`border-2 border-dashed rounded-lg p-8 mb-6 text-center transition-colors ${
                  dragOver
                    ? 'border-blue-500 bg-blue-50'
                    : 'border-gray-300 hover:border-gray-400'
                }`}
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
                role="region"
                aria-label="File upload area"
                aria-describedby="upload-instructions"
              >
                <Upload className="w-12 h-12 mx-auto mb-4 text-gray-500" aria-hidden="true" />
                <p className="text-lg font-semibold text-gray-900 mb-2">
                  {t('snapshots.dropFiles')}
                </p>
                <p className="text-sm text-gray-700 mb-4 font-medium">{t('common.or')}</p>
                <label className="inline-flex items-center gap-2 px-4 py-2 bg-white border border-gray-300 rounded-lg cursor-pointer hover:bg-gray-50 hover:border-gray-400 transition-colors font-medium text-gray-800 focus-within:ring-2 focus-within:ring-primary-600">
                  <Upload className="w-4 h-4" aria-hidden="true" />
                  {t('snapshots.chooseFiles')}
                  <input
                    type="file"
                    multiple
                    accept=".cfg,.conf,.txt,.log"
                    className="hidden"
                    onChange={(e) => handleFileUpload(e.target.files)}
                    disabled={isSelectedSnapshotFileActionBlocked}
                    aria-label={t('snapshots.chooseFilesAria')}
                    aria-describedby="upload-instructions"
                  />
                </label>
                <p id="upload-instructions" className="text-xs text-gray-700 mt-3 font-medium">
                  {t('snapshots.supportedFormats')}
                </p>
                {uploadMutation.isPending && (
                  <div role="status" aria-live="polite" className="mt-4">
                    <span className="text-sm text-blue-600">{t('snapshots.uploading')}</span>
                  </div>
                )}
                {uploadError && (
                  <p className="mt-4 text-sm text-red-600 font-medium" role="alert">
                    {uploadError}
                  </p>
                )}
              </div>

              {/* Files list */}
              {files && files.length > 0 ? (
                <div className="space-y-3">
                  <div className="rounded-lg border border-blue-100 bg-blue-50 px-4 py-3 text-sm text-blue-900">
                    <p className="font-medium">{t('snapshots.format.help')}</p>
                    <p className="mt-1 text-blue-800">{t('snapshots.format.logWarning')}</p>
                  </div>
                  {fileFormatError && (
                    <p className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm font-medium text-red-700" role="alert">
                      {fileFormatError}
                    </p>
                  )}
                  {fileDeleteError && (
                    <p className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm font-medium text-red-700" role="alert">
                      {fileDeleteError}
                    </p>
                  )}
                  {fileReinitializeError && (
                    <p className="rounded-lg border border-yellow-200 bg-yellow-50 px-4 py-3 text-sm font-medium text-yellow-800" role="alert">
                      {fileReinitializeError}
                    </p>
                  )}
                  <div className="overflow-hidden rounded-lg bg-white shadow">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50">
                        <tr>
                          <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 uppercase tracking-wider">
                            {t('snapshots.table.filenameAndFormat')}
                          </th>
                          <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 uppercase tracking-wider">
                            {t('snapshots.table.size')}
                          </th>
                          <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 uppercase tracking-wider">
                            {t('snapshots.table.modified')}
                          </th>
                        </tr>
                      </thead>
                      <tbody className="bg-white divide-y divide-gray-200">
                        {files.map((file) => {
                          const formatSelectValue = getFileFormatSelectValue(file)
                          const formatControlId = getFileFormatControlId(selectedSnapshot, file.name)
                          const unsupportedFormat = file.unsupported_configuration_format_override
                          const hasUnsupportedFormat =
                            unsupportedFormat !== null && unsupportedFormat !== undefined
                          const unsupportedFormatLabel =
                            unsupportedFormat || t('snapshots.format.emptyHeader')
                          const formatOverrideError = file.format_override_error
                          const isUpdatingFormat =
                            updateFileFormatMutation.isPending &&
                            updateFileFormatMutation.variables?.name === selectedSnapshot &&
                            updateFileFormatMutation.variables?.filename === file.name
                          const isDeletingFile =
                            deleteFileMutation.isPending &&
                            deleteFileMutation.variables?.name === selectedSnapshot &&
                            deleteFileMutation.variables?.filename === file.name

                          return (
                            <tr key={file.name} className="hover:bg-gray-50">
                              <td className="px-6 py-4 align-top text-sm text-gray-900">
                                <div className="flex flex-col gap-2 xl:flex-row xl:items-center xl:gap-4">
                                  <span className="min-w-0 break-all font-semibold">{file.name}</span>
                                  <div className="min-w-[13rem] max-w-xs">
                                    <label htmlFor={formatControlId} className="sr-only">
                                      {t('snapshots.format.ariaLabel', { name: file.name })}
                                    </label>
                                    <select
                                      id={formatControlId}
                                      value={formatSelectValue}
                                      disabled={
                                        isSelectedSnapshotFileActionBlocked ||
                                        file.format_override_supported === false
                                      }
                                      onChange={(event) => handleFileFormatChange(file, event.target.value)}
                                      className="w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm font-medium text-gray-800 shadow-sm transition-colors focus:border-primary-600 focus:outline-none focus:ring-2 focus:ring-primary-600 disabled:cursor-not-allowed disabled:opacity-60"
                                      aria-label={t('snapshots.format.ariaLabel', { name: file.name })}
                                    >
                                      {hasUnsupportedFormat && (
                                        <option value={`${UNSUPPORTED_FORMAT_PREFIX}${unsupportedFormat}`} disabled>
                                          {t('snapshots.format.unsupportedOption', { format: unsupportedFormatLabel })}
                                        </option>
                                      )}
                                      <option value={AUTO_FORMAT_VALUE}>{t('snapshots.format.auto')}</option>
                                      {RANCID_FORMAT_OPTIONS.map((option) => (
                                        <option key={option.value} value={option.value}>
                                          {t(option.labelKey)}
                                        </option>
                                      ))}
                                    </select>
                                    {isUpdatingFormat && (
                                      <p className="mt-1 text-xs font-medium text-blue-700">
                                        {t('snapshots.format.updating')}
                                      </p>
                                    )}
                                    {hasUnsupportedFormat && (
                                      <p className="mt-1 text-xs font-medium text-yellow-700">
                                        {t('snapshots.format.unsupportedHeader', { format: unsupportedFormatLabel })}
                                      </p>
                                    )}
                                    {formatOverrideError && (
                                      <p className="mt-1 text-xs font-medium text-red-700">
                                        {t('snapshots.format.readFailed')}
                                      </p>
                                    )}
                                  </div>
                                </div>
                              </td>
                              <td className="px-6 py-4 align-top whitespace-nowrap text-sm text-gray-800 font-medium">
                                {formatBytes(file.size_bytes)}
                              </td>
                              <td className="px-6 py-4 align-top whitespace-nowrap text-sm text-gray-700 font-medium">
                                <div className="flex items-center justify-between gap-4">
                                  <span>{new Date(file.modified_at).toLocaleString()}</span>
                                  <button
                                    type="button"
                                    onClick={() => handleFileDelete(file)}
                                    disabled={isSelectedSnapshotFileActionBlocked}
                                    className="inline-flex h-9 w-9 items-center justify-center rounded-md border border-red-200 text-red-600 transition-colors hover:bg-red-50 hover:text-red-700 focus:outline-none focus:ring-2 focus:ring-red-600 focus:ring-offset-1 disabled:cursor-not-allowed disabled:opacity-50"
                                    aria-label={t('snapshots.deleteFileAria', { name: file.name })}
                                    aria-busy={isDeletingFile}
                                    title={t('snapshots.deleteFile')}
                                  >
                                    {isDeletingFile ? (
                                      <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                                    ) : (
                                      <Trash2 className="h-4 w-4" aria-hidden="true" />
                                    )}
                                  </button>
                                </div>
                              </td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              ) : (
                <div className="text-center py-12 text-gray-700">
                  <p className="font-semibold text-base">{t('snapshots.noFiles')}</p>
                  <p className="text-sm mt-2 text-gray-700">{t('snapshots.uploadToStart')}</p>
                </div>
              )}

              <AdvancedArtifactPanel snapshotName={selectedSnapshot} />
            </>
          ) : (
            <div className="flex items-center justify-center h-full text-gray-700">
              <div className="text-center">
                <FolderOpen className="w-16 h-16 mx-auto mb-4 text-gray-500" />
                <p className="text-lg font-semibold">{t('snapshots.selectSnapshot')}</p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Create dialog */}
      {showCreateDialog && (
        <div
          className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50"
          role="dialog"
          aria-modal="true"
          aria-labelledby="create-dialog-title"
          onClick={() => {
            setShowCreateDialog(false)
            setValidationError('')
            setNewSnapshotName('')
            setNewSnapshotFolder('')
          }}
        >
          <div
            className="bg-white rounded-lg shadow-xl p-6 w-full max-w-md"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between mb-4">
              <h3 id="create-dialog-title" className="text-lg font-semibold text-gray-900">
                {t('snapshots.createDialog.title')}
              </h3>
              <button
                onClick={() => {
                  setShowCreateDialog(false)
                  setValidationError('')
                  setNewSnapshotName('')
                  setNewSnapshotFolder('')
                }}
                className="p-1 hover:bg-gray-100 rounded focus:outline-none focus:ring-2 focus:ring-primary-600"
                aria-label={t('common.closeDialog')}
              >
                <X className="w-5 h-5" aria-hidden="true" />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label htmlFor="snapshot-name-input" className="block text-sm font-medium text-gray-800 mb-1">
                  {t('snapshots.createDialog.nameLabel')}
                </label>
                <input
                  id="snapshot-name-input"
                  type="text"
                  value={newSnapshotName}
                  onChange={(e) => {
                    setNewSnapshotName(e.target.value)
                    setValidationError('')
                  }}
                  onKeyDown={(e) => e.key === 'Enter' && handleCreate()}
                  placeholder="my-network-snapshot"
                  className={`w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 transition-colors ${
                    validationError
                      ? 'border-red-500 focus:ring-red-500 bg-red-50'
                      : 'border-gray-300 focus:ring-primary-600'
                  }`}
                  autoFocus
                  aria-invalid={!!validationError}
                  aria-describedby={validationError ? 'snapshot-name-error' : 'snapshot-name-hint'}
                />
                <p id="snapshot-name-hint" className="sr-only">
                  Enter a name for your snapshot using letters, numbers, hyphens, and underscores
                </p>
                {validationError && (
                  <p id="snapshot-name-error" className="mt-2 text-sm text-red-600 font-medium" role="alert">
                    {validationError}
                  </p>
                )}
              </div>

              <div>
                <label htmlFor="snapshot-folder-create-input" className="block text-sm font-medium text-gray-800 mb-1">
                  {t('snapshots.createDialog.folderLabel')}
                </label>
                <SnapshotFolderCombobox
                  id="snapshot-folder-create-input"
                  value={newSnapshotFolder}
                  onChange={setNewSnapshotFolder}
                  options={folderOptions}
                  placeholder={t('snapshots.folderPlaceholder')}
                  ariaDescribedBy="snapshot-folder-create-help"
                />
                <p id="snapshot-folder-create-help" className="mt-2 text-xs text-gray-600">{t('snapshots.folderHelp')}</p>
              </div>

              <div className="flex gap-3 justify-end">
                <button
                  onClick={() => {
                    setShowCreateDialog(false)
                    setValidationError('')
                    setNewSnapshotName('')
                    setNewSnapshotFolder('')
                  }}
                  className="px-4 py-2 text-gray-800 hover:bg-gray-100 rounded-lg transition-colors font-medium focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-1"
                >
                  {t('common.cancel')}
                </button>
                <button
                  onClick={handleCreate}
                  disabled={createMutation.isPending}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors font-medium focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-1"
                  aria-busy={createMutation.isPending}
                >
                  {createMutation.isPending ? t('snapshots.createDialog.creating') : t('common.create')}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Delete confirmation dialog */}
      <ConfirmDialog
        isOpen={deleteConfirmOpen}
        title={t('snapshots.deleteConfirm.title', 'Delete Snapshot')}
        message={t('snapshots.deleteConfirm.message', { name: snapshotToDelete }) || `Are you sure you want to delete "${snapshotToDelete}"? This action cannot be undone.`}
        confirmText={t('common.delete', 'Delete')}
        cancelText={t('common.cancel', 'Cancel')}
        onConfirm={confirmDelete}
        onCancel={cancelDelete}
        variant="danger"
        isLoading={deleteMutation.isPending}
      />
      <ConfirmDialog
        isOpen={fileDeleteConfirmOpen}
        title={t('snapshots.deleteFileConfirm.title')}
        message={t('snapshots.deleteFileConfirm.message', {
          snapshot: fileToDelete?.snapshotName ?? '',
          file: fileToDelete?.file.name ?? '',
        })}
        confirmText={t('common.delete', 'Delete')}
        cancelText={t('common.cancel', 'Cancel')}
        onConfirm={confirmFileDelete}
        onCancel={cancelFileDelete}
        variant="danger"
        isLoading={deleteFileMutation.isPending}
      />
    </div>
  )
}
