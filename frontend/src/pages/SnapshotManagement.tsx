/**
 * Snapshot CRUD management page
 * - Create, delete, upload configuration or log files, and activate snapshots for Batfish analysis
 * - Drag-and-drop file upload with progress tracking and validation
 * - Form validation and React Query mutations for optimistic UI updates
 * - Zustand store integration for current snapshot state synchronization
 * - Handles multiple file uploads and snapshot lifecycle management
 */
import { useState, useCallback, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import {
  Plus,
  Upload,
  Trash2,
  CheckCircle,
  FolderOpen,
  ArrowLeft,
  X,
  Loader2,
  GitCompare,
  Cable,
} from 'lucide-react'

import {
  useSnapshots,
  useSnapshotFiles,
  useCreateSnapshot,
  useDeleteSnapshot,
  useUpdateSnapshot,
  useUploadFile,
  useActivateSnapshot,
} from '../hooks'
import { useSnapshotStore } from '../store'
import { ConfirmDialog } from '../components/ConfirmDialog'
import type { Snapshot } from '../types'
import { extractErrorMessage } from '../types/errors'

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

  /**
   * Global Zustand state for active snapshot tracking
   * Synchronized across components to maintain consistent snapshot selection
   */
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)
  const setCurrentSnapshotName = useSnapshotStore((state) => state.setCurrentSnapshotName)

  /**
   * React Query data fetching hooks
   * - useSnapshots: Fetches all available snapshots list
   * - useSnapshotFiles: Fetches file list for selected snapshot (conditional query)
   */
  const { data: snapshots, isLoading: loadingSnapshots } = useSnapshots()
  const { data: files } = useSnapshotFiles(selectedSnapshot || '', !!selectedSnapshot)

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
  const activateMutation = useActivateSnapshot()

  const selectedSnapshotDetails = useMemo(
    () => snapshots?.find((snapshot) => snapshot.name === selectedSnapshot) ?? null,
    [selectedSnapshot, snapshots]
  )

  const groupedSnapshots = useMemo(() => {
    const groups = new Map<string, Snapshot[]>()

    for (const snapshot of snapshots ?? []) {
      const key = snapshot.folder_name?.trim() || '__ungrouped__'
      const existing = groups.get(key) ?? []
      existing.push(snapshot)
      groups.set(key, existing)
    }

    return Array.from(groups.entries())
      .sort(([left], [right]) => {
        if (left === '__ungrouped__') return 1
        if (right === '__ungrouped__') return -1
        return left.localeCompare(right)
      })
      .map(([groupKey, groupSnapshots]) => ({
        key: groupKey,
        label: groupKey === '__ungrouped__' ? t('snapshots.ungroupedFolder') : groupKey,
        snapshots: groupSnapshots,
      }))
  }, [snapshots, t])

  const getFolderDisplayName = useCallback(
    (folderName?: string | null) => folderName || t('snapshots.ungroupedFolder'),
    [t]
  )

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

      setUploadError('')
      Array.from(files).forEach((file) => {
        uploadMutation.mutate(
          {
            name: selectedSnapshot,
            file,
          },
          {
            onError: (error: unknown) => {
              setUploadError((currentError) => (
                currentError || extractErrorMessage(error, `Failed to upload file '${file.name}'`)
              ))
            },
          }
        )
      })
    },
    [selectedSnapshot, uploadMutation]
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

  /**
   * Handle snapshot selection and synchronize editable folder state
   */
  const handleSnapshotSelection = useCallback(
    (snapshot: Snapshot) => {
      setSelectedSnapshot(snapshot.name)
      setFolderDraft(snapshot.folder_name || '')
      setFolderValidationError('')

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
  const isFolderDirty = currentFolderValue !== (folderDraft.trim() || '')

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
                {groupedSnapshots.map((group) => (
                  <section key={group.key} className="space-y-2" aria-label={group.label}>
                    <div className="flex items-center gap-2 px-1">
                      <FolderOpen className="w-4 h-4 text-gray-500" aria-hidden="true" />
                      <h3 className="text-sm font-semibold text-gray-700">{group.label}</h3>
                    </div>
                    {group.snapshots.map((snapshot: Snapshot) => (
                      <div
                        key={snapshot.name}
                        role="button"
                        className={`p-4 rounded-lg border-2 cursor-pointer transition-colors focus-within:ring-2 focus-within:ring-primary-600 ${
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
                  </section>
                ))}
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
                    <input
                      id="snapshot-folder-input"
                      type="text"
                      value={folderDraft}
                      onChange={(e) => {
                        setFolderDraft(e.target.value)
                        setFolderValidationError('')
                      }}
                      placeholder={t('snapshots.folderPlaceholder')}
                      className={`w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 transition-colors ${
                        folderValidationError
                          ? 'border-red-500 focus:ring-red-500 bg-red-50'
                          : 'border-gray-300 focus:ring-primary-600'
                      }`}
                    />
                    <p className="mt-2 text-xs text-gray-600">{t('snapshots.folderHelp')}</p>
                    {folderValidationError && (
                      <p className="mt-2 text-sm text-red-600 font-medium" role="alert">
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
                <div className="bg-white rounded-lg shadow">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 uppercase tracking-wider">
                          {t('snapshots.table.filename')}
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
                      {files.map((file) => (
                        <tr key={file.name} className="hover:bg-gray-50">
                          <td className="px-6 py-4 whitespace-nowrap text-sm font-semibold text-gray-900">
                            {file.name}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-800 font-medium">
                            {formatBytes(file.size_bytes)}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-700 font-medium">
                            {new Date(file.modified_at).toLocaleString()}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="text-center py-12 text-gray-700">
                  <p className="font-semibold text-base">{t('snapshots.noFiles')}</p>
                  <p className="text-sm mt-2 text-gray-700">{t('snapshots.uploadToStart')}</p>
                </div>
              )}
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
                <input
                  id="snapshot-folder-create-input"
                  type="text"
                  value={newSnapshotFolder}
                  onChange={(e) => setNewSnapshotFolder(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleCreate()}
                  placeholder={t('snapshots.folderPlaceholder')}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-600 transition-colors"
                />
                <p className="mt-2 text-xs text-gray-600">{t('snapshots.folderHelp')}</p>
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
    </div>
  )
}
