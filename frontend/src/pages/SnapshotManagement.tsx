/**
 * Snapshot CRUD management page
 * - Create, delete, upload configuration files, and activate snapshots for Batfish analysis
 * - Drag-and-drop file upload with progress tracking and validation
 * - Form validation and React Query mutations for optimistic UI updates
 * - Zustand store integration for current snapshot state synchronization
 * - Handles multiple file uploads and snapshot lifecycle management
 */
import { useState, useCallback } from 'react'
import { Link } from 'react-router-dom'
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
  useUploadFile,
  useActivateSnapshot,
} from '../hooks'
import { useSnapshotStore } from '../store'
import type { Snapshot } from '../types'

export function SnapshotManagement() {
  const [selectedSnapshot, setSelectedSnapshot] = useState<string | null>(null)
  const [showCreateDialog, setShowCreateDialog] = useState(false)
  const [newSnapshotName, setNewSnapshotName] = useState('')
  const [dragOver, setDragOver] = useState(false)
  const [validationError, setValidationError] = useState('')

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
  const uploadMutation = useUploadFile()
  const activateMutation = useActivateSnapshot()

  /**
   * Handle snapshot creation with validation
   * Validates name (min 3 chars, alphanumeric+underscore+hyphen only)
   * On success: closes dialog, resets form, and selects new snapshot
   */
  const handleCreate = useCallback(() => {
    const trimmedName = newSnapshotName.trim()

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
      { name: trimmedName },
      {
        onSuccess: (snapshot) => {
          setShowCreateDialog(false)
          setNewSnapshotName('')
          setValidationError('')
          setSelectedSnapshot(snapshot.name)
        },
        onError: (error: any) => {
          setValidationError(error.message || 'Failed to create snapshot')
        },
      }
    )
  }, [newSnapshotName, createMutation])

  /**
   * Handle snapshot deletion with confirmation
   * Updates selected snapshot and current snapshot state if deleted snapshot was active
   */
  const handleDelete = useCallback(
    (name: string) => {
      if (!confirm(`Delete snapshot "${name}"?`)) return

      deleteMutation.mutate(name, {
        onSuccess: () => {
          if (selectedSnapshot === name) {
            setSelectedSnapshot(null)
          }
          if (currentSnapshotName === name) {
            setCurrentSnapshotName(null)
          }
        },
      })
    },
    [deleteMutation, selectedSnapshot, currentSnapshotName, setCurrentSnapshotName]
  )

  /**
   * Handle file upload to selected snapshot
   * Processes multiple files concurrently via React Query mutation
   */
  const handleFileUpload = useCallback(
    (files: FileList | null) => {
      if (!files || !selectedSnapshot) return

      Array.from(files).forEach((file) => {
        uploadMutation.mutate({
          name: selectedSnapshot,
          file,
        })
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

  return (
    <div className="flex flex-col h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b border-gray-200 px-6 py-4" role="banner">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Link
              to="/"
              className="p-2 hover:bg-gray-100 rounded-lg transition-colors focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-2"
              aria-label="Back to topology view"
            >
              <ArrowLeft className="w-5 h-5" aria-hidden="true" />
              <span className="sr-only">Back to Topology</span>
            </Link>
            <h1 className="text-2xl font-bold text-gray-900">Snapshot Management</h1>
          </div>
          <div className="flex items-center gap-3">
            <Link
              to="/snapshots/compare"
              className="flex items-center gap-2 px-4 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 transition-colors font-medium shadow-sm hover:shadow-md focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-2"
              aria-label="Compare snapshots"
            >
              <GitCompare className="w-4 h-4" aria-hidden="true" />
              Compare Snapshots
            </Link>
            <button
              onClick={() => setShowCreateDialog(true)}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-medium shadow-sm hover:shadow-md focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-2"
              aria-label="Create new snapshot"
            >
              <Plus className="w-4 h-4" aria-hidden="true" />
              New Snapshot
            </button>
          </div>
        </div>
      </header>

      {/* Main content */}
      <div className="flex-1 flex overflow-hidden">
        {/* Snapshots list */}
        <nav className="w-96 bg-white border-r border-gray-200 overflow-y-auto" aria-label="Snapshots list">
          <div className="p-4">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">Snapshots</h2>

            {loadingSnapshots ? (
              <div className="text-center py-8 text-gray-700 font-medium" role="status" aria-live="polite">
                <span className="sr-only">Loading snapshots...</span>
                Loading...
              </div>
            ) : !snapshots || snapshots.length === 0 ? (
              <div className="text-center py-8 text-gray-700">
                <FolderOpen className="w-12 h-12 mx-auto mb-3 text-gray-500" aria-hidden="true" />
                <p className="font-semibold text-base">No snapshots yet</p>
                <p className="text-sm mt-2 text-gray-700">Create one to get started</p>
              </div>
            ) : (
              <div className="space-y-2" role="list" aria-label="Available snapshots">
                {snapshots.map((snapshot: Snapshot) => (
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
                    onClick={() => {
                      setSelectedSnapshot(snapshot.name)
                      if (currentSnapshotName !== snapshot.name) {
                        handleActivate(snapshot.name)
                      }
                    }}
                    tabIndex={0}
                    aria-pressed={selectedSnapshot === snapshot.name}
                    aria-label={`Snapshot ${snapshot.name} with ${snapshot.file_count} files${
                      currentSnapshotName === snapshot.name
                        ? ' - currently active'
                        : activateMutation.isPending && activateMutation.variables === snapshot.name
                        ? ' - activating...'
                        : ''
                    }. Click to activate and view files`}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault()
                        setSelectedSnapshot(snapshot.name)
                        if (currentSnapshotName !== snapshot.name) {
                          handleActivate(snapshot.name)
                        }
                      }
                    }}
                  >
                    <div className="flex items-start justify-between mb-2">
                      <h3 className="font-semibold text-gray-900">{snapshot.name}</h3>
                      {currentSnapshotName === snapshot.name ? (
                        <CheckCircle className="w-5 h-5 text-green-600 flex-shrink-0" aria-hidden="true" />
                      ) : activateMutation.isPending && activateMutation.variables === snapshot.name ? (
                        <Loader2 className="w-5 h-5 text-blue-600 flex-shrink-0 animate-spin" aria-hidden="true" />
                      ) : null}
                    </div>
                    <div className="text-sm text-gray-800 space-y-1 font-medium">
                      <p>{snapshot.file_count} files</p>
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
            )}
          </div>
        </nav>

        {/* File management */}
        <div className="flex-1 overflow-y-auto p-6">
          {selectedSnapshot ? (
            <>
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-xl font-semibold text-gray-900">
                  Files in {selectedSnapshot}
                </h2>
                <Link
                  to={`/snapshots/${selectedSnapshot}/layer1-topology`}
                  className="inline-flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
                >
                  <Cable className="w-4 h-4" />
                  Edit Layer 1 Topology
                </Link>
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
                  Drop configuration files here
                </p>
                <p className="text-sm text-gray-700 mb-4 font-medium">or</p>
                <label className="inline-flex items-center gap-2 px-4 py-2 bg-white border border-gray-300 rounded-lg cursor-pointer hover:bg-gray-50 hover:border-gray-400 transition-colors font-medium text-gray-800 focus-within:ring-2 focus-within:ring-primary-600">
                  <Upload className="w-4 h-4" aria-hidden="true" />
                  Choose Files
                  <input
                    type="file"
                    multiple
                    accept=".cfg,.conf,.txt"
                    className="hidden"
                    onChange={(e) => handleFileUpload(e.target.files)}
                    aria-label="Choose configuration files to upload"
                    aria-describedby="upload-instructions"
                  />
                </label>
                <p id="upload-instructions" className="text-xs text-gray-700 mt-3 font-medium">
                  Supported: .cfg, .conf, .txt (max 10MB)
                </p>
                {uploadMutation.isPending && (
                  <div role="status" aria-live="polite" className="mt-4">
                    <span className="text-sm text-blue-600">Uploading files...</span>
                  </div>
                )}
              </div>

              {/* Files list */}
              {files && files.length > 0 ? (
                <div className="bg-white rounded-lg shadow">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 uppercase tracking-wider">
                          Filename
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 uppercase tracking-wider">
                          Size
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 uppercase tracking-wider">
                          Modified
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
                  <p className="font-semibold text-base">No files uploaded yet</p>
                  <p className="text-sm mt-2 text-gray-700">Upload configuration files to get started</p>
                </div>
              )}
            </>
          ) : (
            <div className="flex items-center justify-center h-full text-gray-700">
              <div className="text-center">
                <FolderOpen className="w-16 h-16 mx-auto mb-4 text-gray-500" />
                <p className="text-lg font-semibold">Select a snapshot to manage files</p>
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
          onClick={() => setShowCreateDialog(false)}
        >
          <div
            className="bg-white rounded-lg shadow-xl p-6 w-full max-w-md"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between mb-4">
              <h3 id="create-dialog-title" className="text-lg font-semibold text-gray-900">
                Create New Snapshot
              </h3>
              <button
                onClick={() => setShowCreateDialog(false)}
                className="p-1 hover:bg-gray-100 rounded focus:outline-none focus:ring-2 focus:ring-primary-600"
                aria-label="Close dialog"
              >
                <X className="w-5 h-5" aria-hidden="true" />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label htmlFor="snapshot-name-input" className="block text-sm font-medium text-gray-800 mb-1">
                  Snapshot Name
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

              <div className="flex gap-3 justify-end">
                <button
                  onClick={() => {
                    setShowCreateDialog(false)
                    setValidationError('')
                    setNewSnapshotName('')
                  }}
                  className="px-4 py-2 text-gray-800 hover:bg-gray-100 rounded-lg transition-colors font-medium focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-1"
                >
                  Cancel
                </button>
                <button
                  onClick={handleCreate}
                  disabled={createMutation.isPending}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors font-medium focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-1"
                  aria-busy={createMutation.isPending}
                >
                  {createMutation.isPending ? 'Creating...' : 'Create'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}