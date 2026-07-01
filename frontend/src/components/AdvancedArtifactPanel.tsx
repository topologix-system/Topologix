import { useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import {
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  FileJson,
  Loader2,
  Pencil,
  RefreshCw,
  Trash2,
  Upload,
} from 'lucide-react'

import {
  useActivateSnapshot,
  useDeleteSnapshotArtifact,
  usePreviewSnapshotArtifactChange,
  useReplaceSnapshotArtifactContent,
  useSnapshotArtifactTree,
  useSnapshotArtifactTypes,
  useUploadSnapshotArtifact,
  useUpdateSnapshotArtifact,
  useValidateSnapshotArtifacts,
} from '../hooks'
import { useSnapshotStore } from '../store'
import type { SnapshotArtifactRecord, SnapshotArtifactTypeDefinition } from '../types'
import { extractErrorMessage } from '../types/errors'
import { ConfirmDialog } from './ConfirmDialog'

interface AdvancedArtifactPanelProps {
  snapshotName: string
}

const formatBytes = (bytes: number) => {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`
}

const cleanMetadata = (metadata: Record<string, string>) =>
  Object.fromEntries(
    Object.entries(metadata)
      .map(([key, value]) => [key, value.trim()])
      .filter(([, value]) => value)
  )

const buildMetadataKey = (metadata: Record<string, string>) =>
  JSON.stringify(Object.entries(cleanMetadata(metadata)).sort(([left], [right]) => left.localeCompare(right)))

const buildEditPreviewKey = (
  artifact: SnapshotArtifactRecord,
  filename: string,
  metadata: Record<string, string>
) => `${artifact.artifact_id}:${filename.trim()}:${buildMetadataKey(metadata)}`

const getAcceptValue = (definition: SnapshotArtifactTypeDefinition | undefined) => {
  if (!definition) return '.cfg,.conf,.txt,.log,.json,.yml,.iptables'
  if (definition.allowed_extensions.length > 0) {
    return definition.allowed_extensions.join(',')
  }
  if (definition.allowed_suffixes.length > 0) {
    const extensions = new Set(
      definition.allowed_suffixes
        .map((suffix) => `.${suffix.split('.').pop()}`)
        .filter((extension) => extension.length > 1)
    )
    return Array.from(extensions).join(',')
  }
  return undefined
}

export function AdvancedArtifactPanel({ snapshotName }: AdvancedArtifactPanelProps) {
  const { t } = useTranslation()
  const setCurrentSnapshotName = useSnapshotStore((state) => state.setCurrentSnapshotName)
  const [isOpen, setIsOpen] = useState(false)
  const [artifactType, setArtifactType] = useState('network_config')
  const [metadataDraft, setMetadataDraft] = useState<Record<string, string>>({})
  const [uploadFile, setUploadFile] = useState<File | null>(null)
  const [panelError, setPanelError] = useState('')
  const [panelNotice, setPanelNotice] = useState('')
  const [deleteTarget, setDeleteTarget] = useState<SnapshotArtifactRecord | null>(null)
  const [replaceTarget, setReplaceTarget] = useState<SnapshotArtifactRecord | null>(null)
  const [replaceConfirmOpen, setReplaceConfirmOpen] = useState(false)
  const [replaceFile, setReplaceFile] = useState<File | null>(null)
  const [replacePreviewToken, setReplacePreviewToken] = useState('')
  const [deletePreviewToken, setDeletePreviewToken] = useState('')
  const [editTarget, setEditTarget] = useState<SnapshotArtifactRecord | null>(null)
  const [editFilename, setEditFilename] = useState('')
  const [editDraft, setEditDraft] = useState<Record<string, string>>({})
  const [editPreviewKey, setEditPreviewKey] = useState('')
  const [editConfirmOpen, setEditConfirmOpen] = useState(false)
  const uploadInputRef = useRef<HTMLInputElement>(null)
  const replaceTargetRef = useRef<SnapshotArtifactRecord | null>(null)
  const replaceInputRef = useRef<HTMLInputElement>(null)

  const artifactTypesQuery = useSnapshotArtifactTypes(snapshotName, isOpen)
  const artifactTreeQuery = useSnapshotArtifactTree(snapshotName, isOpen)
  const previewMutation = usePreviewSnapshotArtifactChange()
  const uploadMutation = useUploadSnapshotArtifact()
  const updateMutation = useUpdateSnapshotArtifact()
  const replaceMutation = useReplaceSnapshotArtifactContent()
  const deleteMutation = useDeleteSnapshotArtifact()
  const validateMutation = useValidateSnapshotArtifacts()
  const activateMutation = useActivateSnapshot()
  const actionPreviewMutation = usePreviewSnapshotArtifactChange()
  const editPreviewMutation = usePreviewSnapshotArtifactChange()

  const artifactTypes = artifactTypesQuery.data ?? []
  const effectiveArtifactType = artifactTypes.some((definition) => definition.id === artifactType)
    ? artifactType
    : artifactTypes[0]?.id ?? artifactType
  const selectedDefinition = artifactTypes.find((definition) => definition.id === effectiveArtifactType)
  const artifactTree = artifactTreeQuery.data
  const artifacts = useMemo(() => artifactTree?.artifacts ?? [], [artifactTree?.artifacts])

  const groupedArtifacts = useMemo(() => {
    const groups = new Map<string, SnapshotArtifactRecord[]>()
    for (const artifact of artifacts) {
      const current = groups.get(artifact.artifact_type) ?? []
      current.push(artifact)
      groups.set(artifact.artifact_type, current)
    }
    return Array.from(groups.entries()).sort(([left], [right]) => left.localeCompare(right))
  }, [artifacts])

  const requiredFieldsMissing = !!selectedDefinition?.fields.some(
    (field) => field.required && !metadataDraft[field.name]?.trim()
  )
  const editDefinition = editTarget
    ? artifactTypes.find((definition) => definition.id === editTarget.artifact_type)
    : undefined
  const editRequiredFieldsMissing = !!editDefinition?.fields.some(
    (field) => field.required && !editDraft[field.name]?.trim()
  )
  const editCurrentPreviewKey = editTarget ? buildEditPreviewKey(editTarget, editFilename, editDraft) : ''
  const previewMatchesUpload =
    !!previewMutation.data &&
    previewMutation.data.artifact_type === effectiveArtifactType &&
    !previewMutation.data.destination_exists
  const previewMatchesEdit =
    !!editTarget &&
    !!editPreviewMutation.data &&
    editPreviewMutation.data.artifact_type === editTarget.artifact_type &&
    editPreviewKey === editCurrentPreviewKey
  const editDestinationConflict =
    !!editPreviewMutation.data?.destination_exists &&
    editPreviewMutation.data.current_destination !== editPreviewMutation.data.next_destination
  const isBusy =
    previewMutation.isPending ||
    uploadMutation.isPending ||
    updateMutation.isPending ||
    replaceMutation.isPending ||
    deleteMutation.isPending ||
    validateMutation.isPending ||
    activateMutation.isPending ||
    actionPreviewMutation.isPending ||
    editPreviewMutation.isPending

  const translateTypeLabel = (definition: SnapshotArtifactTypeDefinition | undefined, artifactTypeId: string) =>
    t(`snapshots.artifacts.types.${artifactTypeId}.label`, {
      defaultValue: definition?.label ?? artifactTypeId,
    })

  const translateTypeDescription = (definition: SnapshotArtifactTypeDefinition | undefined, artifactTypeId: string) =>
    t(`snapshots.artifacts.types.${artifactTypeId}.description`, {
      defaultValue: definition?.description ?? '',
    })

  const canEditArtifact = (
    artifact: SnapshotArtifactRecord,
    definition: SnapshotArtifactTypeDefinition | undefined
  ) => {
    if (!definition) return false
    if (definition?.fixed_destination) return false
    const policy = artifact.mutation_policy ?? definition?.mutation_policy
    if (!policy) return false
    return policy?.metadata_edit !== 'none' || policy?.safe_relocate !== 'none'
  }

  const resetEditState = () => {
    setEditTarget(null)
    setEditFilename('')
    setEditDraft({})
    setEditPreviewKey('')
    setEditConfirmOpen(false)
    editPreviewMutation.reset()
  }

  const resetEditPreview = () => {
    setEditPreviewKey('')
    editPreviewMutation.reset()
  }

  const maybeReactivateSnapshot = (requiresReinitialize?: boolean) => {
    if (!requiresReinitialize) return
    if (useSnapshotStore.getState().currentSnapshotName !== snapshotName) {
      setPanelNotice(t('snapshots.artifacts.requiresReactivate'))
      return
    }

    activateMutation.mutate(snapshotName, {
      onSuccess: () => {
        setCurrentSnapshotName(snapshotName)
        setPanelNotice(t('snapshots.artifacts.reactivated'))
      },
      onError: (error: unknown) => {
        setPanelError(extractErrorMessage(error, t('snapshots.artifacts.reactivateFailed')))
      },
    })
  }

  const handlePreview = () => {
    if (!uploadFile) return
    setPanelError('')
    setPanelNotice('')
    previewMutation.mutate(
      {
        name: snapshotName,
        request: {
          operation: 'upload',
          artifact_type: effectiveArtifactType,
          filename: uploadFile.name,
          metadata: cleanMetadata(metadataDraft),
        },
      },
      {
        onError: (error: unknown) => {
          setPanelError(extractErrorMessage(error, t('snapshots.artifacts.previewFailed')))
        },
      }
    )
  }

  const handleUpload = () => {
    if (!uploadFile) return
    const previewToken = previewMutation.data?.preview_token
    if (!previewMatchesUpload || !previewToken) {
      setPanelError(t('snapshots.artifacts.previewRequired'))
      return
    }
    setPanelError('')
    setPanelNotice('')
    uploadMutation.mutate(
      {
        name: snapshotName,
        artifactType: effectiveArtifactType,
        file: uploadFile,
        metadata: cleanMetadata(metadataDraft),
        previewToken,
      },
      {
        onSuccess: (artifact) => {
          if (!artifact) {
            setPanelError(t('snapshots.artifacts.uploadFailed'))
            return
          }
          setUploadFile(null)
          if (uploadInputRef.current) {
            uploadInputRef.current.value = ''
          }
          setPanelNotice(t('snapshots.artifacts.uploaded'))
          previewMutation.reset()
          maybeReactivateSnapshot(artifact.requires_reinitialize)
        },
        onError: (error: unknown) => {
          setPanelError(extractErrorMessage(error, t('snapshots.artifacts.uploadFailed')))
        },
      }
    )
  }

  const openReplaceFilePicker = (artifact: SnapshotArtifactRecord) => {
    setPanelError('')
    setPanelNotice('')
    setReplacePreviewToken('')
    setReplaceTarget(artifact)
    replaceTargetRef.current = artifact
    replaceInputRef.current?.click()
  }

  const handleReplaceFile = (file: File | undefined) => {
    const target = replaceTargetRef.current
    if (!target || !file) return
    setReplaceFile(file)
    actionPreviewMutation.mutate(
      {
        name: snapshotName,
        request: {
          operation: 'replace',
          artifact_id: target.artifact_id,
          filename: file.name,
        },
      },
      {
        onSuccess: (preview) => {
          if (!preview) {
            setPanelError(t('snapshots.artifacts.previewFailed'))
            return
          }
          setReplacePreviewToken(preview.preview_token)
          setReplaceConfirmOpen(true)
        },
        onError: (error: unknown) => {
          setPanelError(extractErrorMessage(error, t('snapshots.artifacts.previewFailed')))
          setReplaceTarget(null)
          replaceTargetRef.current = null
          setReplaceFile(null)
          setReplacePreviewToken('')
        },
      }
    )
  }

  const confirmReplaceArtifact = () => {
    const target = replaceTargetRef.current
    if (!target || !replaceFile || !replacePreviewToken) return
    replaceMutation.mutate(
      {
        name: snapshotName,
        artifactId: target.artifact_id,
        file: replaceFile,
        previewToken: replacePreviewToken,
      },
      {
        onSuccess: (artifact) => {
          if (!artifact) {
            setPanelError(t('snapshots.artifacts.replaceFailed'))
            return
          }
          setPanelNotice(t('snapshots.artifacts.replaced'))
          setReplaceTarget(null)
          replaceTargetRef.current = null
          setReplaceFile(null)
          setReplacePreviewToken('')
          setReplaceConfirmOpen(false)
          maybeReactivateSnapshot(artifact.requires_reinitialize)
        },
        onError: (error: unknown) => {
          setPanelError(extractErrorMessage(error, t('snapshots.artifacts.replaceFailed')))
          setReplaceTarget(null)
          replaceTargetRef.current = null
          setReplaceFile(null)
          setReplacePreviewToken('')
          setReplaceConfirmOpen(false)
        },
      }
    )
  }

  const confirmDeleteArtifact = () => {
    if (!deleteTarget || !deletePreviewToken) return
    deleteMutation.mutate(
      {
        name: snapshotName,
        artifactId: deleteTarget.artifact_id,
        previewToken: deletePreviewToken,
      },
      {
        onSuccess: (result) => {
          if (!result) {
            setPanelError(t('snapshots.artifacts.deleteFailed'))
            return
          }
          setPanelNotice(t('snapshots.artifacts.deleted'))
          setDeleteTarget(null)
          setDeletePreviewToken('')
          maybeReactivateSnapshot(result.requires_reinitialize)
        },
        onError: (error: unknown) => {
          setPanelError(extractErrorMessage(error, t('snapshots.artifacts.deleteFailed')))
          setDeleteTarget(null)
          setDeletePreviewToken('')
        },
      }
    )
  }

  const openDeleteConfirm = (artifact: SnapshotArtifactRecord) => {
    setPanelError('')
    setPanelNotice('')
    setDeletePreviewToken('')
    actionPreviewMutation.mutate(
      {
        name: snapshotName,
        request: {
          operation: 'delete',
          artifact_id: artifact.artifact_id,
        },
      },
      {
        onSuccess: (preview) => {
          if (!preview) {
            setPanelError(t('snapshots.artifacts.previewFailed'))
            return
          }
          setDeletePreviewToken(preview.preview_token)
          setDeleteTarget(artifact)
        },
        onError: (error: unknown) => {
          setPanelError(extractErrorMessage(error, t('snapshots.artifacts.previewFailed')))
        },
      }
    )
  }

  const openEditArtifact = (artifact: SnapshotArtifactRecord) => {
    const definition = artifactTypes.find((item) => item.id === artifact.artifact_type)
    const nextDraft: Record<string, string> = {}
    for (const field of definition?.fields ?? []) {
      const value = artifact.metadata?.[field.name]
      nextDraft[field.name] = typeof value === 'string' ? value : ''
    }
    setPanelError('')
    setPanelNotice('')
    setEditTarget(artifact)
    setEditFilename(artifact.logical_name)
    setEditDraft(nextDraft)
    setEditPreviewKey('')
    setEditConfirmOpen(false)
    editPreviewMutation.reset()
  }

  const handlePreviewEdit = () => {
    if (!editTarget) return
    const nextPreviewKey = buildEditPreviewKey(editTarget, editFilename, editDraft)
    setPanelError('')
    setPanelNotice('')
    editPreviewMutation.mutate(
      {
        name: snapshotName,
        request: {
          operation: 'metadata_update',
          artifact_id: editTarget.artifact_id,
          artifact_type: editTarget.artifact_type,
          filename: editFilename.trim(),
          metadata: cleanMetadata(editDraft),
        },
      },
      {
        onSuccess: (preview) => {
          if (!preview) {
            setPanelError(t('snapshots.artifacts.previewFailed'))
            return
          }
          setEditPreviewKey(nextPreviewKey)
        },
        onError: (error: unknown) => {
          setPanelError(extractErrorMessage(error, t('snapshots.artifacts.previewFailed')))
          setEditPreviewKey('')
        },
      }
    )
  }

  const confirmUpdateArtifact = () => {
    if (!editTarget || !previewMatchesEdit || !editPreviewMutation.data?.preview_token) return
    updateMutation.mutate(
      {
        name: snapshotName,
        artifactId: editTarget.artifact_id,
        artifactType: editTarget.artifact_type,
        filename: editFilename.trim(),
        metadata: cleanMetadata(editDraft),
        previewToken: editPreviewMutation.data.preview_token,
      },
      {
        onSuccess: (artifact) => {
          if (!artifact) {
            setPanelError(t('snapshots.artifacts.updateFailed'))
            return
          }
          setPanelNotice(t('snapshots.artifacts.updated'))
          resetEditState()
          maybeReactivateSnapshot(artifact.requires_reinitialize)
        },
        onError: (error: unknown) => {
          setPanelError(extractErrorMessage(error, t('snapshots.artifacts.updateFailed')))
          setEditConfirmOpen(false)
        },
      }
    )
  }

  const handleValidate = () => {
    setPanelError('')
    setPanelNotice('')
    validateMutation.mutate(snapshotName, {
      onError: (error: unknown) => {
        setPanelError(extractErrorMessage(error, t('snapshots.artifacts.validateFailed')))
      },
    })
  }

  return (
    <section className="mt-6 overflow-hidden rounded-lg border border-gray-200 bg-white shadow-sm">
      <button
        type="button"
        onClick={() => setIsOpen((current) => !current)}
        className="flex w-full items-center justify-between gap-3 px-4 py-4 text-left hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-inset"
        aria-expanded={isOpen}
      >
        <span className="flex min-w-0 items-center gap-3">
          <FileJson className="h-5 w-5 flex-shrink-0 text-blue-600" aria-hidden="true" />
          <span>
            <span className="block text-base font-semibold text-gray-900">
              {t('snapshots.artifacts.title')}
            </span>
            <span className="block text-sm text-gray-600">
              {t('snapshots.artifacts.summary', { count: artifacts.length })}
            </span>
          </span>
        </span>
        {isOpen ? (
          <ChevronDown className="h-5 w-5 text-gray-500" aria-hidden="true" />
        ) : (
          <ChevronRight className="h-5 w-5 text-gray-500" aria-hidden="true" />
        )}
      </button>

      {isOpen && (
        <div className="border-t border-gray-200 p-4">
          <div className="mb-4 rounded-lg border border-blue-100 bg-blue-50 px-4 py-3 text-sm text-blue-900">
            <p className="font-medium">{t('snapshots.artifacts.helpTitle')}</p>
            <p className="mt-1 text-blue-800">{t('snapshots.artifacts.helpBody')}</p>
          </div>

          {panelError && (
            <p className="mb-4 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm font-medium text-red-700" role="alert">
              {panelError}
            </p>
          )}
          {panelNotice && (
            <p className="mb-4 rounded-lg border border-green-200 bg-green-50 px-4 py-3 text-sm font-medium text-green-800" role="status">
              {panelNotice}
            </p>
          )}

          <div className="grid gap-6 xl:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
            <div className="rounded-lg border border-gray-200 p-4">
              <h3 className="text-sm font-semibold uppercase text-gray-700">
                {t('snapshots.artifacts.uploadTitle')}
              </h3>

              <div className="mt-4 space-y-4">
                <div>
                  <label htmlFor="artifact-type-select" className="block text-sm font-medium text-gray-800">
                    {t('snapshots.artifacts.typeLabel')}
                  </label>
                  <select
                    id="artifact-type-select"
                    value={effectiveArtifactType}
                    onChange={(event) => {
                      setArtifactType(event.target.value)
                      setMetadataDraft({})
                      setUploadFile(null)
                      setPanelError('')
                      setPanelNotice('')
                      previewMutation.reset()
                    }}
                    className="mt-1 w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 shadow-sm focus:border-primary-600 focus:outline-none focus:ring-2 focus:ring-primary-600"
                    disabled={artifactTypesQuery.isLoading || isBusy}
                  >
                    {artifactTypes.map((definition) => (
                      <option key={definition.id} value={definition.id}>
                        {translateTypeLabel(definition, definition.id)}
                      </option>
                    ))}
                  </select>
                  <p className="mt-2 text-xs text-gray-600">
                    {translateTypeDescription(selectedDefinition, effectiveArtifactType)}
                  </p>
                </div>

                {selectedDefinition?.fields.map((field) => (
                  <div key={field.name}>
                    <label htmlFor={`artifact-metadata-${field.name}`} className="block text-sm font-medium text-gray-800">
                      {t(`snapshots.artifacts.fields.${field.name}`, { defaultValue: field.label })}
                      {field.required && <span className="ml-1 text-red-600">*</span>}
                    </label>
                    <input
                      id={`artifact-metadata-${field.name}`}
                      type="text"
                      value={metadataDraft[field.name] ?? ''}
                      onChange={(event) => {
                        setMetadataDraft((current) => ({
                          ...current,
                          [field.name]: event.target.value,
                        }))
                        previewMutation.reset()
                      }}
                      placeholder={field.placeholder}
                      className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-900 shadow-sm focus:border-primary-600 focus:outline-none focus:ring-2 focus:ring-primary-600"
                      disabled={isBusy}
                    />
                  </div>
                ))}

                <div>
                  <label htmlFor="artifact-upload-file" className="block text-sm font-medium text-gray-800">
                    {t('snapshots.artifacts.fileLabel')}
                  </label>
                  <input
                    id="artifact-upload-file"
                    key={`${snapshotName}-${effectiveArtifactType}`}
                    ref={uploadInputRef}
                    type="file"
                    accept={getAcceptValue(selectedDefinition)}
                    onChange={(event) => {
                      setUploadFile(event.target.files?.[0] ?? null)
                      previewMutation.reset()
                    }}
                    className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-900 shadow-sm file:mr-3 file:rounded file:border-0 file:bg-gray-100 file:px-3 file:py-1.5 file:text-sm file:font-medium file:text-gray-700 hover:file:bg-gray-200 focus:outline-none focus:ring-2 focus:ring-primary-600"
                    disabled={isBusy}
                  />
                </div>

                <div className="flex flex-wrap gap-3">
                  <button
                    type="button"
                    onClick={handlePreview}
                    disabled={!uploadFile || requiredFieldsMissing || isBusy}
                    className="inline-flex items-center gap-2 rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-800 transition-colors hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    <RefreshCw className="h-4 w-4" aria-hidden="true" />
                    {t('snapshots.artifacts.preview')}
                  </button>
                  <button
                    type="button"
                    onClick={handleUpload}
                    disabled={!uploadFile || requiredFieldsMissing || !previewMatchesUpload || isBusy}
                    className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {uploadMutation.isPending ? (
                      <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                    ) : (
                      <Upload className="h-4 w-4" aria-hidden="true" />
                    )}
                    {t('snapshots.artifacts.upload')}
                  </button>
                </div>

                {previewMutation.data && (
                  <div className="rounded-lg border border-gray-200 bg-gray-50 px-4 py-3 text-sm text-gray-800">
                    <p className="font-medium">{t('snapshots.artifacts.previewDestination')}</p>
                    <p className="mt-1 break-all font-mono text-xs text-gray-700">
                      {previewMutation.data.next_destination}
                    </p>
                    {previewMutation.data.destination_exists && (
                      <p className="mt-2 flex items-center gap-2 text-yellow-700">
                        <AlertTriangle className="h-4 w-4" aria-hidden="true" />
                        {t('snapshots.artifacts.destinationExists')}
                      </p>
                    )}
                    {previewMutation.data.warnings.map((warning) => (
                      <p key={warning} className="mt-2 text-yellow-700">{warning}</p>
                    ))}
                  </div>
                )}
              </div>
            </div>

            <div className="rounded-lg border border-gray-200 p-4">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <h3 className="text-sm font-semibold uppercase text-gray-700">
                    {t('snapshots.artifacts.treeTitle')}
                  </h3>
                  <p className="mt-1 text-sm text-gray-600">
                    {t('snapshots.artifacts.treeHelp')}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={handleValidate}
                  disabled={isBusy}
                  className="inline-flex items-center justify-center gap-2 rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-800 transition-colors hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {validateMutation.isPending ? (
                    <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                  ) : (
                    <RefreshCw className="h-4 w-4" aria-hidden="true" />
                  )}
                  {t('snapshots.artifacts.validate')}
                </button>
              </div>

              {validateMutation.data && (
                <div className={`mt-4 rounded-lg border px-4 py-3 text-sm ${
                  validateMutation.data.status === 'passed'
                    ? 'border-green-200 bg-green-50 text-green-800'
                    : 'border-red-200 bg-red-50 text-red-700'
                }`}>
                  <p className="font-medium">
                    {t('snapshots.artifacts.validationStatus', {
                      status: validateMutation.data.status,
                      count: validateMutation.data.artifact_count,
                    })}
                  </p>
                  {validateMutation.data.errors.map((error) => (
                    <p key={error} className="mt-1">{error}</p>
                  ))}
                  {validateMutation.data.warnings.map((warning) => (
                    <p key={warning} className="mt-1 text-yellow-700">{warning}</p>
                  ))}
                </div>
              )}

              <input
                ref={replaceInputRef}
                type="file"
                accept=".cfg,.conf,.txt,.log,.json,.yml,.iptables"
                className="hidden"
                onChange={(event) => {
                  handleReplaceFile(event.target.files?.[0])
                  event.target.value = ''
                }}
                aria-label={t('snapshots.artifacts.replaceFile')}
              />

              <div className="mt-4 space-y-4">
                {artifactTreeQuery.isLoading ? (
                  <p className="text-sm text-gray-600">{t('common.loading')}</p>
                ) : groupedArtifacts.length === 0 ? (
                  <p className="rounded-lg border border-gray-200 bg-gray-50 px-4 py-6 text-center text-sm text-gray-600">
                    {t('snapshots.artifacts.empty')}
                  </p>
                ) : (
                  groupedArtifacts.map(([artifactTypeId, records]) => {
                    const definition = artifactTypes.find((item) => item.id === artifactTypeId)
                    return (
                      <div key={artifactTypeId} className="rounded-lg border border-gray-200">
                        <div className="border-b border-gray-200 bg-gray-50 px-4 py-2">
                          <p className="text-sm font-semibold text-gray-800">
                            {translateTypeLabel(definition, artifactTypeId)}
                            <span className="ml-2 text-xs font-medium text-gray-500">{records.length}</span>
                          </p>
                        </div>
                        <div className="divide-y divide-gray-200">
                          {records.map((artifact) => (
                            <div key={artifact.artifact_id} className="px-4 py-3">
                              <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                                <div className="min-w-0">
                                  <p className="break-all text-sm font-semibold text-gray-900">
                                    {artifact.logical_name}
                                  </p>
                                  <p className="mt-1 break-all font-mono text-xs text-gray-600">
                                    {artifact.relative_path}
                                  </p>
                                  <p className="mt-1 text-xs text-gray-500">
                                    {formatBytes(artifact.size_bytes)} / {new Date(artifact.modified_at).toLocaleString()}
                                  </p>
                                </div>
                                <div className="flex flex-wrap gap-2">
                                  {artifact.artifact_type === 'layer1_topology' && (
                                    <Link
                                      to={`/snapshots/${snapshotName}/layer1-editor`}
                                      className="inline-flex items-center rounded-md border border-green-200 px-3 py-1.5 text-xs font-medium text-green-700 hover:bg-green-50"
                                    >
                                      {t('snapshots.editLayer1')}
                                    </Link>
                                  )}
                                  {canEditArtifact(artifact, definition) && (
                                    <button
                                      type="button"
                                      onClick={() => openEditArtifact(artifact)}
                                      disabled={isBusy}
                                      className="inline-flex items-center gap-1.5 rounded-md border border-blue-200 px-3 py-1.5 text-xs font-medium text-blue-700 hover:bg-blue-50 disabled:cursor-not-allowed disabled:opacity-50"
                                      aria-label={t('snapshots.artifacts.editAria', { name: artifact.logical_name })}
                                    >
                                      <Pencil className="h-3.5 w-3.5" aria-hidden="true" />
                                      {t('snapshots.artifacts.editMetadata')}
                                    </button>
                                  )}
                                  <button
                                    type="button"
                                    onClick={() => openReplaceFilePicker(artifact)}
                                    disabled={isBusy}
                                    className="inline-flex items-center rounded-md border border-gray-300 px-3 py-1.5 text-xs font-medium text-gray-800 hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-50"
                                  >
                                    {replaceMutation.isPending && replaceTarget?.artifact_id === artifact.artifact_id
                                      ? t('snapshots.artifacts.replacing')
                                      : t('snapshots.artifacts.replaceFile')}
                                  </button>
                                  <button
                                    type="button"
                                    onClick={() => openDeleteConfirm(artifact)}
                                    disabled={isBusy}
                                    className="inline-flex h-8 w-8 items-center justify-center rounded-md border border-red-200 text-red-600 hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-50"
                                    aria-label={t('snapshots.artifacts.deleteAria', { name: artifact.logical_name })}
                                  >
                                    <Trash2 className="h-4 w-4" aria-hidden="true" />
                                  </button>
                                </div>
                              </div>
                              {editTarget?.artifact_id === artifact.artifact_id && (
                                <div className="mt-3 rounded-lg border border-blue-100 bg-blue-50/60 p-3">
                                  <h4 className="text-sm font-semibold text-blue-950">
                                    {t('snapshots.artifacts.editTitle')}
                                  </h4>
                                  <div className="mt-3 grid gap-3 md:grid-cols-2">
                                    <div>
                                      <label
                                        htmlFor={`artifact-edit-filename-${artifact.artifact_id}`}
                                        className="block text-xs font-medium text-gray-700"
                                      >
                                        {t('snapshots.artifacts.filenameLabel')}
                                      </label>
                                      <input
                                        id={`artifact-edit-filename-${artifact.artifact_id}`}
                                        type="text"
                                        value={editFilename}
                                        onChange={(event) => {
                                          setEditFilename(event.target.value)
                                          resetEditPreview()
                                        }}
                                        className="mt-1 w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 shadow-sm focus:border-primary-600 focus:outline-none focus:ring-2 focus:ring-primary-600"
                                        disabled={isBusy}
                                      />
                                    </div>
                                    {editDefinition?.fields.map((field) => (
                                      <div key={field.name}>
                                        <label
                                          htmlFor={`artifact-edit-${artifact.artifact_id}-${field.name}`}
                                          className="block text-xs font-medium text-gray-700"
                                        >
                                          {t(`snapshots.artifacts.fields.${field.name}`, { defaultValue: field.label })}
                                          {field.required && <span className="ml-1 text-red-600">*</span>}
                                        </label>
                                        <input
                                          id={`artifact-edit-${artifact.artifact_id}-${field.name}`}
                                          type="text"
                                          value={editDraft[field.name] ?? ''}
                                          onChange={(event) => {
                                            setEditDraft((current) => ({
                                              ...current,
                                              [field.name]: event.target.value,
                                            }))
                                            resetEditPreview()
                                          }}
                                          placeholder={field.placeholder}
                                          className="mt-1 w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 shadow-sm focus:border-primary-600 focus:outline-none focus:ring-2 focus:ring-primary-600"
                                          disabled={isBusy}
                                        />
                                      </div>
                                    ))}
                                  </div>

                                  {editPreviewMutation.data && (
                                    <div className="mt-3 rounded-md border border-gray-200 bg-white px-3 py-2 text-xs text-gray-700">
                                      <p className="font-medium">{t('snapshots.artifacts.previewDestination')}</p>
                                      <p className="mt-1">
                                        <span className="font-medium">{t('snapshots.artifacts.currentPath')}:</span>{' '}
                                        <span className="break-all font-mono">{editPreviewMutation.data.current_destination}</span>
                                      </p>
                                      <p className="mt-1">
                                        <span className="font-medium">{t('snapshots.artifacts.newPath')}:</span>{' '}
                                        <span className="break-all font-mono">{editPreviewMutation.data.next_destination}</span>
                                      </p>
                                      {editDestinationConflict && (
                                        <p className="mt-2 flex items-center gap-2 text-yellow-700">
                                          <AlertTriangle className="h-4 w-4" aria-hidden="true" />
                                          {t('snapshots.artifacts.destinationExists')}
                                        </p>
                                      )}
                                      {editPreviewMutation.data.warnings.map((warning) => (
                                        <p key={warning} className="mt-2 text-yellow-700">{warning}</p>
                                      ))}
                                    </div>
                                  )}

                                  <div className="mt-3 flex flex-wrap gap-2">
                                    <button
                                      type="button"
                                      onClick={handlePreviewEdit}
                                      disabled={!editFilename.trim() || editRequiredFieldsMissing || isBusy}
                                      className="inline-flex items-center gap-2 rounded-md border border-gray-300 bg-white px-3 py-1.5 text-xs font-medium text-gray-800 hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-50"
                                    >
                                      {editPreviewMutation.isPending ? (
                                        <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                                      ) : (
                                        <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
                                      )}
                                      {t('snapshots.artifacts.previewEdit')}
                                    </button>
                                    <button
                                      type="button"
                                      onClick={() => setEditConfirmOpen(true)}
                                      disabled={!previewMatchesEdit || editDestinationConflict || isBusy}
                                      className="inline-flex items-center rounded-md bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-50"
                                    >
                                      {t('snapshots.artifacts.applyEdit')}
                                    </button>
                                    <button
                                      type="button"
                                      onClick={resetEditState}
                                      disabled={isBusy}
                                      className="inline-flex items-center rounded-md border border-gray-300 bg-white px-3 py-1.5 text-xs font-medium text-gray-700 hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-50"
                                    >
                                      {t('common.cancel')}
                                    </button>
                                  </div>
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )
                  })
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      <ConfirmDialog
        isOpen={editConfirmOpen}
        title={t('snapshots.artifacts.editConfirm.title')}
        message={t('snapshots.artifacts.editConfirm.message', {
          current: editPreviewMutation.data?.current_destination ?? editTarget?.relative_path ?? '',
          next: editPreviewMutation.data?.next_destination ?? editTarget?.relative_path ?? '',
        })}
        confirmText={t('snapshots.artifacts.applyEdit')}
        cancelText={t('common.cancel')}
        onConfirm={confirmUpdateArtifact}
        onCancel={() => setEditConfirmOpen(false)}
        variant="info"
        isLoading={updateMutation.isPending}
      />

      <ConfirmDialog
        isOpen={replaceConfirmOpen}
        title={t('snapshots.artifacts.replaceConfirm.title')}
        message={t('snapshots.artifacts.replaceConfirm.message', {
          path: replaceTarget?.relative_path ?? '',
          file: replaceFile?.name ?? '',
        })}
        confirmText={t('snapshots.artifacts.replaceFile')}
        cancelText={t('common.cancel')}
        onConfirm={confirmReplaceArtifact}
        onCancel={() => {
          setReplaceConfirmOpen(false)
          setReplaceTarget(null)
          replaceTargetRef.current = null
          setReplaceFile(null)
          setReplacePreviewToken('')
        }}
        variant="warning"
        isLoading={replaceMutation.isPending}
      />

      <ConfirmDialog
        isOpen={!!deleteTarget}
        title={t('snapshots.artifacts.deleteConfirm.title')}
        message={t('snapshots.artifacts.deleteConfirm.message', {
          path: deleteTarget?.relative_path ?? '',
        })}
        confirmText={t('common.delete')}
        cancelText={t('common.cancel')}
        onConfirm={confirmDeleteArtifact}
        onCancel={() => {
          setDeleteTarget(null)
          setDeletePreviewToken('')
        }}
        variant="danger"
        isLoading={deleteMutation.isPending}
      />
    </section>
  )
}
