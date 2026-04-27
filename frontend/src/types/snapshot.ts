/**
 * Snapshot management type definitions
 * Snapshot metadata, files, creation requests, user management, and security logs
 */
export interface Snapshot {
  name: string
  file_count: number
  created_at: string
  size_bytes: number
  folder_name?: string | null
  owner_username?: string | null
  legacy_unowned?: boolean
}

export interface SnapshotFile {
  name: string
  size_bytes: number
  modified_at: string
  configuration_format_override?: string | null
  unsupported_configuration_format_override?: string | null
  format_override_supported?: boolean
  format_override_error?: string | null
}

export interface CreateSnapshotRequest {
  name: string
  folder_name?: string | null
}

export interface ActivateSnapshotRequest {
  name: string
}

export interface UpdateSnapshotRequest {
  folder_name: string | null
}

export interface UploadFileRequest {
  snapshot_name: string
  file: File
}

export interface UpdateSnapshotFileFormatRequest {
  configuration_format_override: string | null
}

export interface SnapshotFileMutationResponse extends SnapshotFile {
  requires_reinitialize?: boolean
}

export interface DeleteSnapshotFileResponse {
  name: string
  requires_reinitialize: boolean
}

export interface SnapshotArtifactFieldDefinition {
  name: string
  label: string
  required: boolean
  placeholder?: string
}

export interface SnapshotArtifactMutationPolicy {
  metadata_edit: 'allowed' | 'restricted' | 'none'
  content_replace: 'allowed' | 'restricted' | 'none'
  safe_relocate: 'allowed' | 'restricted' | 'none'
  type_change: 'allowed' | 'replace_required' | 'forbidden'
  active_snapshot_effect: 'no_reload' | 'requires_reactivate' | 'requires_full_reinitialize'
  preview_required: boolean
  validation_required: boolean
  rollback_required: boolean
}

export interface SnapshotArtifactTypeDefinition {
  id: string
  label: string
  category: string
  description: string
  content_kind: 'text' | 'json' | 'mixed'
  placement: string
  fields: SnapshotArtifactFieldDefinition[]
  allowed_extensions: string[]
  allowed_suffixes: string[]
  fixed_destination?: string | null
  mutation_policy: SnapshotArtifactMutationPolicy
}

export interface SnapshotArtifactRecord {
  artifact_id: string
  artifact_type: string
  label: string
  category: string
  logical_name: string
  relative_path: string
  size_bytes: number
  modified_at: string
  metadata: Record<string, string | null | undefined>
  mutation_policy: SnapshotArtifactMutationPolicy
  warnings: string[]
  requires_reinitialize?: boolean
}

export interface SnapshotArtifactTree {
  snapshot_name: string
  artifacts: SnapshotArtifactRecord[]
  summary: Record<string, number>
}

export interface SnapshotArtifactPreviewRequest {
  operation: 'upload' | 'replace' | 'delete' | 'safe_relocate' | 'metadata_update'
  artifact_type?: string
  artifact_id?: string
  filename?: string
  metadata?: Record<string, string>
}

export interface SnapshotArtifactPreview {
  artifact_type: string
  operation: string
  current_destination?: string | null
  next_destination: string
  destination_exists: boolean
  requires_reinitialize: boolean
  warnings: string[]
  preview_token: string
}

export interface SnapshotArtifactValidationResult {
  status: 'passed' | 'failed'
  artifact_count: number
  errors: string[]
  warnings: string[]
}

export interface UploadSnapshotArtifactRequest {
  name: string
  artifactType: string
  file: File
  metadata: Record<string, string>
  previewToken: string
}

export interface UpdateSnapshotArtifactRequest {
  name: string
  artifactId: string
  artifactType?: string
  filename?: string
  metadata?: Record<string, string>
  previewToken: string
}

export interface ReplaceSnapshotArtifactContentRequest {
  name: string
  artifactId: string
  file: File
  previewToken: string
}

export interface DeleteSnapshotArtifactResponse {
  artifact_id: string
  artifact_type: string
  relative_path: string
  requires_reinitialize: boolean
}
