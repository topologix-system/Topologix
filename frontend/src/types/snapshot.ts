/**
 * Snapshot management type definitions
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

export interface ConfigFileContentResponse {
  content: string
  sha256: string
  size_bytes: number
}

export interface UpdateConfigFileContentRequest {
  name: string
  filename: string
  content: string
  expectedSha256: string
}

export interface SnapshotFileMutationResponse extends SnapshotFile {
  requires_reinitialize?: boolean
}

export interface DeleteSnapshotFileResponse {
  name: string
  requires_reinitialize: boolean
}

export interface SnapshotOwnerMigrationCandidate extends Snapshot {
  access_scope?: string | null
}

export interface AssignSnapshotOwnerRequest {
  snapshot_name: string
  owner_user_id: number
  folder_name?: string | null
  dry_run?: boolean
}

export interface AssignSnapshotOwnerResponse extends Snapshot {
  dry_run: boolean
  owner_user_id: number
  access_scope: string
  previous_access_scope?: string | null
  previous_legacy_unowned?: boolean
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

export interface ActivateSnapshotOptions {
  if_stale?: boolean
}

export type SnapshotVersionKind = 'baseline' | 'manual' | 'external' | 'restore'

export interface VersionRef {
  version_id: string | null
  seq: number
}

export interface SnapshotVersion {
  version_id: string
  seq: number
  message: string
  kind: SnapshotVersionKind
  created_at: string
  author: string | null
  file_count: number
  total_bytes: number
  parent: VersionRef | null
  restored_from: VersionRef | null
}

export interface SnapshotVersionFile {
  path: string
  sha256: string
  size: number
}

export interface SnapshotVersionDetail extends SnapshotVersion {
  files: SnapshotVersionFile[]
}

export interface SnapshotVersionState {
  snapshot_id: string
  content_hash: string | null
  loaded_content_hash: string | null
  loaded_batfish_version: string | null
  loaded_live: boolean
  result_cache_enabled: boolean
  head: SnapshotVersion | null
  uncommitted: boolean
  pending_external: boolean
  external_settling: boolean
  restored_from: VersionRef | null
}

export type VersioningUnavailableReason = 'database' | 'namespace' | 'storage' | 'sidecar' | 'missing_objects'

export type SnapshotVersionErrorCode =
  | 'version_conflict'
  | 'version_unchanged'
  | 'version_not_found'
  | 'namespace_not_found'
  | 'snapshot_not_found'
  | 'restore_failed'
  | 'versioning_unavailable'

export interface VersionListParams {
  limit?: number
  offset?: number
}

export interface VersionListResponse {
  items: SnapshotVersion[]
  total: number
}

export interface CommitVersionRequest {
  message: string
  expected_head?: string | null
}

export type CommitVersionResponse = SnapshotVersion

export interface RestoreVersionRequest {
  expected_working_hash?: string
}

export interface RestoreVersionResponse {
  requires_reinitialize: boolean
  restored_from: VersionRef
}

export type VersionDiffStatus = 'added' | 'removed' | 'modified' | 'unchanged'

export interface VersionDiffSummary {
  path: string
  status: VersionDiffStatus
  size: number | null
  against_size: number | null
}

export interface VersionDiffResponse {
  from: string
  against: string
  files: VersionDiffSummary[]
  working_content_hash?: string
}

export interface VersionDiffLine {
  type: ' ' | '+' | '-'
  text: string
}

export interface VersionDiffHunk {
  old_start: number
  old_lines: number
  new_start: number
  new_lines: number
  lines: VersionDiffLine[]
}

export interface VersionFileDiff {
  path: string
  binary: boolean
  too_large: boolean
  truncated: boolean
  hunks: VersionDiffHunk[]
}

export type VersionDeleteMode = 'all' | 'oldest' | 'newest'

export interface VersionDeleteRequest {
  mode: VersionDeleteMode
  count?: number
  expected_head?: string | null
  expected_total?: number
  expected_unavailable?: VersioningUnavailableReason
}

export interface SingleVersionDeleteRequest {
  expected_head?: string | null
}

export interface VersionDeleteResponse {
  deleted: number
  head: VersionRef | null
}

export interface ClearResultCacheResponse {
  cleared: boolean
}
