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
