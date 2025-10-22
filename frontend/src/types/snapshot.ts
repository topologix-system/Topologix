/**
 * Snapshot management type definitions
 * Snapshot metadata, files, creation requests, user management, and security logs
 */
export interface Snapshot {
  name: string
  path: string
  file_count: number
  created_at: string
  size_bytes: number
}

export interface SnapshotFile {
  name: string
  size_bytes: number
  modified_at: string
}

export interface CreateSnapshotRequest {
  name: string
}

export interface ActivateSnapshotRequest {
  name: string
}

export interface UploadFileRequest {
  snapshot_name: string
  file: File
}