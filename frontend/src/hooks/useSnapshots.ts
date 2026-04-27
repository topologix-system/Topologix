/**
 * React Query hooks for snapshot management
 * Handles snapshot listing, creation, deletion, activation, and file management
 */
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { snapshotAPI } from '../services/api'
import type {
  CreateSnapshotRequest,
  ReplaceSnapshotArtifactContentRequest,
  SnapshotArtifactPreviewRequest,
  UpdateSnapshotArtifactRequest,
  UpdateSnapshotRequest,
  UploadSnapshotArtifactRequest,
} from '../types'

/**
 * Query key factory for snapshot-related React Query caches
 * Hierarchical structure with list and per-snapshot file queries
 */
export const snapshotKeys = {
  all: ['snapshots'] as const,
  list: () => [...snapshotKeys.all, 'list'] as const,
  files: (name: string) => [...snapshotKeys.all, name, 'files'] as const,
  artifactTypes: (name: string) => [...snapshotKeys.all, name, 'artifact-types'] as const,
  artifactTree: (name: string) => [...snapshotKeys.all, name, 'artifact-tree'] as const,
}

/**
 * Query all available snapshots
 * Returns snapshot list with names, file counts, sizes, and creation dates
 * Used in SnapshotManagement page and Header dropdown
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useSnapshots(enabled = true) {
  return useQuery({
    queryKey: snapshotKeys.list(),
    queryFn: () => snapshotAPI.list(),
    enabled,
    staleTime: 30000, // 30 seconds
  })
}

/**
 * Query configuration files within specific snapshot
 * Returns file list with names, sizes, and modification dates
 * Only fetches when snapshot name provided
 * @param name - Snapshot name to query files for
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useSnapshotFiles(name: string, enabled = true) {
  return useQuery({
    queryKey: snapshotKeys.files(name),
    queryFn: () => snapshotAPI.getFiles(name),
    enabled: enabled && !!name,
    staleTime: 10000, // 10 seconds
  })
}

/**
 * Query typed Batfish artifact definitions available for a snapshot.
 */
export function useSnapshotArtifactTypes(name: string, enabled = true) {
  return useQuery({
    queryKey: snapshotKeys.artifactTypes(name),
    queryFn: () => snapshotAPI.getArtifactTypes(name),
    enabled: enabled && !!name,
    staleTime: 60000,
  })
}

/**
 * Query recognized typed Batfish artifacts within a snapshot.
 */
export function useSnapshotArtifactTree(name: string, enabled = true) {
  return useQuery({
    queryKey: snapshotKeys.artifactTree(name),
    queryFn: () => snapshotAPI.getArtifactTree(name),
    enabled: enabled && !!name,
    staleTime: 10000,
  })
}

/**
 * Mutation to create new empty snapshot
 * Creates snapshot directory and invalidates snapshot list
 * Used in SnapshotManagement page create dialog
 */
export function useCreateSnapshot() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (request: CreateSnapshotRequest) => snapshotAPI.create(request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: snapshotKeys.list() })
    },
  })
}

/**
 * Mutation to delete snapshot and all its files
 * Removes snapshot from filesystem and invalidates snapshot list
 * Used in SnapshotManagement page with confirmation dialog
 */
export function useDeleteSnapshot() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (name: string) => snapshotAPI.delete(name),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: snapshotKeys.list() })
    },
  })
}

/**
 * Mutation to update snapshot metadata such as folder classification
 * Invalidates snapshot list so grouping stays in sync across the UI
 */
export function useUpdateSnapshot() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ name, request }: { name: string; request: UpdateSnapshotRequest }) =>
      snapshotAPI.update(name, request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: snapshotKeys.list() })
    },
  })
}

/**
 * Mutation to upload configuration file to snapshot
 * Accepts network device config and log files (.cfg, .conf, .txt, .log)
 * Invalidates both file list and snapshot list (file count changed)
 * Used in SnapshotManagement page drag-and-drop and file picker
 */
export function useUploadFile() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ name, file }: { name: string; file: File }) =>
      snapshotAPI.uploadFile(name, file),
    onSuccess: (_, variables) => {
      // Invalidate files list for this snapshot
      queryClient.invalidateQueries({ queryKey: snapshotKeys.files(variables.name) })
      // Also invalidate snapshots list (file count changed)
      queryClient.invalidateQueries({ queryKey: snapshotKeys.list() })
    },
  })
}

/**
 * Mutation to update a file's Batfish configuration format override.
 * Invalidates file metadata and snapshot list because the file content timestamp/size can change.
 */
export function useUpdateSnapshotFileFormat() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({
      name,
      filename,
      configurationFormatOverride,
    }: {
      name: string
      filename: string
      configurationFormatOverride: string | null
    }) => snapshotAPI.updateFileFormat(name, filename, configurationFormatOverride),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: snapshotKeys.files(variables.name) })
      queryClient.invalidateQueries({ queryKey: snapshotKeys.list() })
    },
  })
}

/**
 * Mutation to delete one uploaded snapshot file.
 * Invalidates file metadata and snapshot list because file count and size can change.
 */
export function useDeleteSnapshotFile() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ name, filename }: { name: string; filename: string }) =>
      snapshotAPI.deleteFile(name, filename),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: snapshotKeys.files(variables.name) })
      queryClient.invalidateQueries({ queryKey: snapshotKeys.list() })
    },
  })
}

/**
 * Preview an artifact mutation before writing files.
 */
export function usePreviewSnapshotArtifactChange() {
  return useMutation({
    mutationFn: ({ name, request }: { name: string; request: SnapshotArtifactPreviewRequest }) =>
      snapshotAPI.previewArtifactChange(name, request),
  })
}

/**
 * Upload a typed Batfish artifact and refresh snapshot views.
 */
export function useUploadSnapshotArtifact() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (request: UploadSnapshotArtifactRequest) => snapshotAPI.uploadArtifact(request),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: snapshotKeys.artifactTree(variables.name) })
      queryClient.invalidateQueries({ queryKey: snapshotKeys.files(variables.name) })
      queryClient.invalidateQueries({ queryKey: snapshotKeys.list() })
    },
  })
}

/**
 * Relocate or update same-type artifact metadata.
 */
export function useUpdateSnapshotArtifact() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (request: UpdateSnapshotArtifactRequest) => snapshotAPI.updateArtifact(request),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: snapshotKeys.artifactTree(variables.name) })
      queryClient.invalidateQueries({ queryKey: snapshotKeys.files(variables.name) })
      queryClient.invalidateQueries({ queryKey: snapshotKeys.list() })
    },
  })
}

/**
 * Replace one artifact's content without changing its destination.
 */
export function useReplaceSnapshotArtifactContent() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (request: ReplaceSnapshotArtifactContentRequest) =>
      snapshotAPI.replaceArtifactContent(request),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: snapshotKeys.artifactTree(variables.name) })
      queryClient.invalidateQueries({ queryKey: snapshotKeys.files(variables.name) })
      queryClient.invalidateQueries({ queryKey: snapshotKeys.list() })
    },
  })
}

/**
 * Delete one typed artifact file.
 */
export function useDeleteSnapshotArtifact() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ name, artifactId, previewToken }: { name: string; artifactId: string; previewToken: string }) =>
      snapshotAPI.deleteArtifact(name, artifactId, previewToken),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: snapshotKeys.artifactTree(variables.name) })
      queryClient.invalidateQueries({ queryKey: snapshotKeys.files(variables.name) })
      queryClient.invalidateQueries({ queryKey: snapshotKeys.list() })
    },
  })
}

/**
 * Validate artifact layout and lightweight schema expectations.
 */
export function useValidateSnapshotArtifacts() {
  return useMutation({
    mutationFn: (name: string) => snapshotAPI.validateArtifacts(name),
  })
}

/**
 * Mutation to activate snapshot for Batfish analysis
 * Initializes Batfish with snapshot and refetches all network data
 * Uses refetchQueries (not invalidateQueries) for immediate data refresh
 * Critical mutation that triggers full topology reload
 * Used in Header dropdown and SnapshotManagement page
 */
export function useActivateSnapshot() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (name: string) => snapshotAPI.activate(name),
    onSuccess: () => {
      // Refetch ALL Batfish-related queries immediately
      // refetchQueries() provides guaranteed immediate refetch (vs invalidateQueries)
      // This ensures data updates immediately when switching snapshots
      queryClient.refetchQueries({ queryKey: ['network'] })
      queryClient.refetchQueries({ queryKey: ['ospf'] })
      queryClient.refetchQueries({ queryKey: ['edges'] })
      queryClient.refetchQueries({ queryKey: ['config'] })
      queryClient.refetchQueries({ queryKey: ['validation'] })
      queryClient.refetchQueries({ queryKey: ['topology'] })
      queryClient.refetchQueries({ queryKey: ['protocols'] })
      queryClient.refetchQueries({ queryKey: ['ha'] })
      queryClient.refetchQueries({ queryKey: ['advanced'] })
      queryClient.refetchQueries({ queryKey: ['analysis'] })
      queryClient.refetchQueries({ queryKey: ['bgp'] })
      queryClient.refetchQueries({ queryKey: ['snmp-security'] })
    },
  })
}
