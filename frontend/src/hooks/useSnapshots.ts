/**
 * React Query hooks for snapshot management
 * Handles snapshot listing, creation, deletion, activation, and file management
 */
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { snapshotAPI, snapshotMigrationAPI } from '../services/api'
import { validationKeys } from './useValidation'
import { getClientGeneration, refetchVersionState, settleIfStaleActivation } from './useSnapshotVersions'
import { useSnapshotStore } from '../store'
import type {
  AssignSnapshotOwnerRequest,
  CreateSnapshotRequest,
  NetworkInitializeResponse,
  ReplaceSnapshotArtifactContentRequest,
  SnapshotArtifactPreviewRequest,
  UpdateConfigFileContentRequest,
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
  fileContent: (name: string, filename: string) =>
    [...snapshotKeys.all, name, 'file-content', filename] as const,
  artifactTypes: (name: string) => [...snapshotKeys.all, name, 'artifact-types'] as const,
  artifactTree: (name: string) => [...snapshotKeys.all, name, 'artifact-tree'] as const,
  migrations: () => [...snapshotKeys.all, 'migrations'] as const,
  unownedMigrations: () => [...snapshotKeys.migrations(), 'unowned'] as const,
}

export const batfishQueryFamilies = [
  ['network'],
  ['ospf'],
  ['edges'],
  ['config'],
  ['validation'],
  ['topology'],
  ['protocols'],
  ['ha'],
  ['advanced'],
  ['analysis'],
  ['bgp'],
  ['snmp-security'],
] as const

export const configFileContentQueryOptions = {
  staleTime: Infinity,
  refetchOnReconnect: false,
  refetchOnWindowFocus: false,
} as const

/**
 * Query all available snapshots
 * Returns snapshot list with names, file counts, sizes, and creation dates
 */
export function useSnapshots(enabled = true) {
  return useQuery({
    queryKey: snapshotKeys.list(),
    queryFn: () => snapshotAPI.list(),
    enabled,
    staleTime: 30000,
  })
}

/**
 * Query configuration files within specific snapshot
 * Returns file list with names, sizes, and modification dates
 */
export function useSnapshotFiles(name: string, enabled = true) {
  return useQuery({
    queryKey: snapshotKeys.files(name),
    queryFn: () => snapshotAPI.getFiles(name),
    enabled: enabled && !!name,
    staleTime: 10000,
  })
}

/**
 * Query full text content for one config file.
 */
export function useConfigFileContent(name: string, filename: string, enabled = true) {
  const queryClient = useQueryClient()

  return useQuery({
    queryKey: snapshotKeys.fileContent(name, filename),
    queryFn: async () => {
      try {
        return await snapshotAPI.getConfigFileContent(name, filename)
      } catch (error) {
        queryClient.invalidateQueries({ queryKey: snapshotKeys.files(name) })
        throw error
      }
    },
    enabled: enabled && !!name && !!filename,
    ...configFileContentQueryOptions,
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

export function useUnownedSnapshotMigrations(enabled = true) {
  return useQuery({
    queryKey: snapshotKeys.unownedMigrations(),
    queryFn: () => snapshotMigrationAPI.listUnowned(),
    enabled,
    staleTime: 10000,
  })
}

export function useAssignSnapshotOwner() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (request: AssignSnapshotOwnerRequest) => snapshotMigrationAPI.assignOwner(request),
    onSuccess: (_, variables) => {
      if (!variables.dry_run) {
        queryClient.invalidateQueries({ queryKey: snapshotKeys.unownedMigrations() })
        queryClient.invalidateQueries({ queryKey: snapshotKeys.list() })
      }
    },
  })
}

/**
 * Mutation to create new empty snapshot
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
 */
export function useUploadFile() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ name, file }: { name: string; file: File }) =>
      snapshotAPI.uploadFile(name, file),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({
        queryKey: snapshotKeys.fileContent(variables.name, variables.file.name),
        refetchType: 'none',
      })
      queryClient.invalidateQueries({ queryKey: snapshotKeys.files(variables.name) })
      queryClient.invalidateQueries({ queryKey: snapshotKeys.list() })
      return refetchVersionState(queryClient, variables.name)
    },
  })
}

/**
 * Mutation to update a file's Batfish configuration format override.
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
      queryClient.invalidateQueries({
        queryKey: snapshotKeys.fileContent(variables.name, variables.filename),
        refetchType: 'none',
      })
      queryClient.invalidateQueries({ queryKey: snapshotKeys.files(variables.name) })
      queryClient.invalidateQueries({ queryKey: snapshotKeys.list() })
      return refetchVersionState(queryClient, variables.name)
    },
  })
}

/**
 * Mutation to update one config file's full text content.
 */
export function useUpdateConfigFileContent() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (request: UpdateConfigFileContentRequest) =>
      snapshotAPI.updateConfigFileContent(request),
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: snapshotKeys.files(variables.name) })
      queryClient.invalidateQueries({
        queryKey: snapshotKeys.fileContent(variables.name, variables.filename),
      })
      queryClient.invalidateQueries({ queryKey: snapshotKeys.list() })
      return refetchVersionState(queryClient, variables.name)
    },
    onError: (_error, variables) => {
      queryClient.invalidateQueries({
        queryKey: snapshotKeys.files(variables.name),
        refetchType: 'none',
      })
    },
  })
}

/**
 * Mutation to delete one uploaded snapshot file.
 */
export function useDeleteSnapshotFile() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ name, filename }: { name: string; filename: string }) =>
      snapshotAPI.deleteFile(name, filename),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({
        queryKey: snapshotKeys.fileContent(variables.name, variables.filename),
        refetchType: 'none',
      })
      queryClient.invalidateQueries({ queryKey: snapshotKeys.files(variables.name) })
      queryClient.invalidateQueries({ queryKey: snapshotKeys.list() })
      return refetchVersionState(queryClient, variables.name)
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
      return refetchVersionState(queryClient, variables.name)
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
      return refetchVersionState(queryClient, variables.name)
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
      return refetchVersionState(queryClient, variables.name)
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
      return refetchVersionState(queryClient, variables.name)
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

export interface ActivateSnapshotVariables {
  name: string
  ifStale?: boolean
}

/**
 * Activate a snapshot in Batfish; a forced activation that succeeds within the same session invalidates every
 * Batfish query family, an `ifStale` one leaves invalidation to settleIfStaleActivation
 */
export function useActivateSnapshot() {
  const queryClient = useQueryClient()
  const setCurrentSnapshotName = useSnapshotStore((state) => state.setCurrentSnapshotName)
  const setSnapshotActivationState = useSnapshotStore((state) => state.setSnapshotActivationState)
  const cancelBatfishQueries = () =>
    Promise.all(batfishQueryFamilies.map((queryKey) => queryClient.cancelQueries({ queryKey })))
  const invalidateBatfishQueriesWithoutRefetch = () =>
    Promise.all(
      batfishQueryFamilies.map((queryKey) =>
        queryClient.invalidateQueries({ queryKey, refetchType: 'none' })
      )
    )

  const applyParseStatus = (snapshotName: string, activationResult: NetworkInitializeResponse | undefined) => {
    queryClient.setQueryData(validationKeys.fileParseStatus(snapshotName), activationResult?.file_parse_status ?? [])
    queryClient.setQueryData(validationKeys.initIssues(snapshotName), activationResult?.init_issues ?? [])
    queryClient.setQueryData(validationKeys.parseWarnings(snapshotName), activationResult?.parse_warnings ?? [])
  }

  return useMutation({
    mutationFn: async (variables: string | ActivateSnapshotVariables) => {
      const { name: snapshotName, ifStale = false } =
        typeof variables === 'string' ? { name: variables } : variables
      const snapshotState = useSnapshotStore.getState()
      if (snapshotState.isSnapshotActivationInProgress) {
        throw new Error('Snapshot activation is already in progress.')
      }

      const generation = getClientGeneration(queryClient)
      const sessionChanged = () => generation !== getClientGeneration(queryClient)

      if (ifStale) {
        setSnapshotActivationState(true, snapshotName)
        try {
          const activationResult = await snapshotAPI.activate(snapshotName, { if_stale: true })
          if (sessionChanged()) return activationResult
          applyParseStatus(snapshotName, activationResult)
          await settleIfStaleActivation(queryClient, snapshotName, activationResult?.parsed !== false, generation)
          return activationResult
        } finally {
          setSnapshotActivationState(false)
        }
      }

      const previousSnapshotName = snapshotState.currentSnapshotName
      let backendActivated = false

      setSnapshotActivationState(true, snapshotName)

      try {
        await cancelBatfishQueries()
        setCurrentSnapshotName(null)

        const activationResult = await snapshotAPI.activate(snapshotName)
        backendActivated = true
        if (sessionChanged()) return activationResult

        await cancelBatfishQueries()
        await refetchVersionState(queryClient, snapshotName)
        await invalidateBatfishQueriesWithoutRefetch()
        if (sessionChanged()) return activationResult

        applyParseStatus(snapshotName, activationResult)
        setCurrentSnapshotName(snapshotName)

        return activationResult
      } catch (error) {
        if (!sessionChanged()) {
          setCurrentSnapshotName(backendActivated ? snapshotName : previousSnapshotName)
        }
        throw error
      } finally {
        setSnapshotActivationState(false)
      }
    },
  })
}
