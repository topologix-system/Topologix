/**
 * React Query hooks and cache helpers for snapshot versioning
 */
import { useEffect } from 'react'
import {
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
  type QueryClient,
  type QueryState,
} from '@tanstack/react-query'
import { isAxiosError } from 'axios'

import { snapshotAPI } from '../services/api'
import { useSnapshotStore } from '../store/useSnapshotStore'
import type {
  RestoreVersionResponse,
  SnapshotVersionState,
  VersionDeleteRequest,
  VersioningUnavailableReason,
} from '../types'
import { logger } from '../utils/logger'
import {
  INVALIDATION_SIGNAL_KEY,
  getClientGeneration,
  getSnapshotTriggerState,
  resetSnapshotTriggerState,
} from './snapshotTriggerState'
import { batfishQueryFamilies, snapshotKeys } from './useSnapshots'
import { layer1EditorKeys } from './useLayer1Editor'

export { INVALIDATION_SIGNAL_KEY, getClientGeneration, getSnapshotTriggerState, resetSnapshotTriggerState }

export const VERSION_STATE_POLL_INTERVAL_MS = 15_000
export const LEGACY_NETWORK_STALE_TIME_MS = 5 * 60 * 1000
export const UNKNOWN_NETWORK_KEY = 'unknown'
export const VERSION_LIST_PAGE_SIZE = 50
export const WORKING_TREE = 'working'
const SUPPRESS_TOKEN_TTL_MS = 30_000
const UNKNOWN_KEY_IDENTITY = `key:${UNKNOWN_NETWORK_KEY}`
const VERSIONING_UNAVAILABLE_REASONS: readonly VersioningUnavailableReason[] = [
  'database',
  'namespace',
  'storage',
  'sidecar',
  'missing_objects',
]

const versionRoot = 'snapshot-versions'

/**
 * Query key factory for snapshot versioning caches, kept outside the Batfish query families
 */
export const snapshotVersionKeys = {
  all: [versionRoot] as const,
  snapshot: (name: string) => [versionRoot, name] as const,
  state: (name: string | null) => [versionRoot, name ?? 'no-active-snapshot', 'state'] as const,
  list: (name: string) => [versionRoot, name, 'list'] as const,
  detail: (name: string, versionId: string) => [versionRoot, name, 'detail', versionId] as const,
  diff: (name: string, versionId: string, against: string) => [versionRoot, name, 'diff', versionId, against] as const,
  fileDiff: (name: string, versionId: string, against: string, path: string) =>
    [versionRoot, name, 'file-diff', versionId, against, path] as const,
}

type QueryFamily = readonly string[]
export type NetworkRefetchType = 'active' | 'none'
export type InvalidationReason = 'edit' | 'clear'

export interface InvalidateSnapshotFamiliesOptions {
  families?: readonly QueryFamily[]
  signal?: boolean
  reason?: InvalidationReason
  networkRefetchType?: NetworkRefetchType
}

export type NetworkKeyResolution =
  | { status: 'pending' }
  | { status: 'no-data' }
  | { status: 'resolved'; keyComponent: string | null }

interface VersionStateView {
  status: 'pending' | 'success' | 'error'
  data: SnapshotVersionState | undefined
  error: unknown
}

function responseCode(error: unknown): string | undefined {
  if (!isAxiosError(error)) return undefined
  const data = error.response?.data as { code?: unknown } | undefined
  return typeof data?.code === 'string' ? data.code : undefined
}

function responseDetails(error: unknown): Record<string, unknown> | undefined {
  if (!isAxiosError(error)) return undefined
  const details = (error.response?.data as { details?: unknown } | undefined)?.details
  return details && typeof details === 'object' && !Array.isArray(details)
    ? (details as Record<string, unknown>)
    : undefined
}

export function getVersionErrorStatus(error: unknown): number | undefined {
  return isAxiosError(error) ? error.response?.status : undefined
}

export function getVersionErrorCode(error: unknown): string | undefined {
  return responseCode(error)
}

/**
 * The `details.reason` of a 503 `versioning_unavailable` answer, `unknown` for an unlisted reason, null otherwise
 */
export function getVersioningUnavailableReason(error: unknown): VersioningUnavailableReason | 'unknown' | null {
  if (getVersionErrorStatus(error) !== 503 || responseCode(error) !== 'versioning_unavailable') return null
  const reason = responseDetails(error)?.reason
  return VERSIONING_UNAVAILABLE_REASONS.find((known) => known === reason) ?? 'unknown'
}

/**
 * The path named by a restore `path_clash` 409 ('' when it names none), null for any other error
 */
export function getPathClashPath(error: unknown): string | null {
  if (getVersionErrorStatus(error) !== 409 || responseCode(error) !== 'version_conflict') return null
  const details = responseDetails(error)
  if (details?.reason !== 'path_clash') return null
  return typeof details.path === 'string' ? details.path : ''
}

export function isVersionNotFoundError(error: unknown): boolean {
  return getVersionErrorStatus(error) === 404 && responseCode(error) === 'version_not_found'
}

/**
 * A version-state error that leaves the snapshot without data: 401, 403 or 404 snapshot_not_found
 */
export function isVersionStateNoDataError(error: unknown): boolean {
  const status = getVersionErrorStatus(error)
  if (status === 401 || status === 403) return true
  return status === 404 && responseCode(error) === 'snapshot_not_found'
}

export function retryVersionState(failureCount: number, error: unknown): boolean {
  return !(isAxiosError(error) && error.response) && failureCount < 2
}

function findVersionStateQuery(queryClient: QueryClient, name: string) {
  return queryClient
    .getQueryCache()
    .find<SnapshotVersionState>({ queryKey: snapshotVersionKeys.state(name), exact: true })
}

export function refetchVersionState(queryClient: QueryClient, name: string): Promise<void> {
  return queryClient.refetchQueries({ queryKey: snapshotVersionKeys.state(name), exact: true })
}

function writeInvalidationSignal(name: string, reason: InvalidationReason) {
  try {
    localStorage.setItem(INVALIDATION_SIGNAL_KEY, JSON.stringify({ name, ts: Date.now(), reason }))
  } catch {
    logger.warn('[SnapshotVersions] Cross-window invalidation signal could not be stored')
  }
}

/**
 * Invalidate the Batfish query families of one snapshot (keys scoped to [family, name]) and, unless `signal` is false,
 * write the cross-window signal; networkRefetchType applies to the network family only
 */
export function invalidateSnapshotFamilies(
  queryClient: QueryClient,
  name: string,
  {
    families = batfishQueryFamilies,
    signal = true,
    reason = 'edit',
    networkRefetchType = 'active',
  }: InvalidateSnapshotFamiliesOptions = {}
): Promise<void> {
  const invalidations = families.map((family) =>
    queryClient.invalidateQueries({
      queryKey: [...family, name],
      refetchType: family[0] === 'network' ? networkRefetchType : 'active',
    })
  )
  if (signal) {
    writeInvalidationSignal(name, reason)
  }
  return Promise.all(invalidations).then(() => undefined)
}

function invalidateWorkingDiffs(queryClient: QueryClient, name: string): Promise<void> {
  return queryClient.invalidateQueries({
    predicate: (query) => {
      const key = query.queryKey
      return (
        key[0] === versionRoot &&
        key[1] === name &&
        (key[2] === 'diff' || key[2] === 'file-diff') &&
        key[4] === WORKING_TREE
      )
    },
  })
}

/**
 * Resolve the key component of the hash-keyed network queries from a version-state result, updating the
 * snapshot's trigger state
 */
export function resolveNetworkKey(
  queryClient: QueryClient,
  name: string,
  view: VersionStateView
): NetworkKeyResolution {
  const triggers = getSnapshotTriggerState(queryClient, name)

  if (view.status === 'success' && view.data) {
    const data = view.data
    const wasNoData = triggers.noData
    triggers.noData = false

    let keyComponent: string | null
    if (data.result_cache_enabled === false) {
      if (triggers.retainedKey === undefined) {
        triggers.retainedKey =
          triggers.lastTrueModeHash !== undefined ? triggers.lastTrueModeHash : data.content_hash
      }
      keyComponent = triggers.retainedKey
    } else {
      triggers.retainedKey = undefined
      triggers.lastTrueModeHash = data.content_hash
      keyComponent = data.content_hash
    }

    if (wasNoData) {
      triggers.firstKeyAfterClear = keyComponent
    } else if (triggers.firstKeyAfterClear !== undefined && triggers.firstKeyAfterClear !== keyComponent) {
      triggers.firstKeyAfterClear = undefined
    }
    return { status: 'resolved', keyComponent }
  }

  if (view.status === 'error') {
    if (triggers.noData || isVersionStateNoDataError(view.error)) {
      if (!triggers.noData) {
        triggers.noData = true
        triggers.retainedKey = undefined
        triggers.lastTrueModeHash = undefined
        triggers.firstKeyAfterClear = undefined
      }
      return { status: 'no-data' }
    }
    if (triggers.retainedKey !== undefined) {
      return { status: 'resolved', keyComponent: triggers.retainedKey }
    }
    if (view.data) {
      return { status: 'resolved', keyComponent: view.data.content_hash }
    }
    return { status: 'resolved', keyComponent: UNKNOWN_NETWORK_KEY }
  }

  return { status: 'pending' }
}

function resolutionIdentity(resolution: NetworkKeyResolution): string {
  return resolution.status === 'resolved' ? `key:${String(resolution.keyComponent)}` : resolution.status
}

/**
 * Evaluate the triggers of the latest version-state result once per (QueryClient, snapshot)
 */
export function evaluateVersionStateResult(queryClient: QueryClient, name: string): void {
  const query = findVersionStateQuery(queryClient, name)
  if (!query) return
  const { status, data, error, dataUpdatedAt, errorUpdatedAt } = query.state
  if (status === 'pending') return

  const triggers = getSnapshotTriggerState(queryClient, name)
  const stamp = status === 'success' ? dataUpdatedAt : errorUpdatedAt
  const evaluation = `${status}:${stamp}`
  if (triggers.lastEvaluated === evaluation) return
  triggers.lastEvaluated = evaluation

  const keyIdentity = resolutionIdentity(resolveNetworkKey(queryClient, name, { status, data, error }))
  const keyChanged = triggers.observedKey !== undefined && triggers.observedKey !== keyIdentity
  triggers.observedKey = keyIdentity

  let suppressed = false
  if (triggers.suppressToken !== null) {
    if (Date.now() - triggers.suppressToken > SUPPRESS_TOKEN_TTL_MS) {
      triggers.suppressToken = null
    } else if (stamp >= triggers.suppressToken) {
      suppressed = true
      triggers.suppressToken = null
    }
  }

  if (status !== 'success' || !data) return

  const families = new Set<QueryFamily>()
  const addAllFamilies = () => batfishQueryFamilies.forEach((family) => families.add(family))
  let markConsumed = false

  if (triggers.invalidateAll) {
    triggers.invalidateAll = false
    markConsumed = true
    addAllFamilies()
  }

  if (data.result_cache_enabled !== false) {
    if (triggers.workingHash !== undefined && data.content_hash !== triggers.workingHash) {
      batfishQueryFamilies.filter((family) => family[0] !== 'network').forEach((family) => families.add(family))
    }
    triggers.workingHash = data.content_hash

    if (data.loaded_content_hash !== null) {
      const previous = triggers.loadedPair
      if (
        previous &&
        (previous.hash !== data.loaded_content_hash || previous.batfishVersion !== data.loaded_batfish_version)
      ) {
        addAllFamilies()
      }
      triggers.loadedPair = { hash: data.loaded_content_hash, batfishVersion: data.loaded_batfish_version }
    }
  }

  if (triggers.fallbackMismatch && !data.external_settling) {
    triggers.fallbackMismatch = false
    addAllFamilies()
  }

  const headVersionId = data.head?.version_id ?? null
  const headChanged = triggers.headVersionId !== undefined && triggers.headVersionId !== headVersionId
  triggers.headVersionId = headVersionId
  const workingChanged = triggers.workingDiffHash !== undefined && triggers.workingDiffHash !== data.content_hash
  triggers.workingDiffHash = data.content_hash
  if (headChanged) {
    void queryClient.invalidateQueries({ queryKey: snapshotVersionKeys.list(name) })
  }
  if (headChanged || workingChanged) {
    void invalidateWorkingDiffs(queryClient, name)
  }

  if (families.size > 0) {
    void invalidateSnapshotFamilies(queryClient, name, {
      families: batfishQueryFamilies.filter((family) => families.has(family)),
      signal: !suppressed && !markConsumed,
      networkRefetchType: keyChanged ? 'none' : 'active',
    })
  }
}

function dropSuppressTokenWithoutObservers(queryClient: QueryClient, name: string) {
  const query = findVersionStateQuery(queryClient, name)
  if (!query || query.getObserversCount() === 0) {
    getSnapshotTriggerState(queryClient, name).suppressToken = null
  }
}

/**
 * Poll a snapshot's version state every 15 seconds while mounted and the tab is visible, and evaluate the cache
 * triggers once per result for this QueryClient
 */
export function useSnapshotVersionState(name: string | null) {
  const queryClient = useQueryClient()
  const query = useQuery({
    queryKey: snapshotVersionKeys.state(name),
    queryFn: () => snapshotAPI.getVersionState(name as string),
    enabled: !!name,
    refetchInterval: VERSION_STATE_POLL_INTERVAL_MS,
    retry: retryVersionState,
  })
  const { status, dataUpdatedAt, errorUpdatedAt } = query

  useEffect(() => {
    if (name) {
      evaluateVersionStateResult(queryClient, name)
    }
  }, [queryClient, name, status, dataUpdatedAt, errorUpdatedAt])

  useEffect(() => {
    if (!name) return
    return () => {
      queueMicrotask(() => dropSuppressTokenWithoutObservers(queryClient, name))
    }
  }, [queryClient, name])

  return query
}

interface RefetchedVersionState {
  observedKey: string | undefined
  refetchedKey: string | undefined
  state: QueryState<SnapshotVersionState> | undefined
}

async function refetchObservedVersionState(queryClient: QueryClient, name: string): Promise<RefetchedVersionState> {
  const observedKey = getSnapshotTriggerState(queryClient, name).observedKey
  await refetchVersionState(queryClient, name)
  const state = findVersionStateQuery(queryClient, name)?.state
  const refetchedKey =
    state && state.status !== 'pending'
      ? resolutionIdentity(resolveNetworkKey(queryClient, name, state))
      : undefined
  return { observedKey, refetchedKey, state }
}

function isFallbackMode({ observedKey, refetchedKey, state }: RefetchedVersionState): boolean {
  if (!state) return false
  return (
    state.status === 'error' ||
    observedKey === UNKNOWN_KEY_IDENTITY ||
    refetchedKey === UNKNOWN_KEY_IDENTITY ||
    state.data?.result_cache_enabled === false
  )
}

function preWriteAndInvalidate(queryClient: QueryClient, name: string, refetched: RefetchedVersionState) {
  const { observedKey, refetchedKey, state } = refetched
  if (state?.status === 'success' && state.data) {
    const triggers = getSnapshotTriggerState(queryClient, name)
    triggers.workingHash = state.data.content_hash
    if (state.data.loaded_content_hash !== null) {
      triggers.loadedPair = {
        hash: state.data.loaded_content_hash,
        batfishVersion: state.data.loaded_batfish_version,
      }
    }
    if (!state.data.external_settling) {
      triggers.fallbackMismatch = false
    }
  }
  void invalidateSnapshotFamilies(queryClient, name, {
    networkRefetchType: refetchedKey !== observedKey ? 'none' : 'active',
  })
}

/**
 * After an `if_stale` activation in the same session, refetch version-state and invalidate the snapshot's Batfish
 * families once if the backend parsed, version-state is not a success, the key is 'unknown' or the kill switch is on
 */
export async function settleIfStaleActivation(
  queryClient: QueryClient,
  name: string,
  parsed: boolean,
  generation = getClientGeneration(queryClient)
): Promise<void> {
  if (generation !== getClientGeneration(queryClient)) return
  const refetched = await refetchObservedVersionState(queryClient, name)
  if (generation !== getClientGeneration(queryClient)) return
  if (parsed || refetched.state?.status !== 'success' || isFallbackMode(refetched)) {
    preWriteAndInvalidate(queryClient, name, refetched)
  }
}

/**
 * Refetch a snapshot's version-state and, for the current snapshot in fallback mode within the same session,
 * invalidate its Batfish families once
 */
export async function refreshAfterLayer1Change(
  queryClient: QueryClient,
  name: string,
  generation = getClientGeneration(queryClient)
): Promise<void> {
  if (generation !== getClientGeneration(queryClient)) return
  if (useSnapshotStore.getState().currentSnapshotName !== name) {
    await refetchVersionState(queryClient, name)
    return
  }
  const refetched = await refetchObservedVersionState(queryClient, name)
  if (generation !== getClientGeneration(queryClient)) return
  if (isFallbackMode(refetched)) {
    preWriteAndInvalidate(queryClient, name, refetched)
  }
}

interface InvalidationSignal {
  name: string
  reason: InvalidationReason
}

function parseInvalidationSignal(value: string | null): InvalidationSignal | null {
  if (!value) return null
  try {
    const parsed = JSON.parse(value) as { name?: unknown; reason?: unknown }
    if (typeof parsed?.name !== 'string' || !parsed.name) return null
    if (parsed.reason !== 'edit' && parsed.reason !== 'clear') return null
    return { name: parsed.name, reason: parsed.reason }
  } catch {
    return null
  }
}

/**
 * Apply a `topologix:invalidate` signal written by another window of the same origin
 */
export async function handleInvalidationSignal(queryClient: QueryClient, value: string | null): Promise<void> {
  const signal = parseInvalidationSignal(value)
  if (!signal) return
  const { name } = signal

  if (signal.reason === 'clear') {
    await invalidateSnapshotFamilies(queryClient, name, { signal: false, reason: 'clear' })
    return
  }

  const query = findVersionStateQuery(queryClient, name)
  if (!query || query.state.status === 'pending') {
    await queryClient.invalidateQueries({ queryKey: snapshotVersionKeys.state(name), exact: true, refetchType: 'none' })
    return
  }

  if (query.state.status === 'error') {
    await invalidateSnapshotFamilies(queryClient, name, { signal: false })
    return
  }

  const generation = getClientGeneration(queryClient)
  const triggers = getSnapshotTriggerState(queryClient, name)
  const observed = query.getObserversCount() > 0

  if (query.state.data?.result_cache_enabled === false) {
    if (observed) {
      triggers.suppressToken = Date.now()
    }
    await refetchVersionState(queryClient, name)
    if (generation !== getClientGeneration(queryClient)) return
    const after = query.state
    if (after.status === 'success' && after.data?.result_cache_enabled !== false) {
      triggers.invalidateAll = true
      return
    }
    if (after.status === 'success' && !after.data?.external_settling) {
      triggers.fallbackMismatch = false
    }
    await invalidateSnapshotFamilies(queryClient, name, { signal: false })
    return
  }

  if (!observed) {
    await queryClient.invalidateQueries({ queryKey: snapshotVersionKeys.state(name), exact: true, refetchType: 'none' })
    return
  }

  triggers.suppressToken = Date.now()
  await refetchVersionState(queryClient, name)
  if (generation !== getClientGeneration(queryClient)) return
  const after = query.state
  if (after.status !== 'success' || after.data?.result_cache_enabled === false) {
    if (after.status === 'success' && !after.data?.external_settling) {
      triggers.fallbackMismatch = false
    }
    await invalidateSnapshotFamilies(queryClient, name, { signal: false })
  }
}

function reloadAfterVersionError(queryClient: QueryClient, name: string, error: unknown): Promise<void> | undefined {
  const status = getVersionErrorStatus(error)
  if (status === 409 || isVersionNotFoundError(error)) {
    return Promise.all([
      queryClient.invalidateQueries({ queryKey: snapshotVersionKeys.list(name) }),
      refetchVersionState(queryClient, name),
    ]).then(() => undefined)
  }
  if (status === 503) {
    return refetchVersionState(queryClient, name)
  }
  return undefined
}

async function reloadListOnVersionNotFound<T>(
  queryClient: QueryClient,
  name: string,
  request: () => Promise<T>
): Promise<T> {
  try {
    return await request()
  } catch (error) {
    if (isVersionNotFoundError(error)) {
      void queryClient.invalidateQueries({ queryKey: snapshotVersionKeys.list(name) })
      void refetchVersionState(queryClient, name)
    }
    throw error
  }
}

/**
 * Version list of a snapshot, newest first, 50 per page loaded by offset
 */
export function useSnapshotVersions(name: string, enabled = true) {
  return useInfiniteQuery({
    queryKey: snapshotVersionKeys.list(name),
    queryFn: ({ pageParam }) =>
      snapshotAPI.listVersions(name, { limit: VERSION_LIST_PAGE_SIZE, offset: pageParam }),
    initialPageParam: 0,
    getNextPageParam: (lastPage, allPages) => {
      const loaded = allPages.reduce((count, page) => count + page.items.length, 0)
      return lastPage.items.length > 0 && loaded < lastPage.total ? loaded : undefined
    },
    enabled: enabled && !!name,
    retry: retryVersionState,
  })
}

/**
 * One version with its file manifest
 */
export function useSnapshotVersion(name: string, versionId: string | null, enabled = true) {
  const queryClient = useQueryClient()
  return useQuery({
    queryKey: snapshotVersionKeys.detail(name, versionId ?? ''),
    queryFn: () => reloadListOnVersionNotFound(queryClient, name, () => snapshotAPI.getVersion(name, versionId as string)),
    enabled: enabled && !!name && !!versionId,
    retry: retryVersionState,
  })
}

/**
 * File-level diff summary from a version to another version or to the working tree
 */
export function useVersionDiff(
  name: string,
  versionId: string | null,
  against: string | null,
  { enabled = true, staleTime }: { enabled?: boolean; staleTime?: number } = {}
) {
  const queryClient = useQueryClient()
  return useQuery({
    queryKey: snapshotVersionKeys.diff(name, versionId ?? '', against ?? ''),
    queryFn: () =>
      reloadListOnVersionNotFound(queryClient, name, () =>
        snapshotAPI.getVersionDiff(name, versionId as string, against as string)
      ),
    enabled: enabled && !!name && !!versionId && !!against,
    staleTime,
    retry: retryVersionState,
  })
}

/**
 * Diff of one file from a version to another version or to the working tree
 */
export function useVersionFileDiff(
  name: string,
  versionId: string | null,
  against: string | null,
  path: string | null,
  enabled = true
) {
  const queryClient = useQueryClient()
  return useQuery({
    queryKey: snapshotVersionKeys.fileDiff(name, versionId ?? '', against ?? '', path ?? ''),
    queryFn: () =>
      reloadListOnVersionNotFound(queryClient, name, () =>
        snapshotAPI.getVersionFileDiff(name, versionId as string, against as string, path as string)
      ),
    enabled: enabled && !!name && !!versionId && !!against && !!path,
    gcTime: 60 * 1000,
    retry: retryVersionState,
  })
}

export interface CommitVersionVariables {
  name: string
  message: string
  expectedHead: string | null
}

/**
 * Commit the working tree as a new version; network keys are untouched
 */
export function useCommitVersion() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ name, message, expectedHead }: CommitVersionVariables) =>
      snapshotAPI.commitVersion(name, { message, expected_head: expectedHead }),
    onSuccess: (_version, { name }) => {
      void queryClient.invalidateQueries({ queryKey: snapshotVersionKeys.list(name), refetchType: 'none' })
      return refetchVersionState(queryClient, name)
    },
    onError: (error, { name }) => reloadAfterVersionError(queryClient, name, error),
  })
}

export interface RestoreVersionVariables {
  name: string
  versionId: string
  expectedWorkingHash?: string
}

/**
 * Restore response with the client time at which it arrived
 */
export interface RestoreVersionOutcome {
  response: RestoreVersionResponse
  respondedAt: number
}

/**
 * Write a version's files into the working tree
 */
export function useRestoreVersion() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async ({ name, versionId, expectedWorkingHash }: RestoreVersionVariables): Promise<RestoreVersionOutcome> => {
      const response = await snapshotAPI.restoreVersion(
        name,
        versionId,
        expectedWorkingHash === undefined ? undefined : { expected_working_hash: expectedWorkingHash }
      )
      return { response, respondedAt: Date.now() }
    },
    onSuccess: (_outcome, { name }) => {
      void queryClient.invalidateQueries({ queryKey: snapshotKeys.files(name) })
      void queryClient.invalidateQueries({ queryKey: snapshotKeys.list() })
      void queryClient.invalidateQueries({ queryKey: [...snapshotKeys.all, name, 'file-content'], refetchType: 'none' })
      void queryClient.invalidateQueries({ queryKey: snapshotKeys.artifactTree(name) })
      void queryClient.invalidateQueries({ queryKey: [...layer1EditorKeys.all, name] })
      return refetchVersionState(queryClient, name)
    },
    onError: (error, { name }) => {
      if (responseCode(error) === 'restore_failed') {
        void queryClient.invalidateQueries({ queryKey: snapshotKeys.files(name) })
        return refetchVersionState(queryClient, name)
      }
      return reloadAfterVersionError(queryClient, name, error)
    },
  })
}

export type DeleteVersionsVariables =
  | { name: string; versionId: string; expectedHead: string | null }
  | { name: string; request: VersionDeleteRequest }

/**
 * Delete one version or the all / oldest N / newest N history; network keys are untouched
 */
export function useDeleteVersions() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (variables: DeleteVersionsVariables) =>
      'versionId' in variables
        ? snapshotAPI.deleteVersion(variables.name, variables.versionId, { expected_head: variables.expectedHead })
        : snapshotAPI.deleteVersions(variables.name, variables.request),
    onSuccess: (_result, { name }) => {
      void queryClient.invalidateQueries({
        predicate: (query) => {
          const key = query.queryKey
          return key[0] === versionRoot && key[1] === name && key[2] !== 'state'
        },
      })
      return refetchVersionState(queryClient, name)
    },
    onError: (error, { name }) => reloadAfterVersionError(queryClient, name, error),
  })
}

/**
 * Ask the server to clear the snapshot's cached results; on success in the same session, invalidate its Batfish
 * families and signal the other windows
 */
export function useClearResultCache() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (name: string) => snapshotAPI.clearResultCache(name),
    onMutate: () => ({ generation: getClientGeneration(queryClient) }),
    onSuccess: (_result, name, context) => {
      if (context?.generation !== getClientGeneration(queryClient)) return
      void invalidateSnapshotFamilies(queryClient, name, { reason: 'clear' })
    },
    onError: (error, name) => reloadAfterVersionError(queryClient, name, error),
  })
}
