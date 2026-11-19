/**
 * React Query hooks for network data fetching and Batfish API interactions
 */
import { useMemo } from 'react'
import { useQuery, useMutation, useQueryClient, type Query, type QueryClient, type QueryKey } from '@tanstack/react-query'
import { runtimeConfig } from '../config/runtimeConfig'
import { networkAPI } from '../services/api'
import type { HashKeyedResponse, NetworkInitializeRequest, ResultIdentityHeaders, SnapshotVersionState } from '../types'
import { useSnapshotStore } from '../store'
import {
  LEGACY_NETWORK_STALE_TIME_MS,
  UNKNOWN_NETWORK_KEY,
  getClientGeneration,
  getSnapshotTriggerState,
  refetchVersionState,
  resolveNetworkKey,
  snapshotVersionKeys,
  useSnapshotVersionState,
  type NetworkKeyResolution,
} from './useSnapshotVersions'

const inactiveSnapshotKey = 'no-active-snapshot'
const snapshotSegment = (snapshotName: string | null) => snapshotName ?? inactiveSnapshotKey
const UNRESOLVED_NETWORK_KEY = 'unresolved'
const NO_DATA_NETWORK_KEY = 'no-data'
const PENDING_RESOLUTION: NetworkKeyResolution = { status: 'pending' }

export type NetworkKeyComponent = string | null

/**
 * Query key factory for the network queries; the hash-keyed keys hold the key component resolved from
 * version-state after the snapshot name
 */
export const networkKeys = {
  all: ['network'] as const,
  health: () => [...networkKeys.all, 'health'] as const,
  allData: (snapshotName: string | null, contentHash: NetworkKeyComponent) =>
    [...networkKeys.all, snapshotSegment(snapshotName), contentHash, 'all-data'] as const,
  nodes: (snapshotName: string | null, contentHash: NetworkKeyComponent) =>
    [...networkKeys.all, snapshotSegment(snapshotName), contentHash, 'nodes'] as const,
  interfaces: (snapshotName: string | null, contentHash: NetworkKeyComponent) =>
    [...networkKeys.all, snapshotSegment(snapshotName), contentHash, 'interfaces'] as const,
  routes: (snapshotName: string | null, contentHash: NetworkKeyComponent) =>
    [...networkKeys.all, snapshotSegment(snapshotName), contentHash, 'routes'] as const,
  vlans: (snapshotName: string | null, contentHash: NetworkKeyComponent) =>
    [...networkKeys.all, snapshotSegment(snapshotName), contentHash, 'vlans'] as const,
  ipOwners: (snapshotName: string | null, contentHash: NetworkKeyComponent) =>
    [...networkKeys.all, snapshotSegment(snapshotName), contentHash, 'ip-owners'] as const,
}

/**
 * Cached hash-keyed response; `legacy` entries keep the 5-minute staleTime instead of Infinity
 */
export interface HashKeyedEntry<T> {
  data: T
  legacy: boolean
}

/**
 * The server answered a hash-keyed query for another snapshot than the one version-state reports
 */
export class SnapshotMismatchError extends Error {
  readonly code = 'snapshot_mismatch'

  constructor() {
    super('The server answered for a different snapshot')
    this.name = 'SnapshotMismatchError'
  }
}

/**
 * The server kept answering a hash-keyed query with content of another hash after version-state settled
 */
export class ContentHashMismatchError extends Error {
  readonly code = 'content_hash_mismatch'

  constructor() {
    super('The server answered with content of a different hash')
    this.name = 'ContentHashMismatchError'
  }
}

export function isSnapshotMismatchError(error: unknown): error is SnapshotMismatchError {
  return error instanceof SnapshotMismatchError
}

export function isContentHashMismatchError(error: unknown): error is ContentHashMismatchError {
  return error instanceof ContentHashMismatchError
}

type ResponseMatch = 'match' | 'legacy' | 'snapshot-mismatch' | 'hash-mismatch'

function matchResponse(
  queryClient: QueryClient,
  name: string,
  keyComponent: NetworkKeyComponent,
  { snapshotId, contentHash, cacheStatus }: ResultIdentityHeaders
): ResponseMatch {
  if (snapshotId === undefined && contentHash === undefined && cacheStatus === undefined) return 'legacy'
  const expectedSnapshotId = queryClient.getQueryData<SnapshotVersionState>(snapshotVersionKeys.state(name))?.snapshot_id
  if (snapshotId && expectedSnapshotId && snapshotId !== expectedSnapshotId) return 'snapshot-mismatch'
  if (keyComponent === null || keyComponent === UNKNOWN_NETWORK_KEY || !contentHash || cacheStatus === 'unstored') {
    return 'legacy'
  }
  return contentHash === keyComponent ? 'match' : 'hash-mismatch'
}

async function fetchHashKeyed<T>(
  queryClient: QueryClient,
  queryKey: QueryKey,
  fetcher: () => Promise<HashKeyedResponse<T>>
): Promise<HashKeyedEntry<T>> {
  const name = queryKey[1] as string
  const keyComponent = queryKey[2] as NetworkKeyComponent
  const keyFor = (contentHash: string) => [queryKey[0], queryKey[1], contentHash, ...queryKey.slice(3)]
  const generation = getClientGeneration(queryClient)
  const sessionChanged = () => generation !== getClientGeneration(queryClient)

  const first = await fetcher()
  if (sessionChanged()) return { data: first.data, legacy: true }
  const firstMatch = matchResponse(queryClient, name, keyComponent, first.identity)
  if (firstMatch === 'snapshot-mismatch') {
    await refetchVersionState(queryClient, name)
    throw new SnapshotMismatchError()
  }
  if (firstMatch !== 'hash-mismatch') {
    return { data: first.data, legacy: firstMatch === 'legacy' }
  }

  queryClient.setQueryData<HashKeyedEntry<T>>(keyFor(first.identity.contentHash as string), {
    data: first.data,
    legacy: false,
  })
  await refetchVersionState(queryClient, name)

  const second = await fetcher()
  if (sessionChanged()) return { data: second.data, legacy: true }
  const secondMatch = matchResponse(queryClient, name, keyComponent, second.identity)
  if (secondMatch === 'snapshot-mismatch') {
    throw new SnapshotMismatchError()
  }
  if (secondMatch !== 'hash-mismatch') {
    return { data: second.data, legacy: secondMatch === 'legacy' }
  }

  queryClient.setQueryData<HashKeyedEntry<T>>(keyFor(second.identity.contentHash as string), {
    data: second.data,
    legacy: false,
  })
  const versionState = queryClient.getQueryState<SnapshotVersionState>(snapshotVersionKeys.state(name))
  const triggers = getSnapshotTriggerState(queryClient, name)
  if (versionState?.status !== 'success') {
    triggers.fallbackMismatch = true
    return { data: second.data, legacy: false }
  }
  if (versionState.data?.external_settling) {
    const existing = queryClient.getQueryData<HashKeyedEntry<T>>(queryKey)
    if (existing) return existing
    triggers.fallbackMismatch = true
    return { data: second.data, legacy: true }
  }
  throw new ContentHashMismatchError()
}

function hashKeyedStaleTime<T>(queryClient: QueryClient) {
  return (query: Query<HashKeyedEntry<T>, Error, HashKeyedEntry<T>, QueryKey>) => {
    const killSwitchKey = getSnapshotTriggerState(queryClient, query.queryKey[1] as string).retainedKey !== undefined
    return query.state.data?.legacy || killSwitchKey || query.queryKey[2] === UNKNOWN_NETWORK_KEY
      ? LEGACY_NETWORK_STALE_TIME_MS
      : Infinity
  }
}

function selectEntryData<T>(entry: HashKeyedEntry<T>): T {
  return entry.data
}

function keepSameSnapshotPlaceholder<T>(snapshotName: string | null) {
  const segment = snapshotSegment(snapshotName)
  return (
    previousData: HashKeyedEntry<T> | undefined,
    previousQuery: Query<HashKeyedEntry<T>, Error, HashKeyedEntry<T>, QueryKey> | undefined
  ) => (previousQuery?.queryKey[1] === segment ? previousData : undefined)
}

const noPlaceholder = () => undefined

/**
 * Network query keyed by the snapshot name and the key component resolved from its version-state; disabled until
 * that key resolves and without data in the sticky no-data state
 */
function useHashKeyedQuery<T>(
  buildKey: (snapshotName: string | null, contentHash: NetworkKeyComponent) => QueryKey,
  fetcher: () => Promise<HashKeyedResponse<T>>,
  enabled: boolean
) {
  const queryClient = useQueryClient()
  const snapshotName = useSnapshotStore((state) => state.currentSnapshotName)
  const versionState = useSnapshotVersionState(snapshotName)
  const resolution = snapshotName ? resolveNetworkKey(queryClient, snapshotName, versionState) : PENDING_RESOLUTION
  const keyComponent =
    resolution.status === 'resolved'
      ? resolution.keyComponent
      : resolution.status === 'no-data'
        ? NO_DATA_NETWORK_KEY
        : UNRESOLVED_NETWORK_KEY
  const noData = resolution.status === 'no-data'
  const firstKeyAfterClear =
    resolution.status === 'resolved' &&
    snapshotName !== null &&
    getSnapshotTriggerState(queryClient, snapshotName).firstKeyAfterClear === resolution.keyComponent

  const staleTime = useMemo(() => hashKeyedStaleTime<T>(queryClient), [queryClient])
  const placeholderData = useMemo(
    () => (noData || firstKeyAfterClear ? noPlaceholder : keepSameSnapshotPlaceholder<T>(snapshotName)),
    [noData, firstKeyAfterClear, snapshotName]
  )

  const query = useQuery<HashKeyedEntry<T>, Error, T, QueryKey>({
    queryKey: buildKey(snapshotName, keyComponent),
    queryFn: ({ queryKey }) => fetchHashKeyed(queryClient, queryKey, fetcher),
    enabled: enabled && !!snapshotName && resolution.status === 'resolved',
    staleTime,
    gcTime: 10 * 60 * 1000,
    placeholderData,
    select: selectEntryData,
    refetchInterval: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    // No automatic retry: each attempt re-runs Batfish queries while the
    // backend holds its process-wide Batfish lock, so retrying a slow/failed
    // aggregate multiplies the outage instead of recovering from it. The
    // error view offers a manual retry button.
    retry: false,
  })

  return {
    ...query,
    isLoading: query.isLoading || (enabled && !!snapshotName && query.isPending && versionState.isPending),
  }
}

/**
 * Query backend health status with automatic polling
 */
export function useHealth() {
  return useQuery({
    queryKey: networkKeys.health(),
    queryFn: () => networkAPI.health(),
    staleTime: 30 * 1000,
    gcTime: 60 * 1000,
    refetchInterval: 60 * 1000,
  })
}

export function useAuthModeStatus() {
  const healthQuery = useHealth()
  const frontendAuthEnabled = runtimeConfig.authEnabled
  const backendAuthEnabled =
    typeof healthQuery.data?.auth_enabled === 'boolean' ? healthQuery.data.auth_enabled : null

  return {
    ...healthQuery,
    frontendAuthEnabled,
    backendAuthEnabled,
    authModeMismatch:
      typeof backendAuthEnabled === 'boolean' && backendAuthEnabled !== frontendAuthEnabled,
  }
}

/**
 * Mutation to initialize Batfish network analysis for active snapshot
 * Triggers Batfish processing and invalidates all network caches on success
 */
export function useInitializeNetwork() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (request: NetworkInitializeRequest) => networkAPI.initializeNetwork(request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: networkKeys.all })
    },
  })
}

/**
 * Query comprehensive network data (topology, nodes, edges, protocols)
 */
export function useAllNetworkData(enabled = true) {
  return useHashKeyedQuery(networkKeys.allData, () => networkAPI.getAllData(), enabled)
}

/**
 * Query network nodes/devices from Batfish
 * Returns list of routers, switches, and other network devices
 */
export function useNodes(enabled = true) {
  return useHashKeyedQuery(networkKeys.nodes, () => networkAPI.getNodes(), enabled)
}

/**
 * Query network interfaces from all devices
 * Returns interface configurations including IPs, VLANs, and status
 */
export function useInterfaces(enabled = true) {
  return useHashKeyedQuery(networkKeys.interfaces, () => networkAPI.getInterfaces(), enabled)
}

/**
 * Query routing tables from all network devices
 * Returns routes with next-hops, protocols, and metrics
 */
export function useRoutes(enabled = true) {
  return useHashKeyedQuery(networkKeys.routes, () => networkAPI.getRoutes(), enabled)
}

/**
 * Query VLAN configurations across the network
 */
export function useVlans(enabled = true) {
  return useHashKeyedQuery(networkKeys.vlans, () => networkAPI.getVlans(), enabled)
}

/**
 * Query IP address ownership mapping
 * Returns which devices/interfaces own each IP address in the network
 */
export function useIPOwners(enabled = true) {
  return useHashKeyedQuery(networkKeys.ipOwners, () => networkAPI.getIPOwners(), enabled)
}
