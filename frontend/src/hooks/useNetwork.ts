/**
 * React Query hooks for network data fetching and Batfish API interactions
 * - Provides type-safe hooks for all network-related queries and mutations
 * - Implements React Query best practices with staleTime, gcTime, and refetch policies
 * - Query key factory pattern for cache management and invalidation
 * - All queries depend on active snapshot selection from Zustand store
 */
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { runtimeConfig } from '../config/runtimeConfig'
import { networkAPI } from '../services/api'
import type { NetworkInitializeRequest } from '../types'
import { useSnapshotStore } from '../store'

const inactiveSnapshotKey = 'no-active-snapshot'
const snapshotSegment = (snapshotName: string | null) => snapshotName ?? inactiveSnapshotKey

/**
 * Query key factory for network-related React Query caches
 * Hierarchical structure enables targeted cache invalidation
 * Example: invalidating networkKeys.all clears all network queries
 */
export const networkKeys = {
  all: ['network'] as const,
  health: () => [...networkKeys.all, 'health'] as const,
  allData: (snapshotName: string | null) => [...networkKeys.all, snapshotSegment(snapshotName), 'all-data'] as const,
  nodes: (snapshotName: string | null) => [...networkKeys.all, snapshotSegment(snapshotName), 'nodes'] as const,
  interfaces: (snapshotName: string | null) => [...networkKeys.all, snapshotSegment(snapshotName), 'interfaces'] as const,
  routes: (snapshotName: string | null) => [...networkKeys.all, snapshotSegment(snapshotName), 'routes'] as const,
  vlans: (snapshotName: string | null) => [...networkKeys.all, snapshotSegment(snapshotName), 'vlans'] as const,
  ipOwners: (snapshotName: string | null) => [...networkKeys.all, snapshotSegment(snapshotName), 'ip-owners'] as const,
}

/**
 * Query backend health status with automatic polling
 * Refetches every 60 seconds to monitor backend availability
 * Used in application header for connection status indicator
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
 * Used after snapshot activation or configuration file uploads
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
 * Primary data source for topology visualization and network analysis panels
 * Only fetches when snapshot is active - disabled if no snapshot selected
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useAllNetworkData(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: networkKeys.allData(currentSnapshotName),
    queryFn: () => networkAPI.getAllData(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 5 * 60 * 1000,
    gcTime: 10 * 60 * 1000,
    refetchInterval: false,
    refetchOnWindowFocus: false,
  })
}

/**
 * Query network nodes/devices from Batfish
 * Returns list of routers, switches, and other network devices
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useNodes(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: networkKeys.nodes(currentSnapshotName),
    queryFn: () => networkAPI.getNodes(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 5 * 60 * 1000,
    gcTime: 10 * 60 * 1000,
    refetchOnWindowFocus: false,
  })
}

/**
 * Query network interfaces from all devices
 * Returns interface configurations including IPs, VLANs, and status
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useInterfaces(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: networkKeys.interfaces(currentSnapshotName),
    queryFn: () => networkAPI.getInterfaces(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 5 * 60 * 1000,
    gcTime: 10 * 60 * 1000,
    refetchOnWindowFocus: false,
  })
}

/**
 * Query routing tables from all network devices
 * Returns routes with next-hops, protocols, and metrics
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useRoutes(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: networkKeys.routes(currentSnapshotName),
    queryFn: () => networkAPI.getRoutes(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 5 * 60 * 1000,
    gcTime: 10 * 60 * 1000,
    refetchOnWindowFocus: false,
  })
}

/**
 * Query VLAN configurations across the network
 * Returns VLAN IDs, names, and associated interfaces
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useVlans(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: networkKeys.vlans(currentSnapshotName),
    queryFn: () => networkAPI.getVlans(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 5 * 60 * 1000,
    gcTime: 10 * 60 * 1000,
    refetchOnWindowFocus: false,
  })
}

/**
 * Query IP address ownership mapping
 * Returns which devices/interfaces own each IP address in the network
 * Used for IP conflict detection and address management
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useIPOwners(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: networkKeys.ipOwners(currentSnapshotName),
    queryFn: () => networkAPI.getIPOwners(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 5 * 60 * 1000,
    gcTime: 10 * 60 * 1000,
    refetchOnWindowFocus: false,
  })
}
