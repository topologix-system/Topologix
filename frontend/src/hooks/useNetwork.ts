/**
 * React Query hooks for network data fetching and Batfish API interactions
 * - Provides type-safe hooks for all network-related queries and mutations
 * - Implements React Query best practices with staleTime, gcTime, and refetch policies
 * - Query key factory pattern for cache management and invalidation
 * - All queries depend on active snapshot selection from Zustand store
 */
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { networkAPI, authAPI } from '../services/api'
import type { NetworkInitializeRequest } from '../types'
import { useSnapshotStore } from '../store'
import { useAuthStore } from '../store/useAuthStore'

/**
 * Query key factory for network-related React Query caches
 * Hierarchical structure enables targeted cache invalidation
 * Example: invalidating networkKeys.all clears all network queries
 */
export const networkKeys = {
  all: ['network'] as const,
  health: () => [...networkKeys.all, 'health'] as const,
  allData: () => [...networkKeys.all, 'all-data'] as const,
  nodes: () => [...networkKeys.all, 'nodes'] as const,
  interfaces: () => [...networkKeys.all, 'interfaces'] as const,
  routes: () => [...networkKeys.all, 'routes'] as const,
  vlans: () => [...networkKeys.all, 'vlans'] as const,
  ipOwners: () => [...networkKeys.all, 'ip-owners'] as const,
}

/**
 * Query backend health status with automatic polling
 * Refetches every 60 seconds to monitor backend availability
 * Used in application header for connection status indicator
 * Only polls when authentication is disabled or user is authenticated (reactive)
 */
export function useHealth() {
  // Zustand store subscription - reactive to auth state changes
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated)

  return useQuery({
    queryKey: networkKeys.health(),
    queryFn: () => networkAPI.health(),
    enabled: !authAPI.isAuthEnabled() || isAuthenticated,
    staleTime: 30 * 1000,
    gcTime: 60 * 1000,
    refetchInterval: 60 * 1000,
  })
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
    queryKey: networkKeys.allData(),
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
  return useQuery({
    queryKey: networkKeys.nodes(),
    queryFn: () => networkAPI.getNodes(),
    enabled,
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
  return useQuery({
    queryKey: networkKeys.interfaces(),
    queryFn: () => networkAPI.getInterfaces(),
    enabled,
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
  return useQuery({
    queryKey: networkKeys.routes(),
    queryFn: () => networkAPI.getRoutes(),
    enabled,
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
  return useQuery({
    queryKey: networkKeys.vlans(),
    queryFn: () => networkAPI.getVlans(),
    enabled,
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
  return useQuery({
    queryKey: networkKeys.ipOwners(),
    queryFn: () => networkAPI.getIPOwners(),
    enabled,
    staleTime: 5 * 60 * 1000,
    gcTime: 10 * 60 * 1000,
    refetchOnWindowFocus: false,
  })
}