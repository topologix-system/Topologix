/**
 * React Query hooks for BGP protocol data
 * Handles BGP peer configuration, process settings, session status, and RIB entries
 */
import { useQuery } from '@tanstack/react-query'
import { bgpAPI } from '../services/api'

/**
 * Query key factory for BGP-related React Query caches
 * Hierarchical structure enables targeted cache invalidation
 */
export const bgpKeys = {
  all: ['bgp'] as const,
  peerConfiguration: () => [...bgpKeys.all, 'peer-configuration'] as const,
  processConfiguration: () => [...bgpKeys.all, 'process-configuration'] as const,
  sessionStatus: () => [...bgpKeys.all, 'session-status'] as const,
  sessionCompatibility: () => [...bgpKeys.all, 'session-compatibility'] as const,
  rib: () => [...bgpKeys.all, 'rib'] as const,
}

/**
 * Query BGP peer configurations across network devices
 * Returns neighbor addresses, AS numbers, and peering policies
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useBGPPeerConfiguration(enabled = true) {
  return useQuery({
    queryKey: bgpKeys.peerConfiguration(),
    queryFn: () => bgpAPI.getPeerConfiguration(),
    enabled,
    staleTime: 60000,
  })
}

/**
 * Query BGP process configurations
 * Returns router IDs, AS numbers, and global BGP settings
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useBGPProcessConfiguration(enabled = true) {
  return useQuery({
    queryKey: bgpKeys.processConfiguration(),
    queryFn: () => bgpAPI.getProcessConfiguration(),
    enabled,
    staleTime: 60000,
  })
}

/**
 * Query BGP session status for all neighbors
 * Returns session states (Established, Idle, Active, etc.) and uptime
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useBGPSessionStatus(enabled = true) {
  return useQuery({
    queryKey: bgpKeys.sessionStatus(),
    queryFn: () => bgpAPI.getSessionStatus(),
    enabled,
    staleTime: 60000,
  })
}

/**
 * Query BGP session compatibility issues
 * Identifies configuration mismatches preventing session establishment
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useBGPSessionCompatibility(enabled = true) {
  return useQuery({
    queryKey: bgpKeys.sessionCompatibility(),
    queryFn: () => bgpAPI.getSessionCompatibility(),
    enabled,
    staleTime: 60000,
  })
}

/**
 * Query BGP Routing Information Base (RIB)
 * Returns learned BGP routes with next-hops, AS paths, and attributes
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useBGPRib(enabled = true) {
  return useQuery({
    queryKey: bgpKeys.rib(),
    queryFn: () => bgpAPI.getRib(),
    enabled,
    staleTime: 60000,
  })
}
