/**
 * React Query hooks for BGP protocol data
 * Handles BGP peer configuration, process settings, session status, and RIB entries
 */
import { useQuery } from '@tanstack/react-query'
import { bgpAPI } from '../services/api'
import { useSnapshotStore } from '../store'

const inactiveSnapshotKey = 'no-active-snapshot'
const snapshotSegment = (snapshotName: string | null) => snapshotName ?? inactiveSnapshotKey

/**
 * Query key factory for BGP-related React Query caches
 * Hierarchical structure enables targeted cache invalidation
 */
export const bgpKeys = {
  all: ['bgp'] as const,
  peerConfiguration: (snapshotName: string | null) => [...bgpKeys.all, snapshotSegment(snapshotName), 'peer-configuration'] as const,
  processConfiguration: (snapshotName: string | null) => [...bgpKeys.all, snapshotSegment(snapshotName), 'process-configuration'] as const,
  sessionStatus: (snapshotName: string | null) => [...bgpKeys.all, snapshotSegment(snapshotName), 'session-status'] as const,
  sessionCompatibility: (snapshotName: string | null) => [...bgpKeys.all, snapshotSegment(snapshotName), 'session-compatibility'] as const,
  rib: (snapshotName: string | null) => [...bgpKeys.all, snapshotSegment(snapshotName), 'rib'] as const,
}

/**
 * Query BGP peer configurations across network devices
 * Returns neighbor addresses, AS numbers, and peering policies
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useBGPPeerConfiguration(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: bgpKeys.peerConfiguration(currentSnapshotName),
    queryFn: () => bgpAPI.getPeerConfiguration(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Query BGP process configurations
 * Returns router IDs, AS numbers, and global BGP settings
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useBGPProcessConfiguration(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: bgpKeys.processConfiguration(currentSnapshotName),
    queryFn: () => bgpAPI.getProcessConfiguration(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Query BGP session status for all neighbors
 * Returns session states (Established, Idle, Active, etc.) and uptime
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useBGPSessionStatus(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: bgpKeys.sessionStatus(currentSnapshotName),
    queryFn: () => bgpAPI.getSessionStatus(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Query BGP session compatibility issues
 * Identifies configuration mismatches preventing session establishment
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useBGPSessionCompatibility(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: bgpKeys.sessionCompatibility(currentSnapshotName),
    queryFn: () => bgpAPI.getSessionCompatibility(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Query BGP Routing Information Base (RIB)
 * Returns learned BGP routes with next-hops, AS paths, and attributes
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useBGPRib(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: bgpKeys.rib(currentSnapshotName),
    queryFn: () => bgpAPI.getRib(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}
