/**
 * React Query hooks for High Availability protocols
 * Handles VRRP, HSRP, MLAG properties, and duplicate router ID detection
 */
import { useQuery } from '@tanstack/react-query'
import { haAPI } from '../services/api'
import { useSnapshotStore } from '../store'

const inactiveSnapshotKey = 'no-active-snapshot'
const snapshotSegment = (snapshotName: string | null) => snapshotName ?? inactiveSnapshotKey

/**
 * Query key factory for High Availability-related React Query caches
 * Covers VRRP, HSRP, MLAG protocols and router ID validation
 */
export const haKeys = {
  all: ['ha'] as const,
  vrrp: (snapshotName: string | null) => [...haKeys.all, snapshotSegment(snapshotName), 'vrrp'] as const,
  hsrp: (snapshotName: string | null) => [...haKeys.all, snapshotSegment(snapshotName), 'hsrp'] as const,
  mlag: (snapshotName: string | null) => [...haKeys.all, snapshotSegment(snapshotName), 'mlag'] as const,
  duplicateRouterIds: (snapshotName: string | null) => [...haKeys.all, snapshotSegment(snapshotName), 'duplicate-router-ids'] as const,
  switchingProperties: (snapshotName: string | null) => [...haKeys.all, snapshotSegment(snapshotName), 'switching-properties'] as const,
}

/**
 * Query VRRP (Virtual Router Redundancy Protocol) properties
 * Returns VRRP groups, priorities, and virtual IP configurations
 * Used for gateway redundancy analysis
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useVRRPProperties(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: haKeys.vrrp(currentSnapshotName),
    queryFn: () => haAPI.getVRRPProperties(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Query HSRP (Hot Standby Router Protocol) properties
 * Returns HSRP groups, priorities, and standby configurations
 * Cisco-specific gateway redundancy protocol
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useHSRPProperties(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: haKeys.hsrp(currentSnapshotName),
    queryFn: () => haAPI.getHSRPProperties(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Query MLAG (Multi-Chassis Link Aggregation) properties
 * Returns MLAG peer configurations and port-channel settings
 * Used for switch-level redundancy analysis
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useMLAGProperties(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: haKeys.mlag(currentSnapshotName),
    queryFn: () => haAPI.getMLAGProperties(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Query duplicate router IDs across devices
 * Returns conflicts where multiple devices share same router ID
 * Critical issue that breaks OSPF/IS-IS routing
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useDuplicateRouterIDs(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: haKeys.duplicateRouterIds(currentSnapshotName),
    queryFn: () => haAPI.getDuplicateRouterIDs(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Query layer 2 switching properties
 * Returns switch configuration including VLANs, trunking, and spanning-tree
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useSwitchingProperties(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: haKeys.switchingProperties(currentSnapshotName),
    queryFn: () => haAPI.getSwitchingProperties(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}
