/**
 * React Query hooks for network topology edges
 * Provides queries for physical, layer3, OSPF, and BGP connections
 */
import { useQuery } from '@tanstack/react-query'
import { edgesAPI } from '../services/api'
import { useSnapshotStore } from '../store'

const inactiveSnapshotKey = 'no-active-snapshot'
const snapshotSegment = (snapshotName: string | null) => snapshotName ?? inactiveSnapshotKey

/**
 * Query key factory for edges-related React Query caches
 * Hierarchical structure enables targeted cache invalidation
 */
export const edgesKeys = {
  all: ['edges'] as const,
  ospf: (snapshotName: string | null) => [...edgesKeys.all, snapshotSegment(snapshotName), 'ospf'] as const,
  physical: (snapshotName: string | null) => [...edgesKeys.all, snapshotSegment(snapshotName), 'physical'] as const,
  layer3: (snapshotName: string | null) => [...edgesKeys.all, snapshotSegment(snapshotName), 'layer3'] as const,
  bgp: (snapshotName: string | null) => [...edgesKeys.all, snapshotSegment(snapshotName), 'bgp'] as const,
}

/**
 * Query OSPF adjacency edges
 * Returns OSPF neighbor relationships and adjacency connections
 * Used for OSPF topology visualization
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useOSPFEdges(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: edgesKeys.ospf(currentSnapshotName),
    queryFn: () => edgesAPI.getOSPFEdges(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Query physical layer connections
 * Returns direct physical links between devices (cables, fiber, etc.)
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function usePhysicalEdges(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: edgesKeys.physical(currentSnapshotName),
    queryFn: () => edgesAPI.getPhysicalEdges(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Query layer 3 (IP) connectivity edges
 * Returns logical IP-level connections and subnets between devices
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useLayer3Edges(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: edgesKeys.layer3(currentSnapshotName),
    queryFn: () => edgesAPI.getLayer3Edges(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Query BGP peering edges
 * Returns BGP neighbor relationships and peering sessions
 * Used for BGP topology visualization
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useBGPEdges(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: edgesKeys.bgp(currentSnapshotName),
    queryFn: () => edgesAPI.getBGPEdges(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}
