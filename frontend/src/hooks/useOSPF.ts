/**
 * React Query hooks for OSPF protocol data
 * Provides cached queries for OSPF processes, areas, interfaces, and sessions
 */
import { useQuery } from '@tanstack/react-query'
import { ospfAPI } from '../services/api'
import { useSnapshotStore } from '../store'

const inactiveSnapshotKey = 'no-active-snapshot'
const snapshotSegment = (snapshotName: string | null) => snapshotName ?? inactiveSnapshotKey

/**
 * Query key factory for OSPF-related React Query caches
 * Hierarchical structure enables targeted cache invalidation
 */
export const ospfKeys = {
  all: ['ospf'] as const,
  processes: (snapshotName: string | null) => [...ospfKeys.all, snapshotSegment(snapshotName), 'processes'] as const,
  areas: (snapshotName: string | null) => [...ospfKeys.all, snapshotSegment(snapshotName), 'areas'] as const,
  interfaces: (snapshotName: string | null) => [...ospfKeys.all, snapshotSegment(snapshotName), 'interfaces'] as const,
  sessions: (snapshotName: string | null) => [...ospfKeys.all, snapshotSegment(snapshotName), 'sessions'] as const,
}

/**
 * Query OSPF process configurations from network devices
 * Returns OSPF router IDs, process IDs, and configuration details
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useOSPFProcesses(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: ospfKeys.processes(currentSnapshotName),
    queryFn: () => ospfAPI.getProcesses(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Query OSPF area configurations
 * Returns area IDs, types (standard, stub, NSSA), and associated interfaces
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useOSPFAreas(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: ospfKeys.areas(currentSnapshotName),
    queryFn: () => ospfAPI.getAreas(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Query OSPF-enabled interfaces
 * Returns interfaces participating in OSPF with network types and costs
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useOSPFInterfaces(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: ospfKeys.interfaces(currentSnapshotName),
    queryFn: () => ospfAPI.getInterfaces(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Query OSPF neighbor sessions/adjacencies
 * Returns neighbor states, router IDs, and adjacency status
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useOSPFSessions(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: ospfKeys.sessions(currentSnapshotName),
    queryFn: () => ospfAPI.getSessions(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}
