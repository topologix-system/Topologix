/**
 * React Query hooks for OSPF protocol data
 * Provides cached queries for OSPF processes, areas, interfaces, and sessions
 */
import { useQuery } from '@tanstack/react-query'
import { ospfAPI } from '../services/api'

/**
 * Query key factory for OSPF-related React Query caches
 * Hierarchical structure enables targeted cache invalidation
 */
export const ospfKeys = {
  all: ['ospf'] as const,
  processes: () => [...ospfKeys.all, 'processes'] as const,
  areas: () => [...ospfKeys.all, 'areas'] as const,
  interfaces: () => [...ospfKeys.all, 'interfaces'] as const,
  sessions: () => [...ospfKeys.all, 'sessions'] as const,
}

/**
 * Query OSPF process configurations from network devices
 * Returns OSPF router IDs, process IDs, and configuration details
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useOSPFProcesses(enabled = true) {
  return useQuery({
    queryKey: ospfKeys.processes(),
    queryFn: () => ospfAPI.getProcesses(),
    enabled,
    staleTime: 60000,
  })
}

/**
 * Query OSPF area configurations
 * Returns area IDs, types (standard, stub, NSSA), and associated interfaces
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useOSPFAreas(enabled = true) {
  return useQuery({
    queryKey: ospfKeys.areas(),
    queryFn: () => ospfAPI.getAreas(),
    enabled,
    staleTime: 60000,
  })
}

/**
 * Query OSPF-enabled interfaces
 * Returns interfaces participating in OSPF with network types and costs
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useOSPFInterfaces(enabled = true) {
  return useQuery({
    queryKey: ospfKeys.interfaces(),
    queryFn: () => ospfAPI.getInterfaces(),
    enabled,
    staleTime: 60000,
  })
}

/**
 * Query OSPF neighbor sessions/adjacencies
 * Returns neighbor states, router IDs, and adjacency status
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useOSPFSessions(enabled = true) {
  return useQuery({
    queryKey: ospfKeys.sessions(),
    queryFn: () => ospfAPI.getSessions(),
    enabled,
    staleTime: 60000,
  })
}