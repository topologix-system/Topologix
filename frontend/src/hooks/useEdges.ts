/**
 * React Query hooks for network topology edges
 * Provides queries for physical, layer3, OSPF, and BGP connections
 */
import { useQuery } from '@tanstack/react-query'
import { edgesAPI } from '../services/api'

/**
 * Query key factory for edges-related React Query caches
 * Hierarchical structure enables targeted cache invalidation
 */
export const edgesKeys = {
  all: ['edges'] as const,
  ospf: () => [...edgesKeys.all, 'ospf'] as const,
  physical: () => [...edgesKeys.all, 'physical'] as const,
  layer3: () => [...edgesKeys.all, 'layer3'] as const,
  bgp: () => [...edgesKeys.all, 'bgp'] as const,
}

/**
 * Query OSPF adjacency edges
 * Returns OSPF neighbor relationships and adjacency connections
 * Used for OSPF topology visualization
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useOSPFEdges(enabled = true) {
  return useQuery({
    queryKey: edgesKeys.ospf(),
    queryFn: () => edgesAPI.getOSPFEdges(),
    enabled,
    staleTime: 60000,
  })
}

/**
 * Query physical layer connections
 * Returns direct physical links between devices (cables, fiber, etc.)
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function usePhysicalEdges(enabled = true) {
  return useQuery({
    queryKey: edgesKeys.physical(),
    queryFn: () => edgesAPI.getPhysicalEdges(),
    enabled,
    staleTime: 60000,
  })
}

/**
 * Query layer 3 (IP) connectivity edges
 * Returns logical IP-level connections and subnets between devices
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useLayer3Edges(enabled = true) {
  return useQuery({
    queryKey: edgesKeys.layer3(),
    queryFn: () => edgesAPI.getLayer3Edges(),
    enabled,
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
  return useQuery({
    queryKey: edgesKeys.bgp(),
    queryFn: () => edgesAPI.getBGPEdges(),
    enabled,
    staleTime: 60000,
  })
}