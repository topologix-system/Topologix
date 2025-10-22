/**
 * React Query hooks for routing protocols (EIGRP, IS-IS, VXLAN, IPsec, BFD)
 * Handles protocol-specific edges, interfaces, and session data
 */
import { useQuery } from '@tanstack/react-query'
import { protocolsAPI } from '../services/api'

/**
 * Query key factory for protocols-related React Query caches
 * Covers EIGRP, IS-IS, BFD, and EVPN protocols
 * Hierarchical structure enables targeted cache invalidation
 */
export const protocolsKeys = {
  all: ['protocols'] as const,
  eigrpEdges: () => [...protocolsKeys.all, 'eigrp-edges'] as const,
  eigrpInterfaces: () => [...protocolsKeys.all, 'eigrp-interfaces'] as const,
  isisEdges: () => [...protocolsKeys.all, 'isis-edges'] as const,
  isisInterfaces: () => [...protocolsKeys.all, 'isis-interfaces'] as const,
  isisLoopbackInterfaces: () => [...protocolsKeys.all, 'isis-loopback-interfaces'] as const,
  bfdSessionStatus: () => [...protocolsKeys.all, 'bfd-session-status'] as const,
  evpnRib: () => [...protocolsKeys.all, 'evpn-rib'] as const,
}

/**
 * Query EIGRP adjacency edges
 * Returns EIGRP neighbor relationships and topology connections
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useEIGRPEdges(enabled = true) {
  return useQuery({
    queryKey: protocolsKeys.eigrpEdges(),
    queryFn: () => protocolsAPI.getEIGRPEdges(),
    enabled,
    staleTime: 60000,
  })
}

/**
 * Query EIGRP-enabled interfaces
 * Returns interfaces participating in EIGRP with network assignments
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useEIGRPInterfaces(enabled = true) {
  return useQuery({
    queryKey: protocolsKeys.eigrpInterfaces(),
    queryFn: () => protocolsAPI.getEIGRPInterfaces(),
    enabled,
    staleTime: 60000,
  })
}

/**
 * Query IS-IS adjacency edges
 * Returns IS-IS neighbor relationships and topology connections
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useISISEdges(enabled = true) {
  return useQuery({
    queryKey: protocolsKeys.isisEdges(),
    queryFn: () => protocolsAPI.getISISEdges(),
    enabled,
    staleTime: 60000,
  })
}

/**
 * Query IS-IS-enabled interfaces
 * Returns interfaces participating in IS-IS with circuit types and levels
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useISISInterfaces(enabled = true) {
  return useQuery({
    queryKey: protocolsKeys.isisInterfaces(),
    queryFn: () => protocolsAPI.getISISInterfaces(),
    enabled,
    staleTime: 60000,
  })
}

/**
 * Query IS-IS loopback interfaces
 * Returns loopback interfaces used for IS-IS router IDs and reachability
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useISISLoopbackInterfaces(enabled = true) {
  return useQuery({
    queryKey: protocolsKeys.isisLoopbackInterfaces(),
    queryFn: () => protocolsAPI.getISISLoopbackInterfaces(),
    enabled,
    staleTime: 60000,
  })
}

/**
 * Query BFD (Bidirectional Forwarding Detection) session status
 * Returns BFD session states and failure detection status for fast convergence
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useBFDSessionStatus(enabled = true) {
  return useQuery({
    queryKey: protocolsKeys.bfdSessionStatus(),
    queryFn: () => protocolsAPI.getBFDSessionStatus(),
    enabled,
    staleTime: 60000,
  })
}

/**
 * Query EVPN (Ethernet VPN) Routing Information Base
 * Returns EVPN routes for VXLAN overlay networks and Layer 2 VPN services
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useEVPNRib(enabled = true) {
  return useQuery({
    queryKey: protocolsKeys.evpnRib(),
    queryFn: () => protocolsAPI.getEVPNRib(),
    enabled,
    staleTime: 60000,
  })
}