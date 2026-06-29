/**
 * React Query hooks for routing protocols (EIGRP, IS-IS, VXLAN, IPsec, BFD)
 * Handles protocol-specific edges, interfaces, and session data
 */
import { useQuery } from '@tanstack/react-query'
import { protocolsAPI } from '../services/api'
import { useSnapshotStore } from '../store'

const inactiveSnapshotKey = 'no-active-snapshot'
const snapshotSegment = (snapshotName: string | null) => snapshotName ?? inactiveSnapshotKey

/**
 * Query key factory for protocols-related React Query caches
 * Covers EIGRP, IS-IS, BFD, and EVPN protocols
 * Hierarchical structure enables targeted cache invalidation
 */
export const protocolsKeys = {
  all: ['protocols'] as const,
  eigrpEdges: (snapshotName: string | null) => [...protocolsKeys.all, snapshotSegment(snapshotName), 'eigrp-edges'] as const,
  eigrpInterfaces: (snapshotName: string | null) => [...protocolsKeys.all, snapshotSegment(snapshotName), 'eigrp-interfaces'] as const,
  isisEdges: (snapshotName: string | null) => [...protocolsKeys.all, snapshotSegment(snapshotName), 'isis-edges'] as const,
  isisInterfaces: (snapshotName: string | null) => [...protocolsKeys.all, snapshotSegment(snapshotName), 'isis-interfaces'] as const,
  isisLoopbackInterfaces: (snapshotName: string | null) => [...protocolsKeys.all, snapshotSegment(snapshotName), 'isis-loopback-interfaces'] as const,
  bfdSessionStatus: (snapshotName: string | null) => [...protocolsKeys.all, snapshotSegment(snapshotName), 'bfd-session-status'] as const,
  evpnRib: (snapshotName: string | null) => [...protocolsKeys.all, snapshotSegment(snapshotName), 'evpn-rib'] as const,
}

/**
 * Query EIGRP adjacency edges
 * Returns EIGRP neighbor relationships and topology connections
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useEIGRPEdges(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: protocolsKeys.eigrpEdges(currentSnapshotName),
    queryFn: () => protocolsAPI.getEIGRPEdges(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Query EIGRP-enabled interfaces
 * Returns interfaces participating in EIGRP with network assignments
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useEIGRPInterfaces(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: protocolsKeys.eigrpInterfaces(currentSnapshotName),
    queryFn: () => protocolsAPI.getEIGRPInterfaces(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Query IS-IS adjacency edges
 * Returns IS-IS neighbor relationships and topology connections
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useISISEdges(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: protocolsKeys.isisEdges(currentSnapshotName),
    queryFn: () => protocolsAPI.getISISEdges(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Query IS-IS-enabled interfaces
 * Returns interfaces participating in IS-IS with circuit types and levels
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useISISInterfaces(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: protocolsKeys.isisInterfaces(currentSnapshotName),
    queryFn: () => protocolsAPI.getISISInterfaces(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Query IS-IS loopback interfaces
 * Returns loopback interfaces used for IS-IS router IDs and reachability
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useISISLoopbackInterfaces(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: protocolsKeys.isisLoopbackInterfaces(currentSnapshotName),
    queryFn: () => protocolsAPI.getISISLoopbackInterfaces(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Query BFD (Bidirectional Forwarding Detection) session status
 * Returns BFD session states and failure detection status for fast convergence
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useBFDSessionStatus(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: protocolsKeys.bfdSessionStatus(currentSnapshotName),
    queryFn: () => protocolsAPI.getBFDSessionStatus(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Query EVPN (Ethernet VPN) Routing Information Base
 * Returns EVPN routes for VXLAN overlay networks and Layer 2 VPN services
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useEVPNRib(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: protocolsKeys.evpnRib(currentSnapshotName),
    queryFn: () => protocolsAPI.getEVPNRib(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}
