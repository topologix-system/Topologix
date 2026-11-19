/**
 * React Query hooks for routing protocols (EIGRP, IS-IS, BFD, EVPN)
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
