/**
 * React Query hooks for network topology layers
 * Handles Layer 1/2 topology, VXLAN VNI properties, and switched VLAN edges
 */
import { useQuery, useMutation } from '@tanstack/react-query'
import { topologyAPI } from '../services/api'
import { useSnapshotStore } from '../store'

const inactiveSnapshotKey = 'no-active-snapshot'
const snapshotSegment = (snapshotName: string | null) => snapshotName ?? inactiveSnapshotKey

/**
 * Query key factory for topology-related React Query caches
 * Covers Layer 1/2, VXLAN, IPsec VPN, and interface properties
 */
export const topologyKeys = {
  all: ['topology'] as const,
  layer1: (snapshotName: string | null) => [...topologyKeys.all, snapshotSegment(snapshotName), 'layer1'] as const,
  layer2: (snapshotName: string | null) => [...topologyKeys.all, snapshotSegment(snapshotName), 'layer2'] as const,
  vxlanVNI: (snapshotName: string | null) => [...topologyKeys.all, snapshotSegment(snapshotName), 'vxlan-vni'] as const,
  vxlanEdges: (snapshotName: string | null) => [...topologyKeys.all, snapshotSegment(snapshotName), 'vxlan-edges'] as const,
  ipsecSessionStatus: (snapshotName: string | null) => [...topologyKeys.all, snapshotSegment(snapshotName), 'ipsec-session-status'] as const,
  ipsecEdges: (snapshotName: string | null) => [...topologyKeys.all, snapshotSegment(snapshotName), 'ipsec-edges'] as const,
  ipsecPeerConfiguration: (snapshotName: string | null) => [...topologyKeys.all, snapshotSegment(snapshotName), 'ipsec-peer-configuration'] as const,
  interfaceMTU: (snapshotName: string | null) => [...topologyKeys.all, snapshotSegment(snapshotName), 'interface-mtu'] as const,
  ipSpaceAssignment: (snapshotName: string | null) => [...topologyKeys.all, snapshotSegment(snapshotName), 'ip-space-assignment'] as const,
}

/**
 * Query Layer 1 (physical) topology
 * Returns physical cable connections between devices
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useLayer1Topology(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: topologyKeys.layer1(currentSnapshotName),
    queryFn: () => topologyAPI.getLayer1Topology(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Query Layer 2 (data link) topology
 * Returns VLAN, switching, and MAC-level connectivity
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useLayer2Topology(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: topologyKeys.layer2(currentSnapshotName),
    queryFn: () => topologyAPI.getLayer2Topology(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Query VXLAN VNI (Virtual Network Identifier) properties
 * Returns VXLAN overlay network configurations and VNI mappings
 * Used for data center fabric analysis
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useVXLANVNIProperties(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: topologyKeys.vxlanVNI(currentSnapshotName),
    queryFn: () => topologyAPI.getVXLANVNIProperties(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Query VXLAN tunnel edges
 * Returns VXLAN tunnel connections between VTEPs (VXLAN Tunnel Endpoints)
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useVXLANEdges(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: topologyKeys.vxlanEdges(currentSnapshotName),
    queryFn: () => topologyAPI.getVXLANEdges(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Query IPsec VPN session status
 * Returns IPsec tunnel states and encryption status
 * Used for VPN connectivity monitoring
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useIPSecSessionStatus(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: topologyKeys.ipsecSessionStatus(currentSnapshotName),
    queryFn: () => topologyAPI.getIPSecSessionStatus(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Query IPsec VPN tunnel edges
 * Returns IPsec tunnel connections between peers
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useIPSecEdges(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: topologyKeys.ipsecEdges(currentSnapshotName),
    queryFn: () => topologyAPI.getIPSecEdges(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Query IPsec peer configuration
 * Returns IPsec peer settings, IKE policies, and transform sets
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useIPSecPeerConfiguration(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: topologyKeys.ipsecPeerConfiguration(currentSnapshotName),
    queryFn: () => topologyAPI.getIPSecPeerConfiguration(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Query interface MTU (Maximum Transmission Unit) settings
 * Returns MTU values for all interfaces across devices
 * Critical for identifying MTU mismatches causing packet fragmentation
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useInterfaceMTU(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: topologyKeys.interfaceMTU(currentSnapshotName),
    queryFn: () => topologyAPI.getInterfaceMTU(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Query IP address space assignments
 * Returns IP subnet allocations and address space organization
 * Used for IP address management and planning
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useIPSpaceAssignment(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: topologyKeys.ipSpaceAssignment(currentSnapshotName),
    queryFn: () => topologyAPI.getIPSpaceAssignment(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Mutation to query longest-prefix-match routes for a target IP.
 */
export function useLpmRoutes() {
  return useMutation({
    mutationFn: (request: { ip: string; nodes?: string | string[]; vrfs?: string | string[] }) =>
      topologyAPI.getLpmRoutes(request),
  })
}

/**
 * Mutation to trace prefix propagation through the network.
 */
export function usePrefixTracer() {
  return useMutation({
    mutationFn: (request: { prefix: string; nodes?: string | string[] }) =>
      topologyAPI.getPrefixTracer(request),
  })
}

/**
 * Mutation to inspect Batfish-normalized user-provided Layer1 edges.
 */
export function useUserProvidedLayer1Edges() {
  return useMutation({
    mutationFn: (request?: { nodes?: string | string[]; remoteNodes?: string | string[] }) =>
      topologyAPI.getUserProvidedLayer1Edges(request),
  })
}
