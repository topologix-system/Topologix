/**
 * React Query hooks for network topology layers
 * Handles Layer 1/2 topology, VXLAN VNI properties, and switched VLAN edges
 */
import { useQuery } from '@tanstack/react-query'
import { topologyAPI } from '../services/api'

/**
 * Query key factory for topology-related React Query caches
 * Covers Layer 1/2, VXLAN, IPsec VPN, and interface properties
 */
export const topologyKeys = {
  all: ['topology'] as const,
  layer1: () => [...topologyKeys.all, 'layer1'] as const,
  layer2: () => [...topologyKeys.all, 'layer2'] as const,
  vxlanVNI: () => [...topologyKeys.all, 'vxlan-vni'] as const,
  vxlanEdges: () => [...topologyKeys.all, 'vxlan-edges'] as const,
  ipsecSessionStatus: () => [...topologyKeys.all, 'ipsec-session-status'] as const,
  ipsecEdges: () => [...topologyKeys.all, 'ipsec-edges'] as const,
  ipsecPeerConfiguration: () => [...topologyKeys.all, 'ipsec-peer-configuration'] as const,
  interfaceMTU: () => [...topologyKeys.all, 'interface-mtu'] as const,
  ipSpaceAssignment: () => [...topologyKeys.all, 'ip-space-assignment'] as const,
}

/**
 * Query Layer 1 (physical) topology
 * Returns physical cable connections between devices
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useLayer1Topology(enabled = true) {
  return useQuery({
    queryKey: topologyKeys.layer1(),
    queryFn: () => topologyAPI.getLayer1Topology(),
    enabled,
    staleTime: 60000,
  })
}

/**
 * Query Layer 2 (data link) topology
 * Returns VLAN, switching, and MAC-level connectivity
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useLayer2Topology(enabled = true) {
  return useQuery({
    queryKey: topologyKeys.layer2(),
    queryFn: () => topologyAPI.getLayer2Topology(),
    enabled,
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
  return useQuery({
    queryKey: topologyKeys.vxlanVNI(),
    queryFn: () => topologyAPI.getVXLANVNIProperties(),
    enabled,
    staleTime: 60000,
  })
}

/**
 * Query VXLAN tunnel edges
 * Returns VXLAN tunnel connections between VTEPs (VXLAN Tunnel Endpoints)
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useVXLANEdges(enabled = true) {
  return useQuery({
    queryKey: topologyKeys.vxlanEdges(),
    queryFn: () => topologyAPI.getVXLANEdges(),
    enabled,
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
  return useQuery({
    queryKey: topologyKeys.ipsecSessionStatus(),
    queryFn: () => topologyAPI.getIPSecSessionStatus(),
    enabled,
    staleTime: 60000,
  })
}

/**
 * Query IPsec VPN tunnel edges
 * Returns IPsec tunnel connections between peers
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useIPSecEdges(enabled = true) {
  return useQuery({
    queryKey: topologyKeys.ipsecEdges(),
    queryFn: () => topologyAPI.getIPSecEdges(),
    enabled,
    staleTime: 60000,
  })
}

/**
 * Query IPsec peer configuration
 * Returns IPsec peer settings, IKE policies, and transform sets
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useIPSecPeerConfiguration(enabled = true) {
  return useQuery({
    queryKey: topologyKeys.ipsecPeerConfiguration(),
    queryFn: () => topologyAPI.getIPSecPeerConfiguration(),
    enabled,
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
  return useQuery({
    queryKey: topologyKeys.interfaceMTU(),
    queryFn: () => topologyAPI.getInterfaceMTU(),
    enabled,
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
  return useQuery({
    queryKey: topologyKeys.ipSpaceAssignment(),
    queryFn: () => topologyAPI.getIPSpaceAssignment(),
    enabled,
    staleTime: 60000,
  })
}