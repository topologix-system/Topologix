/**
 * React Query hooks for High Availability protocols
 * Handles VRRP, HSRP, MLAG properties, and duplicate router ID detection
 */
import { useQuery } from '@tanstack/react-query'
import { haAPI } from '../services/api'

/**
 * Query key factory for High Availability-related React Query caches
 * Covers VRRP, HSRP, MLAG protocols and router ID validation
 */
export const haKeys = {
  all: ['ha'] as const,
  vrrp: () => [...haKeys.all, 'vrrp'] as const,
  hsrp: () => [...haKeys.all, 'hsrp'] as const,
  mlag: () => [...haKeys.all, 'mlag'] as const,
  duplicateRouterIds: () => [...haKeys.all, 'duplicate-router-ids'] as const,
  switchingProperties: () => [...haKeys.all, 'switching-properties'] as const,
}

/**
 * Query VRRP (Virtual Router Redundancy Protocol) properties
 * Returns VRRP groups, priorities, and virtual IP configurations
 * Used for gateway redundancy analysis
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useVRRPProperties(enabled = true) {
  return useQuery({
    queryKey: haKeys.vrrp(),
    queryFn: () => haAPI.getVRRPProperties(),
    enabled,
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
  return useQuery({
    queryKey: haKeys.hsrp(),
    queryFn: () => haAPI.getHSRPProperties(),
    enabled,
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
  return useQuery({
    queryKey: haKeys.mlag(),
    queryFn: () => haAPI.getMLAGProperties(),
    enabled,
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
  return useQuery({
    queryKey: haKeys.duplicateRouterIds(),
    queryFn: () => haAPI.getDuplicateRouterIDs(),
    enabled,
    staleTime: 60000,
  })
}

/**
 * Query layer 2 switching properties
 * Returns switch configuration including VLANs, trunking, and spanning-tree
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useSwitchingProperties(enabled = true) {
  return useQuery({
    queryKey: haKeys.switchingProperties(),
    queryFn: () => haAPI.getSwitchingProperties(),
    enabled,
    staleTime: 60000,
  })
}