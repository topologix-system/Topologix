/**
 * React Query hooks for SNMP security validation
 * Provides SNMP community configuration analysis
 */
import { useQuery } from '@tanstack/react-query'
import { securityAPI } from '../services/api'

/**
 * Query key factory for SNMP security-related React Query caches
 */
export const snmpSecurityKeys = {
  all: ['snmp-security'] as const,
  communities: () => [...snmpSecurityKeys.all, 'communities'] as const,
}

/**
 * Query SNMP community configurations
 * Returns SNMP community strings and their allowed client IPs
 * Critical for security auditing of SNMP access control
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useSNMPCommunities(enabled = true) {
  return useQuery({
    queryKey: snmpSecurityKeys.communities(),
    queryFn: () => securityAPI.getSNMPCommunities(),
    enabled,
    staleTime: 60000,
  })
}
