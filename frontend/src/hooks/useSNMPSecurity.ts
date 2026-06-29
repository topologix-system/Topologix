/**
 * React Query hooks for SNMP security validation
 * Provides SNMP community configuration analysis
 */
import { useQuery } from '@tanstack/react-query'
import { securityAPI } from '../services/api'
import { useSnapshotStore } from '../store'

const inactiveSnapshotKey = 'no-active-snapshot'
const snapshotSegment = (snapshotName: string | null) => snapshotName ?? inactiveSnapshotKey

/**
 * Query key factory for SNMP security-related React Query caches
 */
export const snmpSecurityKeys = {
  all: ['snmp-security'] as const,
  communities: (snapshotName: string | null) => [...snmpSecurityKeys.all, snapshotSegment(snapshotName), 'communities'] as const,
}

/**
 * Query SNMP community configurations
 * Returns SNMP community strings and their allowed client IPs
 * Critical for security auditing of SNMP access control
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useSNMPCommunities(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: snmpSecurityKeys.communities(currentSnapshotName),
    queryFn: () => securityAPI.getSNMPCommunities(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}
