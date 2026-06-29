/**
 * React Query hooks for device configuration structures
 * Provides defined/referenced structures, named structures, and AAA authentication
 */
import { useQuery } from '@tanstack/react-query'
import { configAPI } from '../services/api'
import { useSnapshotStore } from '../store'

const inactiveSnapshotKey = 'no-active-snapshot'
const snapshotSegment = (snapshotName: string | null) => snapshotName ?? inactiveSnapshotKey

/**
 * Query key factory for configuration structures-related React Query caches
 * Covers named structures, references, and AAA authentication config
 */
export const configKeys = {
  all: ['config'] as const,
  definedStructures: (snapshotName: string | null) => [...configKeys.all, snapshotSegment(snapshotName), 'defined-structures'] as const,
  referencedStructures: (snapshotName: string | null) => [...configKeys.all, snapshotSegment(snapshotName), 'referenced-structures'] as const,
  namedStructures: (snapshotName: string | null) => [...configKeys.all, snapshotSegment(snapshotName), 'named-structures'] as const,
  aaaAuthentication: (snapshotName: string | null) => [...configKeys.all, snapshotSegment(snapshotName), 'aaa-authentication'] as const,
}

/**
 * Query defined configuration structures
 * Returns all named config objects (ACLs, route-maps, prefix-lists, etc.)
 * Shows what structures are declared in device configurations
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useDefinedStructures(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: configKeys.definedStructures(currentSnapshotName),
    queryFn: () => configAPI.getDefinedStructures(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Query referenced configuration structures
 * Returns all config objects that are actually used/referenced
 * Useful for identifying active vs. unused configurations
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useReferencedStructures(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: configKeys.referencedStructures(currentSnapshotName),
    queryFn: () => configAPI.getReferencedStructures(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Query named configuration structures summary
 * Returns organized view of named structures by type
 * Higher-level view than defined/referenced structures
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useNamedStructures(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: configKeys.namedStructures(currentSnapshotName),
    queryFn: () => configAPI.getNamedStructures(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Query AAA (Authentication, Authorization, Accounting) configuration
 * Returns authentication methods, TACACS+/RADIUS servers, and AAA settings
 * Critical for security and access control analysis
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useAAAAuthentication(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: configKeys.aaaAuthentication(currentSnapshotName),
    queryFn: () => configAPI.getAAAAuthentication(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}
