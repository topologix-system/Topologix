/**
 * React Query hooks for device configuration structures
 * Provides defined/referenced structures, named structures, and AAA authentication
 */
import { useQuery } from '@tanstack/react-query'
import { configAPI } from '../services/api'

/**
 * Query key factory for configuration structures-related React Query caches
 * Covers named structures, references, and AAA authentication config
 */
export const configKeys = {
  all: ['config'] as const,
  definedStructures: () => [...configKeys.all, 'defined-structures'] as const,
  referencedStructures: () => [...configKeys.all, 'referenced-structures'] as const,
  namedStructures: () => [...configKeys.all, 'named-structures'] as const,
  aaaAuthentication: () => [...configKeys.all, 'aaa-authentication'] as const,
}

/**
 * Query defined configuration structures
 * Returns all named config objects (ACLs, route-maps, prefix-lists, etc.)
 * Shows what structures are declared in device configurations
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useDefinedStructures(enabled = true) {
  return useQuery({
    queryKey: configKeys.definedStructures(),
    queryFn: () => configAPI.getDefinedStructures(),
    enabled,
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
  return useQuery({
    queryKey: configKeys.referencedStructures(),
    queryFn: () => configAPI.getReferencedStructures(),
    enabled,
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
  return useQuery({
    queryKey: configKeys.namedStructures(),
    queryFn: () => configAPI.getNamedStructures(),
    enabled,
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
  return useQuery({
    queryKey: configKeys.aaaAuthentication(),
    queryFn: () => configAPI.getAAAAuthentication(),
    enabled,
    staleTime: 60000,
  })
}