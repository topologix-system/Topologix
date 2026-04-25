/**
 * React Query hooks for configuration validation data
 * Provides file parse status, init issues, parse warnings, and conversion status
 */
import { useQuery, useMutation } from '@tanstack/react-query'
import { validationAPI } from '../services/api'

/**
 * Query key factory for validation-related React Query caches
 * Covers configuration parsing, initialization, and validation checks
 */
export const validationKeys = {
  all: ['validation'] as const,
  fileParseStatus: () => [...validationKeys.all, 'file-parse-status'] as const,
  initIssues: () => [...validationKeys.all, 'init-issues'] as const,
  parseWarnings: () => [...validationKeys.all, 'parse-warnings'] as const,
  viConversionStatus: () => [...validationKeys.all, 'vi-conversion-status'] as const,
}

/**
 * Query configuration file parse status
 * Returns success/failure status for each device config file parsed by Batfish
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useFileParseStatus(enabled = true) {
  return useQuery({
    queryKey: validationKeys.fileParseStatus(),
    queryFn: () => validationAPI.getFileParseStatus(),
    enabled,
    staleTime: 60000,
  })
}

/**
 * Query Batfish initialization issues
 * Returns errors encountered during snapshot initialization phase
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useInitIssues(enabled = true) {
  return useQuery({
    queryKey: validationKeys.initIssues(),
    queryFn: () => validationAPI.getInitIssues(),
    enabled,
    staleTime: 60000,
  })
}

/**
 * Query configuration parse warnings
 * Returns warnings from config parsing (non-fatal issues)
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useParseWarnings(enabled = true) {
  return useQuery({
    queryKey: validationKeys.parseWarnings(),
    queryFn: () => validationAPI.getParseWarnings(),
    enabled,
    staleTime: 60000,
  })
}

/**
 * Query vendor-independent (VI) model conversion status
 * Returns status of converting vendor configs to Batfish VI model
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useVIConversionStatus(enabled = true) {
  return useQuery({
    queryKey: validationKeys.viConversionStatus(),
    queryFn: () => validationAPI.getVIConversionStatus(),
    enabled,
    staleTime: 60000,
  })
}

/**
 * Query unused configuration structures
 * Returns defined config objects (ACLs, route-maps, etc.) that are never referenced
 * Helps identify configuration bloat and cleanup opportunities
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useUnusedStructures(enabled = true) {
  return useQuery({
    queryKey: [...validationKeys.all, 'unused-structures'] as const,
    queryFn: () => validationAPI.getUnusedStructures(),
    enabled,
    staleTime: 60000,
  })
}

/**
 * Query undefined configuration references
 * Returns references to non-existent config objects (broken references)
 * Critical validation issue that can cause failures
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useUndefinedReferences(enabled = true) {
  return useQuery({
    queryKey: [...validationKeys.all, 'undefined-references'] as const,
    queryFn: () => validationAPI.getUndefinedReferences(),
    enabled,
    staleTime: 60000,
  })
}

/**
 * Query routing forwarding loops
 * Returns detected routing loops that cause packet cycling
 * Critical network issue requiring immediate attention
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useForwardingLoops(enabled = true) {
  return useQuery({
    queryKey: [...validationKeys.all, 'forwarding-loops'] as const,
    queryFn: () => validationAPI.getForwardingLoops(),
    enabled,
    staleTime: 60000,
  })
}

/**
 * Query multipath routing consistency
 * Validates ECMP (Equal-Cost Multi-Path) configuration consistency
 * Ensures load balancing works as expected
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useMultipathConsistency(enabled = true) {
  return useQuery({
    queryKey: [...validationKeys.all, 'multipath-consistency'] as const,
    queryFn: () => validationAPI.getMultipathConsistency(),
    enabled,
    staleTime: 60000,
  })
}

/**
 * Query loopback interface multipath consistency
 * Validates ECMP for loopback interfaces (typically used for router IDs)
 * Important for IGP and overlay network stability
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useLoopbackMultipathConsistency(enabled = true) {
  return useQuery({
    queryKey: [...validationKeys.all, 'loopback-multipath-consistency'] as const,
    queryFn: () => validationAPI.getLoopbackMultipathConsistency(),
    enabled,
    staleTime: 60000,
  })
}

/**
 * Mutation to check subnet-level multipath consistency
 * Validates ECMP behavior per subnet (more granular than global check)
 * User-triggered analysis with optional max trace limit
 */
export function useSubnetMultipathConsistency() {
  return useMutation({
    mutationFn: (request?: { maxTraces?: number }) =>
      validationAPI.getSubnetMultipathConsistency(request),
  })
}

/**
 * Mutation to resolve filter specifiers into concrete Batfish filters.
 */
export function useResolveFilterSpecifier() {
  return useMutation({
    mutationFn: (request?: { filters?: string | string[]; nodes?: string | string[]; grammarVersion?: string }) =>
      validationAPI.resolveFilterSpecifier(request),
  })
}

/**
 * Mutation to resolve node specifiers into concrete Batfish nodes.
 */
export function useResolveNodeSpecifier() {
  return useMutation({
    mutationFn: (request?: { nodes?: string | string[]; grammarVersion?: string }) =>
      validationAPI.resolveNodeSpecifier(request),
  })
}

/**
 * Mutation to resolve interface specifiers into concrete Batfish interfaces.
 */
export function useResolveInterfaceSpecifier() {
  return useMutation({
    mutationFn: (request?: { interfaces?: string | string[]; nodes?: string | string[]; grammarVersion?: string }) =>
      validationAPI.resolveInterfaceSpecifier(request),
  })
}

/**
 * Mutation to compare filters between the active snapshot and a reference snapshot.
 */
export function useCompareFilters() {
  return useMutation({
    mutationFn: (request: {
      reference_snapshot: string
      snapshot?: string
      filters?: string | string[]
      nodes?: string | string[]
      ignoreComposites?: boolean
    }) =>
      validationAPI.compareFilters(request),
  })
}
