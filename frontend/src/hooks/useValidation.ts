/**
 * React Query hooks for configuration validation data
 * Provides file parse status, init issues, parse warnings, and conversion status
 */
import { useMemo } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { validationAPI } from '../services/api'
import { buildParseResultSummary } from '../lib/validation/parseResult'
import { useSnapshotStore } from '../store'

const inactiveSnapshotKey = 'no-active-snapshot'
const snapshotSegment = (snapshotName: string | null) => snapshotName ?? inactiveSnapshotKey

/**
 * Query key factory for validation-related React Query caches
 * Covers configuration parsing, initialization, and validation checks
 */
export const validationKeys = {
  all: ['validation'] as const,
  fileParseStatus: (snapshotName: string | null) => [...validationKeys.all, snapshotSegment(snapshotName), 'file-parse-status'] as const,
  initIssues: (snapshotName: string | null) => [...validationKeys.all, snapshotSegment(snapshotName), 'init-issues'] as const,
  parseWarnings: (snapshotName: string | null) => [...validationKeys.all, snapshotSegment(snapshotName), 'parse-warnings'] as const,
  viConversionStatus: (snapshotName: string | null) => [...validationKeys.all, snapshotSegment(snapshotName), 'vi-conversion-status'] as const,
  unusedStructures: (snapshotName: string | null) => [...validationKeys.all, snapshotSegment(snapshotName), 'unused-structures'] as const,
  undefinedReferences: (snapshotName: string | null) => [...validationKeys.all, snapshotSegment(snapshotName), 'undefined-references'] as const,
  forwardingLoops: (snapshotName: string | null) => [...validationKeys.all, snapshotSegment(snapshotName), 'forwarding-loops'] as const,
  multipathConsistency: (snapshotName: string | null) => [...validationKeys.all, snapshotSegment(snapshotName), 'multipath-consistency'] as const,
  loopbackMultipathConsistency: (snapshotName: string | null) => [...validationKeys.all, snapshotSegment(snapshotName), 'loopback-multipath-consistency'] as const,
}

/**
 * Query configuration file parse status
 * Returns success/failure status for each device config file parsed by Batfish
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useFileParseStatus(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: validationKeys.fileParseStatus(currentSnapshotName),
    queryFn: () => validationAPI.getFileParseStatus(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Query Batfish initialization issues
 * Returns errors encountered during snapshot initialization phase
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useInitIssues(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: validationKeys.initIssues(currentSnapshotName),
    queryFn: () => validationAPI.getInitIssues(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Query configuration parse warnings
 * Returns warnings from config parsing (non-fatal issues)
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useParseWarnings(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: validationKeys.parseWarnings(currentSnapshotName),
    queryFn: () => validationAPI.getParseWarnings(),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Aggregate Batfish parse result queries into a compact UI summary.
 * Uses React Query-backed data only; no effect-driven data fetching.
 */
export function useParseResultSummary(enabled = true) {
  const fileParseStatus = useFileParseStatus(enabled)
  const initIssues = useInitIssues(enabled)
  const parseWarnings = useParseWarnings(enabled)

  const summary = useMemo(
    () =>
      buildParseResultSummary(
        fileParseStatus.data ?? [],
        initIssues.data ?? [],
        parseWarnings.data ?? []
      ),
    [fileParseStatus.data, initIssues.data, parseWarnings.data]
  )

  return {
    summary,
    fileParseStatus,
    initIssues,
    parseWarnings,
    isLoading:
      fileParseStatus.isLoading ||
      fileParseStatus.isFetching ||
      initIssues.isLoading ||
      initIssues.isFetching ||
      parseWarnings.isLoading ||
      parseWarnings.isFetching,
    isError:
      fileParseStatus.isError ||
      fileParseStatus.isRefetchError ||
      initIssues.isError ||
      initIssues.isRefetchError ||
      parseWarnings.isError ||
      parseWarnings.isRefetchError,
    error: fileParseStatus.error || initIssues.error || parseWarnings.error,
  }
}

/**
 * Query vendor-independent (VI) model conversion status
 * Returns status of converting vendor configs to Batfish VI model
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useVIConversionStatus(enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: validationKeys.viConversionStatus(currentSnapshotName),
    queryFn: () => validationAPI.getVIConversionStatus(),
    enabled: enabled && !!currentSnapshotName,
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
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: validationKeys.unusedStructures(currentSnapshotName),
    queryFn: () => validationAPI.getUnusedStructures(),
    enabled: enabled && !!currentSnapshotName,
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
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: validationKeys.undefinedReferences(currentSnapshotName),
    queryFn: () => validationAPI.getUndefinedReferences(),
    enabled: enabled && !!currentSnapshotName,
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
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: validationKeys.forwardingLoops(currentSnapshotName),
    queryFn: () => validationAPI.getForwardingLoops(),
    enabled: enabled && !!currentSnapshotName,
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
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: validationKeys.multipathConsistency(currentSnapshotName),
    queryFn: () => validationAPI.getMultipathConsistency(),
    enabled: enabled && !!currentSnapshotName,
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
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: validationKeys.loopbackMultipathConsistency(currentSnapshotName),
    queryFn: () => validationAPI.getLoopbackMultipathConsistency(),
    enabled: enabled && !!currentSnapshotName,
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
