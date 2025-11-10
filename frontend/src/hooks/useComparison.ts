/**
 * React Query hooks for snapshot comparison
 * Handles differential analysis between two network snapshots
 */
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { snapshotAPI } from '../services/api'
import type { CompareSnapshotsRequest } from '../types'

/**
 * Query key factory for comparison-related React Query caches
 * Hierarchical structure for comparison results
 */
export const comparisonKeys = {
  all: ['comparison'] as const,
  compare: (baseSnapshot: string, comparisonSnapshot: string) =>
    [...comparisonKeys.all, baseSnapshot, comparisonSnapshot] as const,
}

/**
 * Mutation to compare two snapshots
 * Analyzes differences in nodes, edges, routes, and reachability
 * Returns comprehensive comparison results showing additions, removals, and modifications
 * Used in SnapshotComparison page to display differential analysis
 */
export function useCompareSnapshots() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (request: CompareSnapshotsRequest) =>
      snapshotAPI.compare(request),
    onSuccess: (data, variables) => {
      // Cache comparison result for potential future use
      queryClient.setQueryData(
        comparisonKeys.compare(variables.base_snapshot, variables.comparison_snapshot),
        data
      )
    },
  })
}
