/**
 * React Query hooks for network analysis and reachability testing
 */
import { useQuery, useMutation } from '@tanstack/react-query'
import type { AxiosError } from 'axios'
import { analysisAPI } from '../services/api'
import type { ReachabilityRequest, TracerouteRequest, TracerouteResponse, BidirectionalTracerouteResponse } from '../types'
import { useSnapshotStore } from '../store'

const inactiveSnapshotKey = 'no-active-snapshot'
const snapshotSegment = (snapshotName: string | null) => snapshotName ?? inactiveSnapshotKey

/**
 * Query key factory for network analysis-related React Query caches
 * Covers reachability, traceroute, and route policy analysis
 */
export const analysisKeys = {
  all: ['analysis'] as const,
  reachability: (request?: ReachabilityRequest) => [...analysisKeys.all, 'reachability', request] as const,
  routePolicies: (snapshotName: string | null, params?: { nodes?: string; action?: string }) =>
    [...analysisKeys.all, snapshotSegment(snapshotName), 'route-policies', params] as const,
  traceroute: (request?: TracerouteRequest) => [...analysisKeys.all, 'traceroute', request] as const,
  bidirectionalTraceroute: (request?: TracerouteRequest) =>
    [...analysisKeys.all, 'bidirectional-traceroute', request] as const,
}

/**
 * Mutation to compute network reachability
 * Analyzes end-to-end connectivity between source and destination
 */
export function useReachability() {
  return useMutation({
    mutationFn: (request?: ReachabilityRequest) => analysisAPI.getReachability(request),
  })
}

/**
 * Query route policies (route-maps) across devices
 * Returns route-map configurations and policy details
 */
export function useRoutePolicies(params?: { nodes?: string; action?: string }, enabled = true) {
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)

  return useQuery({
    queryKey: analysisKeys.routePolicies(currentSnapshotName, params),
    queryFn: () => analysisAPI.getRoutePolicies(params),
    enabled: enabled && !!currentSnapshotName,
    staleTime: 60000,
  })
}

/**
 * Mutation to compute unidirectional traceroute
 * Simulates packet path from source to destination
 */
export function useTraceroute() {
  return useMutation<TracerouteResponse[], AxiosError, TracerouteRequest | undefined>({
    mutationFn: async (request) => (await analysisAPI.traceroute(request)) ?? [],
    retry: (failureCount, error) => {
      if (error?.response?.status && error.response.status >= 500 && failureCount < 2) return true
      return false
    },
  })
}

/**
 * Mutation to compute bidirectional traceroute
 * Simulates packet path in both forward and reverse directions
 */
export function useBidirectionalTraceroute() {
  return useMutation<BidirectionalTracerouteResponse[], AxiosError, TracerouteRequest | undefined>({
    mutationFn: async (request) => (await analysisAPI.bidirectionalTraceroute(request)) ?? [],
    retry: (failureCount, error) => {
      if (error?.response?.status && error.response.status >= 500 && failureCount < 2) return true
      return false
    },
  })
}
