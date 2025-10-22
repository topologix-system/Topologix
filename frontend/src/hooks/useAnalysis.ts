/**
 * React Query hooks for network analysis and reachability testing
 * Handles reachability queries, traceroute, route policies, and forwarding analysis
 */
import { useQuery, useMutation } from '@tanstack/react-query'
import { analysisAPI } from '../services/api'
import type { ReachabilityRequest, TracerouteRequest } from '../types'

/**
 * Query key factory for network analysis-related React Query caches
 * Covers reachability, traceroute, and route policy analysis
 */
export const analysisKeys = {
  all: ['analysis'] as const,
  reachability: (request?: ReachabilityRequest) => [...analysisKeys.all, 'reachability', request] as const,
  routePolicies: (params?: { nodes?: string; action?: string }) =>
    [...analysisKeys.all, 'route-policies', params] as const,
  traceroute: (request?: TracerouteRequest) => [...analysisKeys.all, 'traceroute', request] as const,
  bidirectionalTraceroute: (request?: TracerouteRequest) =>
    [...analysisKeys.all, 'bidirectional-traceroute', request] as const,
}

/**
 * Mutation to compute network reachability
 * Analyzes end-to-end connectivity between source and destination
 * Returns permitted/denied flows and path details
 * Used in TraceroutePanel for reachability analysis
 */
export function useReachability() {
  return useMutation({
    mutationFn: (request?: ReachabilityRequest) => analysisAPI.getReachability(request),
  })
}

/**
 * Query route policies (route-maps) across devices
 * Returns route-map configurations and policy details
 * Supports filtering by nodes and action (permit/deny)
 * @param params - Optional filter parameters (nodes, action)
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useRoutePolicies(params?: { nodes?: string; action?: string }, enabled = true) {
  return useQuery({
    queryKey: analysisKeys.routePolicies(params),
    queryFn: () => analysisAPI.getRoutePolicies(params),
    enabled,
    staleTime: 60000,
  })
}

/**
 * Mutation to compute unidirectional traceroute
 * Simulates packet path from source to destination
 * Returns hop-by-hop path with forwarding decisions
 * Used in TraceroutePanel for path analysis
 */
export function useTraceroute() {
  return useMutation({
    mutationFn: (request?: TracerouteRequest) => analysisAPI.traceroute(request),
  })
}

/**
 * Mutation to compute bidirectional traceroute
 * Simulates packet path in both forward and reverse directions
 * Validates symmetric routing and return path reachability
 * Used in TraceroutePanel for comprehensive path analysis
 */
export function useBidirectionalTraceroute() {
  return useMutation({
    mutationFn: (request?: TracerouteRequest) => analysisAPI.bidirectionalTraceroute(request),
  })
}