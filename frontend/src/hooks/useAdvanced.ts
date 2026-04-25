/**
 * React Query hooks for advanced features
 * Handles F5 BIG-IP VIPs, vendor-independent model queries, and custom analyses
 */
import { useQuery, useMutation } from '@tanstack/react-query'
import { advancedAPI } from '../services/api'

/**
 * Query key factory for advanced features-related React Query caches
 * Covers F5 BIG-IP load balancers and vendor-independent models
 */
export const advancedKeys = {
  all: ['advanced'] as const,
  f5vips: () => [...advancedKeys.all, 'f5-vips'] as const,
  viModel: () => [...advancedKeys.all, 'vi-model'] as const,
}

/**
 * Query F5 BIG-IP Virtual IPs (VIPs)
 * Returns load balancer VIP configurations from F5 devices
 * Used for load balancer analysis and troubleshooting
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useF5VIPs(enabled = true) {
  return useQuery({
    queryKey: advancedKeys.f5vips(),
    queryFn: () => advancedAPI.getF5VIPs(),
    enabled,
    staleTime: 60000,
  })
}

/**
 * Query vendor-independent (VI) configuration model
 * Returns Batfish's normalized device model across all vendors
 * Advanced feature for deep config analysis
 * @param enabled - Optional flag to conditionally enable query (default: true)
 */
export function useVIModel(enabled = true) {
  return useQuery({
    queryKey: advancedKeys.viModel(),
    queryFn: () => advancedAPI.getVIModel(),
    enabled,
    staleTime: 60000,
  })
}

/**
 * Mutation to test route policy behavior
 * Simulates route-map/policy application in specified direction
 * Used for policy validation and troubleshooting
 */
export function useTestRoutePolicies() {
  return useMutation({
    mutationFn: (request: {
      direction: string
      inputRoutes: object | object[]
      nodes?: string | string[]
      policies?: string | string[]
      bgpSessionProperties?: object
    }) =>
      advancedAPI.testRoutePolicies(request),
  })
}

/**
 * Mutation to search for route policies across devices
 * Finds route-maps/policies matching action criteria (permit/deny)
 * Supports filtering by specific nodes
 */
export function useSearchRoutePolicies() {
  return useMutation({
    mutationFn: (request?: {
      action?: string
      nodes?: string | string[]
      policies?: string | string[]
      inputConstraints?: object
      outputConstraints?: object
      perPath?: boolean
      pathOption?: string
    }) =>
      advancedAPI.searchRoutePolicies(request),
  })
}

/**
 * Mutation to resolve location specifiers into concrete Batfish locations.
 */
export function useResolveLocationSpecifier() {
  return useMutation({
    mutationFn: (request?: { locations?: string; grammarVersion?: string }) =>
      advancedAPI.resolveLocationSpecifier(request),
  })
}

/**
 * Mutation to resolve IP specifiers into concrete IPs.
 */
export function useResolveIpSpecifier() {
  return useMutation({
    mutationFn: (request?: { ips?: string; grammarVersion?: string }) =>
      advancedAPI.resolveIpSpecifier(request),
  })
}

/**
 * Mutation to resolve location specifiers into source IP spaces.
 */
export function useResolveIpsOfLocationSpecifier() {
  return useMutation({
    mutationFn: (request: { locations: string; grammarVersion?: string }) =>
      advancedAPI.resolveIpsOfLocationSpecifier(request),
  })
}

/**
 * Mutation for bidirectional reachability.
 */
export function useBidirectionalReachability() {
  return useMutation({
    mutationFn: (request: { headers: object; pathConstraints?: object; returnFlowType?: string }) =>
      advancedAPI.bidirectionalReachability(request),
  })
}

/**
 * Mutation to query A10 virtual server configuration.
 */
export function useA10VirtualServerConfiguration() {
  return useMutation({
    mutationFn: (request?: { nodes?: string | string[]; virtualServerIps?: string }) =>
      advancedAPI.getA10VirtualServerConfiguration(request),
  })
}

/**
 * Mutation to run transfer BDD validation for route policies.
 */
export function useTransferBDDValidation() {
  return useMutation({
    mutationFn: (request?: {
      nodes?: string | string[]
      policies?: string | string[]
      retainAllPaths?: boolean
      seed?: number | string
    }) =>
      advancedAPI.transferBDDValidation(request),
  })
}

/**
 * Mutation to compare peer group policies.
 */
export function useComparePeerGroupPolicies() {
  return useMutation({
    mutationFn: (request: { reference_snapshot: string; snapshot?: string }) =>
      advancedAPI.comparePeerGroupPolicies(request),
  })
}

/**
 * Mutation to compare route policy symbolic behavior.
 */
export function useCompareRoutePolicies() {
  return useMutation({
    mutationFn: (request: {
      policy: string
      referencePolicy: string
      reference_snapshot: string
      snapshot?: string
      nodes?: string | string[]
    }) =>
      advancedAPI.compareRoutePolicies(request),
  })
}

/**
 * Mutation to analyze filter/ACL line reachability
 * Identifies unreachable ACL lines (shadowed by earlier entries)
 * Helps optimize ACL configurations
 */
export function useFilterLineReachability() {
  return useMutation({
    mutationFn: (request?: { filters?: string; nodes?: string[]; ignoreComposites?: boolean }) =>
      advancedAPI.getFilterLineReachability(request),
  })
}

/**
 * Mutation to test filter/ACL behavior
 * Simulates packet matching against specified filters
 * Used for ACL validation and troubleshooting
 */
export function useTestFilters() {
  return useMutation({
    mutationFn: (request: { headers: object; filters?: string; nodes?: string[]; startLocation?: string }) =>
      advancedAPI.testFilters(request),
  })
}

/**
 * Mutation to find ACL lines matching packet headers
 * Returns which filter lines would match specified packet characteristics
 * Detailed ACL analysis for specific traffic patterns
 */
export function useFindMatchingFilterLines() {
  return useMutation({
    mutationFn: (request: { headers: object; filters?: string; nodes?: string[] }) =>
      advancedAPI.findMatchingFilterLines(request),
  })
}

/**
 * Mutation to search filters/ACLs by action
 * Finds ACLs with specific permit/deny actions across devices
 * Supports filtering by specific nodes
 */
export function useSearchFilters() {
  return useMutation({
    mutationFn: (request?: { action?: string; filters?: string; nodes?: string[] }) =>
      advancedAPI.searchFilters(request),
  })
}

/**
 * Mutation to compute reduced reachability with path constraints
 * Analyzes reachability while respecting specified constraints
 * Advanced reachability analysis for complex scenarios
 */
export function useReduceReachability() {
  return useMutation({
    mutationFn: (request?: {
      headers?: object
      pathConstraints?: object
      actions?: string | string[]
      maxTraces?: number
      invertSearch?: boolean
      ignoreFilters?: boolean
    }) =>
      advancedAPI.reduceReachability(request),
  })
}
