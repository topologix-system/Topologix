/**
 * TypeScript type definitions for snapshot comparison feature
 * Defines data structures for comparing network configurations between snapshots
 */

/**
 * Request payload for snapshot comparison
 */
export interface CompareSnapshotsRequest {
  base_snapshot: string
  comparison_snapshot: string
}

/**
 * Complete comparison result from backend
 */
export interface ComparisonResult {
  base_snapshot: string
  comparison_snapshot: string
  nodes: NodesDiff
  edges: EdgesDiff
  routes: RoutesDiff
  reachability: ReachabilityDiff[]
}

/**
 * Node comparison results showing additions and removals
 */
export interface NodesDiff {
  added: string[]
  removed: string[]
  total_base: number
  total_comparison: number
}

/**
 * Edge (topology) comparison results
 */
export interface EdgesDiff {
  added: EdgeInfo[]
  removed: EdgeInfo[]
  total_base: number
  total_comparison: number
}

/**
 * Individual edge information
 */
export interface EdgeInfo {
  source: string
  target: string
  source_interface?: string
  target_interface?: string
  [key: string]: any
}

/**
 * Routing table comparison results
 */
export interface RoutesDiff {
  added: RouteInfo[]
  removed: RouteInfo[]
  modified: ModifiedRoute[]
  total_base: number
  total_comparison: number
}

/**
 * Individual route information
 */
export interface RouteInfo {
  node: string
  vrf: string
  network: string
  next_hop?: string
  protocol?: string
  [key: string]: any
}

/**
 * Modified route showing before/after values
 */
export interface ModifiedRoute {
  network: string
  node: string
  vrf: string
  base_next_hop?: string
  comparison_next_hop?: string
  base_protocol?: string
  comparison_protocol?: string
}

/**
 * Reachability comparison result (differential reachability from Batfish)
 */
export interface ReachabilityDiff {
  flow: any
  base_traces: any[]
  delta_traces: any[]
  change: string
}

/**
 * Summary statistics for comparison results
 */
export interface ComparisonSummary {
  nodes_added: number
  nodes_removed: number
  edges_added: number
  edges_removed: number
  routes_added: number
  routes_removed: number
  routes_modified: number
  reachability_changes: number
}
