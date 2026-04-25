/**
 * Reachability analysis type definitions
 * Flow traces, packet headers, hop details, and end-to-end connectivity testing
 */
export interface FlowTrace {
  flow: string
  traces: any[]
  trace_count: number
}

export interface ReachabilityTrace {
  source_node: string
  destination_node: string
  flow: string
  hops: Array<Record<string, any>>
  status: string
  disposition: string
}

export interface TracerouteRequest {
  headers?: {
    srcIps?: string
    dstIps?: string
    ipProtocols?: string[]
    srcPorts?: string
    dstPorts?: string
    applications?: string[]
    icmpTypes?: number[]
    icmpCodes?: number[]
    dscps?: number[]
    ecns?: number[]
    packetLengths?: string
  }
  /** Ingress device/interface where the trace starts (Batfish query param) */
  startLocation?: string
  maxTraces?: number
  ignoreFilters?: boolean
}

export interface TracerouteFlow {
  srcIp?: string
  dstIp?: string
  ipProtocol?: string
  srcPort?: number
  dstPort?: number
  icmpType?: number
  icmpCode?: number
  dscp?: number
  ecn?: number
  packetLength?: number
  [key: string]: any
}

export interface TraceStep {
  detail: string
  action: string
  [key: string]: any
}

export interface TraceHop {
  node: string
  steps: TraceStep[]
  [key: string]: any
}

export interface Trace {
  disposition: string
  hops: TraceHop[]
  [key: string]: any
}

export interface TracerouteResponse {
  flow: TracerouteFlow | string
  traces: Trace[] | string[]
}

export interface BidirectionalTracerouteResponse {
  flow: TracerouteFlow | string
  forward_traces: Trace[] | string[]
  reverse_flow: TracerouteFlow | string
  reverse_traces: Trace[] | string[]
}

export interface FilterLineReachability {
  node: string
  filter: string
  sources: string | string[] | null
  unreachable_line: string
  unreachable_line_action: string
  action: string
  blocking_lines: string[]
  different_action: boolean
  reason: string
  additional_info: string
  line: number | null
  destinations?: string
}

export interface FilterApplication {
  interface_name: string
  direction: 'inbound' | 'outbound'
  zone: string | null
  primary_address: string | null
}

export interface AddressOwnership {
  address: string
  match_type: 'exact' | 'cidr_contains'
  owner_node: string
  owner_interface: string
  owner_vrf: string
}

export interface EnrichedFilterEntry {
  node: string
  filter: string
  action: string
  line: number | null
  unreachable_line: string
  unreachable_line_action: string
  blocking_lines: string[]
  different_action: boolean
  reason: string
  additional_info: string
  sources: string | string[] | null
  applied_to: FilterApplication[]
  referenced_addresses: string[]
  address_owners: AddressOwnership[]
}

export interface FilterGroup {
  filter_name: string
  node: string
  applied_to: FilterApplication[]
  severity: 'low' | 'high'
  action_breakdown: { deny: number; permit: number; other: number }
  entries: EnrichedFilterEntry[]
}
