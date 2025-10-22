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
  startLocation?: string
  pathConstraints?: {
    startLocation?: string
    endLocation?: string
    transitLocations?: string
    forbiddenLocations?: string
  }
  maxTraces?: number
  ignoreFilters?: boolean
  actions?: string[]
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