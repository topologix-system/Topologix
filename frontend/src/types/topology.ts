/**
 * Topology analysis type definitions
 * Layer 1/2 edges, VXLAN VNI properties, IPsec VPN, interface MTU, and IP space assignments
 */
export interface IPSecSessionStatus {
  node: string
  vpn: string
  remote_node: string
  remote_ip: string
  local_ip: string
  status: string
  tunnel_interfaces: string[]
}

/** @deprecated Use IPsecEdge from './edges' instead (standardized RFC 6071 casing) */
export type IPSecEdge = import('./edges').IPsecEdge

export interface IPSecPeerConfiguration {
  [key: string]: any
}

export interface BFDSessionStatus {
  [key: string]: any
}

export interface Layer2Topology {
  [key: string]: any
}

export interface VIModel {
  [key: string]: any
}
