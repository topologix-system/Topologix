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

export interface IPSecEdge {
  node: string
  remote_node: string
  local_interface: string
  remote_interface: string
  tunnel_interfaces: string[]
}

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
