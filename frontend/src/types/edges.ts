/**
 * Network edge/connection type definitions
 * Physical, layer 3, and protocol adjacency edges (OSPF, BGP, VXLAN, EIGRP, IS-IS, IPsec)
 * Core data structures for topology graph visualization
 */
export interface PhysicalEdge {
  interface: string
  remote_interface: string
}

export interface Layer1Edge {
  interface: string
  remote_interface: string
}

export interface Layer3Edge {
  interface: string
  remote_interface: string
  ips: string[]
  remote_ips: string[]
}

export interface BGPEdge {
  node: string
  interface: string | null
  remote_node: string
  remote_interface: string | null
  remote_ip: string
  local_ip: string
  remote_asn: string
  local_asn: string
  import_policy: string[]
  export_policy: string[]
}

export interface VXLANEdge {
  node: string
  vni: number
  vtep_address: string
  remote_node: string
  remote_vtep_address: string
  multicast_group: string
}

export interface EIGRPEdge {
  interface: string
  remote_interface: string
  ip: string
  remote_ip: string
}

export interface ISISEdge {
  interface: string
  remote_interface: string
  level: string
}

export interface IPsecEdge {
  node: string
  remote_node: string
  local_interface: string
  remote_interface: string
  tunnel_interfaces: string[]
}