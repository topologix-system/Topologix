/**
 * BGP protocol type definitions
 * Peer configuration, process config, session status, compatibility, and RIB (Routing Information Base)
 */
export interface BGPPeerConfiguration {
  node: string
  vrf: string
  local_as: number | null
  local_ip: string
  local_interface: string | null
  confederation: number | null
  remote_as: number | null
  remote_ip: string
  description: string
  ebgp_multihop: boolean
  peer_group: string
  import_policy: string[]
  export_policy: string[]
  send_community: boolean
  route_reflector_client: boolean
  cluster_id: number | null
  shutdown: boolean
  passive: boolean
}

export interface BGPProcessConfiguration {
  node: string
  vrf: string
  router_id: string
  confederation_id: number | null
  confederation_members: number[]
  multipath_equivalent_as_path_match_mode: string
  multipath_ebgp: boolean
  multipath_ibgp: boolean
  neighbors: string[]
  tie_breaker: string
}

export interface BGPSessionStatus {
  node: string
  vrf: string
  local_as: number | null
  local_interface: string | null
  local_ip: string
  remote_as: number | null
  remote_node: string
  remote_ip: string
  address_families: string[]
  session_type: string
  established_status: string
}

export interface BGPSessionCompatibility {
  node: string
  vrf: string
  local_as: number | null
  local_interface: string | null
  local_ip: string
  remote_as: number | null
  remote_node: string
  remote_ip: string
  address_families: string[]
  session_type: string
  configured_status: string
}

export interface BGPRib {
  node: string
  vrf: string
  network: string
  next_hop_ip: string
  protocol: string
  as_path: number[]
  local_preference: number | null
  med: number | null
  origin_protocol: string
  origin_type: string
  originator_id: string
  received_from_ip: string
  tag: number | null
  weight: number | null
  communities: string[]
  cluster_list: string[]
}
