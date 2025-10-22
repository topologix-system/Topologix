/**
 * OSPF protocol type definitions
 * Process configuration, area settings, interface config, session status, and adjacencies
 */
export interface OSPFProcessConfig {
  node: string
  vrf: string
  process_id: number
  areas: string[]
  reference_bandwidth?: number
  router_id?: string
  export_policy_sources: string[]
  area_border_router: boolean
}

export interface OSPFAreaConfig {
  node: string
  vrf: string
  process_id: number
  area: string
  area_type: string
  active_interfaces: string[]
  passive_interfaces: string[]
}

export interface OSPFInterfaceConfig {
  interface: string
  vrf: string
  process_id: number
  ospf_area_name: string
  ospf_enabled: boolean
  ospf_passive: boolean
  ospf_cost?: number
  ospf_network_type?: string
  ospf_hello_interval?: number
  ospf_dead_interval?: number
}

export interface OSPFSessionCompat {
  interface: string
  vrf: string
  ip: string
  area: string
  remote_interface: string
  remote_vrf: string
  remote_ip: string
  remote_area: string
  session_status: string
}

export interface OSPFEdge {
  interface: string
  remote_interface: string
  ip: string
  remote_ip: string
}