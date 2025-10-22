/**
 * Network topology core type definitions
 * Node properties, interface details, routing tables, and IP ownership
 * Used throughout the application for network device modeling
 */
import { NodeType } from './enums'

export interface InterfaceDetail {
  name: string
  admin_up: boolean
  active: boolean
  description?: string
  speed?: number
  mtu: number
  vlan?: number
  allowed_vlans: number[]
  primary_address?: string
  bandwidth?: number
  inactive_reason?: string
}

export interface VLANInfo {
  id: number
  name?: string
  interfaces_count: number
  interfaces: string[]
  vxlan_vni?: number
}

export interface RouteEntry {
  network: string
  next_hop: string
  next_hop_ip?: string
  next_hop_interface?: string
  protocol: string
  metric?: number
  admin_distance?: number
  tag?: number
}

export interface NetworkNode {
  id: string
  name: string
  type: NodeType
  platform: string
  hostname?: string
  interfaces: InterfaceDetail[]
  vlans: VLANInfo[]
  routes: Record<string, number>
  ip_addresses: string[]
  protocols: Record<string, any>
  health_status: string
  config_issues: string[]

  configuration_format?: string
  dns_servers: string[]
  domain_name?: string
  ntp_servers: string[]
  logging_servers: string[]
  snmp_trap_servers: string[]
  tacacs_servers: string[]
  vrfs: string[]
  zones: string[]
}

export interface NetworkEdge {
  source: string
  target: string
  source_port: string
  target_port: string
  source_ip?: string
  target_ip?: string
  protocol?: string
  bandwidth?: number
  utilization?: number
}

export interface NodeProperties {
  node: string
  configuration_format?: string
  dns_servers: string[]
  dns_source_interface?: string
  domain_name?: string
  hostname: string
  ipsec_vpns: string[]
  interfaces: string[]
  logging_servers: string[]
  logging_source_interface?: string
  ntp_servers: string[]
  ntp_source_interface?: string
  snmp_source_interface?: string
  snmp_trap_servers: string[]
  tacacs_servers: string[]
  tacacs_source_interface?: string
  vendor: string
  vrfs: string[]
  zones: string[]
}

export interface InterfaceProperties {
  interface: string
  access_vlan?: number
  active: boolean
  admin_up: boolean
  all_prefixes: string[]
  allowed_vlans: string
  auto_state_vlan: boolean
  bandwidth?: number
  blacklisted: boolean
  channel_group?: string
  channel_group_members: string[]
  declared_names: string[]
  description: string
  encapsulation_vlan?: number
  hsrp_groups: any[]
  hsrp_version?: string
  incoming_filter_name?: string
  interface_type: string
  mtu: number
  native_vlan?: number
  ospf_area_name?: string
  ospf_cost?: number
  ospf_enabled: boolean
  ospf_network_type?: string
  ospf_passive: boolean
  outgoing_filter_name?: string
  primary_address?: string
  primary_network?: string
  proxy_arp: boolean
  rip_enabled: boolean
  rip_passive: boolean
  speed?: number
  switchport: boolean
  switchport_mode: string
  switchport_trunk_encapsulation: string
  vlan?: number
  vrf: string
  zone?: string
}

export interface Route {
  node: string
  vrf: string
  network: string
  next_hop: string
  next_hop_ip?: string
  next_hop_interface?: string
  protocol: string
  metric?: number
  admin_distance?: number
  tag?: number
}