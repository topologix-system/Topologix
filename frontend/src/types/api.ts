/**
 * API request/response type definitions
 * Defines data structures for HTTP API communication with backend
 * Includes APIResponse wrapper, network initialization, and comprehensive data aggregation types
 */
import {
  NodeProperties,
  InterfaceProperties,
  Route,
} from './network'
import { OSPFProcessConfig, OSPFAreaConfig, OSPFInterfaceConfig, OSPFSessionCompat, OSPFEdge } from './ospf'
import { PhysicalEdge, Layer1Edge, Layer3Edge, BGPEdge, VXLANEdge, EIGRPEdge, ISISEdge, IPsecEdge } from './edges'
import { BGPPeerConfiguration, BGPProcessConfiguration, BGPSessionStatus, BGPSessionCompatibility, BGPRib } from './bgp'
import { SwitchedVlanProperties } from './vlan'
import { IPOwner } from './ip'
import { DefinedStructure, ReferencedStructure, NamedStructure } from './structures'
import { FileParseStatus, InitIssue, ParseWarning, ViConversionStatus } from './validation'
import { FlowTrace } from './reachability'
import { RoutePolicy, AAAAuthenticationLogin } from './policy'

export interface APIResponse<T> {
  status: 'success' | 'error'
  message: string
  data?: T
}

export interface NetworkInitializeRequest {
  snapshot_dir: string
}

export interface NetworkInitializeResponse {
  status: string
  network: string
  snapshot: string
  file_parse_status: FileParseStatus[]
  init_issues: InitIssue[]
  parse_warnings: ParseWarning[]
  initialization_result: Record<string, unknown>
}

export interface AllNetworkData {
  node_properties: NodeProperties[]
  interface_properties: InterfaceProperties[]
  routes: Route[]
  ospf_process_configuration: OSPFProcessConfig[]
  ospf_area_configuration: OSPFAreaConfig[]
  ospf_interface_configuration: OSPFInterfaceConfig[]
  ospf_session_compatibility: OSPFSessionCompat[]
  ospf_edges: OSPFEdge[]
  bgp_edges: BGPEdge[]
  bgp_peer_configuration: BGPPeerConfiguration[]
  bgp_process_configuration: BGPProcessConfiguration[]
  bgp_session_status: BGPSessionStatus[]
  bgp_session_compatibility: BGPSessionCompatibility[]
  bgp_rib: BGPRib[]
  edges: PhysicalEdge[]
  layer1_edges: Layer1Edge[]
  layer3_edges: Layer3Edge[]
  vxlan_edges: VXLANEdge[]
  eigrp_edges: EIGRPEdge[]
  isis_edges: ISISEdge[]
  ipsec_edges: IPsecEdge[]
  switched_vlan_properties: SwitchedVlanProperties[]
  ip_owners: IPOwner[]
  defined_structures: DefinedStructure[]
  referenced_structures: ReferencedStructure[]
  named_structures: NamedStructure[]
  file_parse_status: FileParseStatus[]
  init_issues: InitIssue[]
  parse_warnings: ParseWarning[]
  vi_conversion_status: ViConversionStatus[]
  reachability: FlowTrace[]
  search_route_policies: RoutePolicy[]
  aaa_authentication_login: AAAAuthenticationLogin[]
}

export interface ReachabilityRequest {
  headers?: {
    srcIps?: string
    dstIps?: string
    [key: string]: string | undefined
  }
}

export interface User {
  id: number
  username: string
  email: string
  full_name?: string
  is_active: boolean
  is_superuser: boolean
  email_verified: boolean
  created_at: string
  last_login_at?: string
  roles: string[]
}

export interface RegisterRequest {
  username: string
  email: string
  password: string
  full_name?: string
}

export interface UpdateUserRequest {
  email?: string
  full_name?: string
  roles?: string[]
  is_active?: boolean
}

export interface ChangePasswordRequest {
  current_password: string
  new_password: string
}

export interface PasswordResetRequestRequest {
  email: string
}

export interface PasswordResetRequest {
  token: string
  new_password: string
}

export interface SecurityLog {
  id: number
  ip_address: string
  username: string | null
  attempt_time: string
  success: boolean
  user_agent: string | null
}

export interface SecurityLogsQueryParams {
  page?: number
  per_page?: number
  ip_address?: string
  username?: string
  success?: boolean
  start_date?: string
  end_date?: string
  sort?: 'asc' | 'desc'
}

export interface PaginatedSecurityLogsResponse {
  logs: SecurityLog[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

export interface SecurityStats {
  total_attempts: number
  failed_attempts: number
  success_rate: number
  unique_ips: number
  blocked_ips: number
  most_targeted_accounts: Array<{ username: string; count: number }>
  recent_24h: {
    total: number
    failed: number
  }
  recent_7d: {
    total: number
    failed: number
  }
}