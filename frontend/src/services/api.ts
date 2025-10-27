/**
 * Main API client for Topologix backend communication
 * - Configures axios with authentication, CSRF protection, and rate limiting
 * - Implements automatic token refresh on 401 errors with interceptors
 * - Provides typed API methods for all network analysis endpoints (Batfish integration)
 * - Handles environment/runtime-based auth enable/disable configuration
 * - Role-based access control with hasRole() and hasPermission() helpers
 */
import axios, { AxiosInstance, AxiosError, AxiosRequestConfig } from 'axios'
import { runtimeConfig } from '../config/runtimeConfig'
import type {
  APIResponse,
  NetworkInitializeRequest,
  NetworkInitializeResponse,
  AllNetworkData,
  NodeProperties,
  InterfaceProperties,
  Route,
  OSPFProcessConfig,
  OSPFAreaConfig,
  OSPFInterfaceConfig,
  OSPFSessionCompat,
  OSPFEdge,
  PhysicalEdge,
  Layer1Edge,
  Layer3Edge,
  SwitchedVlanProperties,
  IPOwner,
  DefinedStructure,
  ReferencedStructure,
  NamedStructure,
  FileParseStatus,
  InitIssue,
  ParseWarning,
  ViConversionStatus,
  DuplicateRouterID,
  FlowTrace,
  RoutePolicy,
  AAAAuthenticationLogin,
  ReachabilityRequest,
  Snapshot,
  SnapshotFile,
  CreateSnapshotRequest,
  IPSecSessionStatus,
  IPSecEdge,
  IPSecPeerConfiguration,
  BFDSessionStatus,
  Layer2Topology,
  VIModel,
  TracerouteRequest,
  TracerouteResponse,
  BidirectionalTracerouteResponse,
  BGPEdge,
  BGPPeerConfiguration,
  BGPProcessConfiguration,
  BGPSessionStatus,
  BGPSessionCompatibility,
  BGPRib,
  User,
  RegisterRequest,
  UpdateUserRequest,
  ChangePasswordRequest,
} from '../types'

const API_BASE_URL = runtimeConfig.apiBaseUrl || ''
const AUTH_ENABLED = runtimeConfig.authEnabled

interface AuthState {
  accessToken: string | null
  refreshToken: string | null
  csrfToken: string | null
  user: {
    username: string
    roles: string[]
    email: string
  } | null
}

let authState: AuthState = {
  accessToken: null,
  refreshToken: null,
  csrfToken: null,
  user: null
}

if (AUTH_ENABLED) {
  authState = {
    accessToken: localStorage.getItem('access_token'),
    refreshToken: localStorage.getItem('refresh_token'),
    csrfToken: sessionStorage.getItem('csrf_token'),
    user: null
  }

  const storedUser = localStorage.getItem('user')
  if (storedUser) {
    try {
      authState.user = JSON.parse(storedUser)
    } catch (e) {
      console.error('Failed to parse stored user data')
    }
  }
}

const apiClient: AxiosInstance = axios.create({
  baseURL: `${API_BASE_URL}/api`,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
    ...(AUTH_ENABLED ? {} : {
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Pragma': 'no-cache',
    })
  },
  ...(AUTH_ENABLED ? { withCredentials: true } : {}),
})

if (AUTH_ENABLED) {
  apiClient.interceptors.request.use(
    (config) => {
      if (authState.accessToken) {
        config.headers['Authorization'] = `Bearer ${authState.accessToken}`
      }

      if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(config.method?.toUpperCase() || '')) {
        if (authState.csrfToken) {
          config.headers['X-CSRF-Token'] = authState.csrfToken
        }
      }

      return config
    },
    (error) => {
      return Promise.reject(error)
    }
  )
}

apiClient.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    if (AUTH_ENABLED) {
      const originalRequest = error.config as AxiosRequestConfig & { _retry?: boolean }

      if (error.response?.status === 401 && !originalRequest._retry) {
        originalRequest._retry = true

        if (authState.refreshToken) {
          try {
            const refreshResponse = await axios.post(
              `${API_BASE_URL}/api/auth/refresh`,
              { refresh_token: authState.refreshToken }
            )

            const { access_token } = refreshResponse.data.data
            authState.accessToken = access_token
            localStorage.setItem('access_token', access_token)

            if (originalRequest.headers) {
              originalRequest.headers['Authorization'] = `Bearer ${access_token}`
            }
            return apiClient(originalRequest)
          } catch (refreshError) {
            authAPI.logout()
            window.location.href = '/login'
            return Promise.reject(refreshError)
          }
        } else {
          window.location.href = '/login'
        }
      }

      if (error.response?.status === 403) {
        const errorData = error.response.data as any
        if (errorData?.message?.includes('CSRF')) {
          try {
            const csrfResponse = await apiClient.get('/auth/csrf-token')
            authState.csrfToken = csrfResponse.data.data.csrf_token
            sessionStorage.setItem('csrf_token', authState.csrfToken)

            if (originalRequest.headers) {
              originalRequest.headers['X-CSRF-Token'] = authState.csrfToken
            }
            return apiClient(originalRequest)
          } catch (csrfError) {
            console.error('Failed to refresh CSRF token')
          }
        } else {
          console.error('Permission denied:', errorData?.message)
        }
      }

      if (error.response?.status === 429) {
        const retryAfter = error.response.headers['retry-after']
        console.error(`Rate limit exceeded. Retry after ${retryAfter} seconds`)
      }
    }

    if (error.response) {
      console.error('API Error:', error.response.status, error.response.data)
    } else if (error.request) {
      console.error('Network Error: No response from server')
    } else {
      console.error('Request Error:', error.message)
    }

    return Promise.reject(error)
  }
)

/**
 * Authentication and authorization API methods
 * Handles login, logout, token refresh, CSRF token management, and password reset
 * Only enabled when VITE_AUTH_ENABLED=true in environment
 * Manages JWT access/refresh tokens and CSRF protection
 */
export const authAPI = {
  async login(username: string, password: string) {
    if (!AUTH_ENABLED) {
      throw new Error('Authentication is not enabled')
    }

    const response = await axios.post<APIResponse<{
      access_token: string
      refresh_token: string
      token_type: string
      expires_in: number
      user: { username: string; roles: string[]; email: string }
      csrf_token: string
    }>>(`${API_BASE_URL}/api/auth/login`, { username, password })

    const data = response.data.data

    authState.accessToken = data.access_token
    authState.refreshToken = data.refresh_token
    authState.csrfToken = data.csrf_token
    authState.user = data.user

    localStorage.setItem('access_token', data.access_token)
    localStorage.setItem('refresh_token', data.refresh_token)
    localStorage.setItem('user', JSON.stringify(data.user))
    sessionStorage.setItem('csrf_token', data.csrf_token)

    return data
  },

  async logout() {
    if (!AUTH_ENABLED) {
      return
    }

    try {
      await apiClient.post('/auth/logout')
    } catch (e) {
      console.error('Logout error:', e)
    } finally {
      authState.accessToken = null
      authState.refreshToken = null
      authState.csrfToken = null
      authState.user = null

      localStorage.removeItem('access_token')
      localStorage.removeItem('refresh_token')
      localStorage.removeItem('user')
      sessionStorage.removeItem('csrf_token')
    }
  },

  getCurrentUser() {
    return AUTH_ENABLED ? authState.user : null
  },

  isAuthenticated() {
    return AUTH_ENABLED ? !!authState.accessToken : true
  },

  hasRole(role: string) {
    if (!AUTH_ENABLED) {
      return true
    }
    return authState.user?.roles?.includes(role) || false
  },

  async refreshCSRFToken() {
    if (!AUTH_ENABLED) {
      throw new Error('Authentication is not enabled')
    }

    const response = await apiClient.get<APIResponse<{ csrf_token: string }>>('/auth/csrf-token')
    authState.csrfToken = response.data.data.csrf_token
    sessionStorage.setItem('csrf_token', authState.csrfToken)
    return authState.csrfToken
  },

  isAuthEnabled() {
    return AUTH_ENABLED
  },

  async requestPasswordReset(email: string) {
    if (!AUTH_ENABLED) {
      throw new Error('Authentication is not enabled')
    }

    const response = await axios.post<APIResponse<null>>(
      `${API_BASE_URL}/api/auth/password-reset-request`,
      { email }
    )
    return response.data
  },

  async resetPassword(token: string, new_password: string) {
    if (!AUTH_ENABLED) {
      throw new Error('Authentication is not enabled')
    }

    const response = await axios.post<APIResponse<null>>(
      `${API_BASE_URL}/api/auth/password-reset`,
      { token, new_password }
    )
    return response.data
  }
}

/**
 * Core network data API methods
 * Provides access to network topology, nodes, interfaces, routes, VLANs, and IP ownership
 * Primary source for Batfish network analysis data
 */
export const networkAPI = {
  async health() {
    const response = await apiClient.get<APIResponse<{ service: string; status: string }>>('/health')
    return response.data.data
  },

  async initializeNetwork(request: NetworkInitializeRequest) {
    const response = await apiClient.post<APIResponse<NetworkInitializeResponse>>(
      '/network/initialize',
      request
    )
    return response.data.data
  },

  async getAllData() {
    const response = await apiClient.get<APIResponse<AllNetworkData>>('/network/all-data')
    return response.data.data
  },

  async getNodes() {
    const response = await apiClient.get<APIResponse<NodeProperties[]>>('/network/nodes')
    return response.data.data
  },

  async getInterfaces() {
    const response = await apiClient.get<APIResponse<InterfaceProperties[]>>('/network/interfaces')
    return response.data.data
  },

  async getRoutes() {
    const response = await apiClient.get<APIResponse<Route[]>>('/network/routes')
    return response.data.data
  },

  async getVlans() {
    const response = await apiClient.get<APIResponse<SwitchedVlanProperties[]>>('/network/vlans')
    return response.data.data
  },

  async getIPOwners() {
    const response = await apiClient.get<APIResponse<IPOwner[]>>('/network/ip-owners')
    return response.data.data
  },
}

/**
 * OSPF protocol API methods
 * Provides access to OSPF processes, areas, interface configurations, and adjacency sessions
 * Used for OSPF topology analysis and troubleshooting
 */
export const ospfAPI = {
  async getProcesses() {
    const response = await apiClient.get<APIResponse<OSPFProcessConfig[]>>('/ospf/processes')
    return response.data.data
  },

  async getAreas() {
    const response = await apiClient.get<APIResponse<OSPFAreaConfig[]>>('/ospf/areas')
    return response.data.data
  },

  async getInterfaces() {
    const response = await apiClient.get<APIResponse<OSPFInterfaceConfig[]>>('/ospf/interfaces')
    return response.data.data
  },

  async getSessions() {
    const response = await apiClient.get<APIResponse<OSPFSessionCompat[]>>('/ospf/sessions')
    return response.data.data
  },
}

/**
 * Network edges API methods
 * Provides access to physical, layer 3, OSPF, and BGP connectivity edges
 * Core data for topology visualization with Cytoscape.js
 */
export const edgesAPI = {
  async getOSPFEdges() {
    const response = await apiClient.get<APIResponse<OSPFEdge[]>>('/edges/ospf')
    return response.data.data
  },

  async getPhysicalEdges() {
    const response = await apiClient.get<APIResponse<PhysicalEdge[]>>('/edges/physical')
    return response.data.data
  },

  async getLayer3Edges() {
    const response = await apiClient.get<APIResponse<Layer3Edge[]>>('/edges/layer3')
    return response.data.data
  },

  async getBGPEdges() {
    const response = await apiClient.get<APIResponse<BGPEdge[]>>('/bgp/edges')
    return response.data.data
  },
}

/**
 * BGP protocol API methods
 * Provides access to BGP edges, peer configuration, process config, session status, and RIB
 * Used for BGP topology analysis and routing table inspection
 */
export const bgpAPI = {
  async getEdges() {
    const response = await apiClient.get<APIResponse<BGPEdge[]>>('/bgp/edges')
    return response.data.data
  },

  async getPeerConfiguration() {
    const response = await apiClient.get<APIResponse<BGPPeerConfiguration[]>>('/bgp/peer-configuration')
    return response.data.data
  },

  async getProcessConfiguration() {
    const response = await apiClient.get<APIResponse<BGPProcessConfiguration[]>>('/bgp/process-configuration')
    return response.data.data
  },

  async getSessionStatus() {
    const response = await apiClient.get<APIResponse<BGPSessionStatus[]>>('/bgp/session-status')
    return response.data.data
  },

  async getSessionCompatibility() {
    const response = await apiClient.get<APIResponse<BGPSessionCompatibility[]>>('/bgp/session-compatibility')
    return response.data.data
  },

  async getRib() {
    const response = await apiClient.get<APIResponse<BGPRib[]>>('/bgp/rib')
    return response.data.data
  },
}

/**
 * Configuration structures API methods
 * Provides access to defined/referenced/named structures and AAA authentication config
 * Used for configuration analysis and cross-reference validation
 */
export const configAPI = {
  async getDefinedStructures() {
    const response = await apiClient.get<APIResponse<DefinedStructure[]>>('/config/defined-structures')
    return response.data.data
  },

  async getReferencedStructures() {
    const response = await apiClient.get<APIResponse<ReferencedStructure[]>>('/config/referenced-structures')
    return response.data.data
  },

  async getNamedStructures() {
    const response = await apiClient.get<APIResponse<NamedStructure[]>>('/config/named-structures')
    return response.data.data
  },

  async getAAAAuthentication() {
    const response = await apiClient.get<APIResponse<AAAAuthenticationLogin[]>>('/config/aaa-authentication')
    return response.data.data
  },
}

/**
 * Network validation API methods
 * Provides configuration parsing status, init issues, warnings, and network validation
 * Includes unused structures, undefined references, forwarding loops, and multipath consistency
 * Critical for identifying network configuration errors before deployment
 */
export const validationAPI = {
  async getFileParseStatus() {
    const response = await apiClient.get<APIResponse<FileParseStatus[]>>('/validation/file-parse-status')
    return response.data.data
  },

  async getInitIssues() {
    const response = await apiClient.get<APIResponse<InitIssue[]>>('/validation/init-issues')
    return response.data.data
  },

  async getParseWarnings() {
    const response = await apiClient.get<APIResponse<ParseWarning[]>>('/validation/parse-warnings')
    return response.data.data
  },

  async getVIConversionStatus() {
    const response = await apiClient.get<APIResponse<ViConversionStatus[]>>('/validation/vi-conversion-status')
    return response.data.data
  },

  async getUnusedStructures() {
    const response = await apiClient.get<APIResponse>('/validation/unused-structures')
    return response.data.data
  },

  async getUndefinedReferences() {
    const response = await apiClient.get<APIResponse>('/validation/undefined-references')
    return response.data.data
  },

  async getForwardingLoops() {
    const response = await apiClient.get<APIResponse>('/validation/detect-loops')
    return response.data.data
  },

  async getMultipathConsistency(request?: { protocol?: string }) {
    const response = await apiClient.post<APIResponse>('/validation/multipath-consistency', request || {})
    return response.data.data
  },

  async getSubnetMultipathConsistency(request?: { node?: string }) {
    const response = await apiClient.post<APIResponse>('/validation/subnet-multipath-consistency', request || {})
    return response.data.data
  },

  async getDifferentialReachability(request?: { reference_snapshot?: string }) {
    const response = await apiClient.post<APIResponse>('/validation/differential-reachability', request || {})
    return response.data.data
  },
}

/**
 * Network analysis API methods
 * Provides reachability analysis, route policies, traceroute, and bidirectional traceroute
 * Core functionality for end-to-end connectivity testing and path analysis
 */
export const analysisAPI = {
  async getReachability(request?: ReachabilityRequest) {
    const response = await apiClient.post<APIResponse<FlowTrace[]>>('/analysis/reachability', request)
    return response.data.data
  },

  async getRoutePolicies(params?: { nodes?: string; action?: string }) {
    const response = await apiClient.get<APIResponse<RoutePolicy[]>>('/analysis/route-policies', { params })
    return response.data.data
  },

  async traceroute(request?: TracerouteRequest) {
    const response = await apiClient.post<APIResponse<TracerouteResponse[]>>('/path/traceroute', request)
    return response.data.data
  },

  async bidirectionalTraceroute(request?: TracerouteRequest) {
    const response = await apiClient.post<APIResponse<BidirectionalTracerouteResponse[]>>('/path/bidirectional-traceroute', request)
    return response.data.data
  },
}

/**
 * Snapshot management API methods
 * Handles snapshot CRUD operations, file uploads, and snapshot activation
 * Snapshots contain network device configurations for Batfish analysis
 */
export const snapshotAPI = {
  async list() {
    const response = await apiClient.get<APIResponse<Snapshot[]>>('/snapshots')
    return response.data.data
  },

  async create(request: CreateSnapshotRequest) {
    const response = await apiClient.post<APIResponse<Snapshot>>('/snapshots', request)
    return response.data.data
  },

  async delete(name: string) {
    const response = await apiClient.delete<APIResponse<{ name: string }>>(`/snapshots/${name}`)
    return response.data.data
  },

  async getFiles(name: string) {
    const response = await apiClient.get<APIResponse<SnapshotFile[]>>(`/snapshots/${name}/files`)
    return response.data.data
  },

  async uploadFile(name: string, file: File) {
    const formData = new FormData()
    formData.append('file', file)

    const response = await apiClient.post<APIResponse<SnapshotFile>>(
      `/snapshots/${name}/files`,
      formData,
      {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      }
    )
    return response.data.data
  },

  async activate(name: string) {
    const response = await apiClient.post<APIResponse<NetworkInitializeResponse>>(
      `/snapshots/${name}/activate`
    )
    return response.data.data
  },
}

/**
 * High availability protocols API methods
 * Provides access to VRRP, HSRP, MLAG properties, duplicate router IDs, and switching
 * Used for HA configuration analysis and redundancy validation
 */
export const haAPI = {
  async getVRRPProperties() {
    const response = await apiClient.get<APIResponse>('/ha/vrrp-properties')
    return response.data.data
  },

  async getHSRPProperties() {
    const response = await apiClient.get<APIResponse>('/ha/hsrp-properties')
    return response.data.data
  },

  async getMLAGProperties() {
    const response = await apiClient.get<APIResponse>('/ha/mlag-properties')
    return response.data.data
  },

  async getDuplicateRouterIDs() {
    const response = await apiClient.get<APIResponse<DuplicateRouterID[]>>('/ha/duplicate-router-ids')
    return response.data.data
  },

  async getSwitchingProperties() {
    const response = await apiClient.get<APIResponse<SwitchedVlanProperties[]>>('/ha/switching-properties')
    return response.data.data
  },
}

/**
 * Additional routing protocols API methods
 * Provides EIGRP, IS-IS, and BFD protocol data
 * Covers edges, interface configurations, and session status
 */
export const protocolsAPI = {
  async getEIGRPEdges() {
    const response = await apiClient.get<APIResponse>('/protocols/eigrp/edges')
    return response.data.data
  },

  async getEIGRPInterfaces() {
    const response = await apiClient.get<APIResponse>('/protocols/eigrp/interface-configuration')
    return response.data.data
  },

  async getISISEdges() {
    const response = await apiClient.get<APIResponse>('/protocols/isis/edges')
    return response.data.data
  },

  async getISISInterfaces() {
    const response = await apiClient.get<APIResponse>('/protocols/isis/interface-configuration')
    return response.data.data
  },

  async getISISLoopbackInterfaces() {
    const response = await apiClient.get<APIResponse>('/protocols/isis-loopback-interfaces')
    return response.data.data
  },

  async getBFDSessionStatus() {
    const response = await apiClient.get<APIResponse<BFDSessionStatus[]>>('/protocols/bfd-session-status')
    return response.data.data
  },
}

/**
 * Network topology API methods
 * Provides Layer 1/2 topology, VXLAN VNI properties, IPsec VPN data, and switched VLAN edges
 * Core data for multi-layer network visualization
 */
export const topologyAPI = {
  async getLayer1Topology() {
    const response = await apiClient.get<APIResponse<Layer1Edge[]>>('/topology/layer1-topology')
    return response.data.data
  },

  async getLayer2Topology() {
    const response = await apiClient.get<APIResponse<Layer2Topology[]>>('/topology/layer2-topology')
    return response.data.data
  },

  async getVXLANVNIProperties() {
    const response = await apiClient.get<APIResponse>('/protocols/evpn/vxlan-vni-properties')
    return response.data.data
  },

  async getVXLANEdges() {
    const response = await apiClient.get<APIResponse<VXLANEdge[]>>('/protocols/evpn/vxlan-edges')
    return response.data.data
  },

  async getIPSecSessionStatus() {
    const response = await apiClient.get<APIResponse<IPSecSessionStatus[]>>('/topology/ipsec-session-status')
    return response.data.data
  },

  async getIPSecEdges() {
    const response = await apiClient.get<APIResponse<IPSecEdge[]>>('/topology/ipsec-edges')
    return response.data.data
  },

  async getIPSecPeerConfiguration() {
    const response = await apiClient.get<APIResponse<IPSecPeerConfiguration[]>>('/topology/ipsec-peer-configuration')
    return response.data.data
  },

  async getSwitchedVlanEdges() {
    const response = await apiClient.get<APIResponse<SwitchedVlanEdge[]>>('/topology/switched-vlan-edges')
    return response.data.data
  },
}

/**
 * Advanced analysis features API methods
 * Provides F5 load balancer VIPs, route policy testing, ACL analysis, and filter reachability
 * Advanced network analysis capabilities for enterprise environments
 */
export const advancedAPI = {
  async getF5VIPs() {
    const response = await apiClient.get<APIResponse>('/advanced/f5-bigip-vip-configuration')
    return response.data.data
  },

  async testRoutePolicies(request: { direction: string; policy: string }) {
    const response = await apiClient.post<APIResponse>('/advanced/test-route-policies', request)
    return response.data.data
  },

  async searchRoutePolicies(request?: { action?: string; nodes?: string[] }) {
    const response = await apiClient.post<APIResponse>('/advanced/search-route-policies', request || {})
    return response.data.data
  },

  async getFilterLineReachability(request?: { filters?: string; nodes?: string[] }) {
    const response = await apiClient.post<APIResponse>('/advanced/filter-line-reachability', request || {})
    return response.data.data
  },

  async testFilters(request: { filters: string; nodes?: string[] }) {
    const response = await apiClient.post<APIResponse>('/advanced/test-filters', request)
    return response.data.data
  },

  async findMatchingFilterLines(request: { headers: object; filters?: string; nodes?: string[] }) {
    const response = await apiClient.post<APIResponse>('/advanced/find-matching-filter-lines', request)
    return response.data.data
  },

  async searchFilters(request?: { action?: string; filters?: string; nodes?: string[] }) {
    const response = await apiClient.post<APIResponse>('/advanced/search-filters', request || {})
    return response.data.data
  },

  async reduceReachability(request?: { pathConstraints?: object }) {
    const response = await apiClient.post<APIResponse>('/advanced/reduce-reachability', request || {})
    return response.data.data
  },

  async getVIModel() {
    const response = await apiClient.get<APIResponse<VIModel[]>>('/advanced/vi-model')
    return response.data.data
  },
}

/**
 * User management API methods
 * Handles user registration, listing, updates, password changes, and deletion
 * Admin-only operations for user account management (except getMe and changePassword for self)
 */
export const usersAPI = {
  async register(data: RegisterRequest) {
    const response = await axios.post<APIResponse<User>>(`${API_BASE_URL}/api/users`, data)
    return response.data.data
  },

  async list() {
    const response = await apiClient.get<APIResponse<User[]>>('/users')
    return response.data.data
  },

  async getMe() {
    const response = await apiClient.get<APIResponse<User>>('/users/me')
    return response.data.data
  },

  async getById(id: number) {
    const response = await apiClient.get<APIResponse<User>>(`/users/${id}`)
    return response.data.data
  },

  async update(id: number, data: UpdateUserRequest) {
    const response = await apiClient.put<APIResponse<User>>(`/users/${id}`, data)
    return response.data.data
  },

  async changePassword(id: number, data: ChangePasswordRequest) {
    const response = await apiClient.put<APIResponse<void>>(`/users/${id}/password`, data)
    return response.data.data
  },

  async delete(id: number) {
    const response = await apiClient.delete<APIResponse<void>>(`/users/${id}`)
    return response.data.data
  },
}

/**
 * Security audit logs API methods
 * Provides access to login attempts, security events, and statistics
 * Admin-only endpoints for security monitoring and compliance
 */
export const securityLogsAPI = {
  async list(params?: SecurityLogsQueryParams) {
    const queryParams = new URLSearchParams()
    if (params?.page) queryParams.append('page', params.page.toString())
    if (params?.per_page) queryParams.append('per_page', params.per_page.toString())
    if (params?.ip_address) queryParams.append('ip_address', params.ip_address)
    if (params?.username) queryParams.append('username', params.username)
    if (params?.success !== undefined) queryParams.append('success', params.success.toString())
    if (params?.start_date) queryParams.append('start_date', params.start_date)
    if (params?.end_date) queryParams.append('end_date', params.end_date)
    if (params?.sort) queryParams.append('sort', params.sort)

    const queryString = queryParams.toString()
    const url = `/admin/security-logs${queryString ? `?${queryString}` : ''}`

    const response = await apiClient.get<APIResponse<PaginatedSecurityLogsResponse>>(url)
    return response.data.data
  },

  async getStats() {
    const response = await apiClient.get<APIResponse<SecurityStats>>('/admin/security-logs/stats')
    return response.data.data
  },
}

/**
 * Meta API methods
 * Provides API endpoint discovery and system metadata
 */
export const metaAPI = {
  async getEndpoints() {
    const response = await apiClient.get('/endpoints')
    return response.data.data
  },
}

export { apiClient }
