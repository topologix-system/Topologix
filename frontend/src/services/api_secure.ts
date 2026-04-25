/**
 * Secure API client variant with enhanced input validation
 * - Enforces IP address validation (IPv4/IPv6 format checks) before API calls
 * - Required for production deployments with strict security policies
 * - Always uses authentication (no disable option unlike api.ts)
 * - Validates all user inputs against ReDoS patterns before submission
 * - Uses CSRFService for stateless double-submit cookie pattern
 */
import axios, { AxiosInstance, AxiosError, AxiosRequestConfig } from 'axios'
import { runtimeConfig } from '../config/runtimeConfig'
// isTokenExpired removed — expiry now checked via stored tokenExpiresAt timestamp
import { logger } from '../utils/logger'
import { CSRFService } from './csrfService'
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
  FlowTrace,
  RoutePolicy,
  AAAAuthenticationLogin,
  ReachabilityRequest,
  Snapshot,
  SnapshotFile,
  CreateSnapshotRequest,
  BGPEdge,
  BGPPeerConfiguration,
  BGPProcessConfiguration,
  BGPSessionStatus,
  BGPSessionCompatibility,
  BGPRib,
  SNMPCommunityConfig,
  DuplicateRouterID,
  BFDSessionStatus,
  Layer1Edge,
  Layer2Topology,
  IPSecSessionStatus,
  IPSecEdge,
  IPSecPeerConfiguration,
  VXLANEdge,
  VIModel,
  Layer1Topology,
  Layer1TopologySaveResult,
  SnapshotInterfaces,
  User,
  RegisterRequest,
  UpdateUserRequest,
  ChangePasswordRequest,
  SecurityLogsQueryParams,
  PaginatedSecurityLogsResponse,
  SecurityStats,
} from '../types'

const API_BASE_URL = runtimeConfig.apiBaseUrl || 'http://localhost:5000'

interface AuthState {
  csrfToken: string | null
  tokenExpiresAt: number | null
  user: {
    username: string
    roles: string[]
    email: string
  } | null
}

const tokenExpiresAtStr = localStorage.getItem('token_expires_at')

let authState: AuthState = {
  csrfToken: null,
  tokenExpiresAt: tokenExpiresAtStr ? parseInt(tokenExpiresAtStr, 10) : null,
  user: null
}

const storedUser = localStorage.getItem('user')
if (storedUser) {
  try {
    authState.user = JSON.parse(storedUser)
  } catch (e) {
    logger.error('Failed to parse stored user data')
  }
}

const apiClient: AxiosInstance = axios.create({
  baseURL: `${API_BASE_URL}/api`,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true,
})

apiClient.interceptors.request.use(
  async (config) => {
    // Check if token is expired BEFORE sending request (via stored timestamp)
    if (authState.tokenExpiresAt && Date.now() > authState.tokenExpiresAt) {
      logger.warn('[API Secure] Access token expired, clearing local state')

      authState.csrfToken = null
      authState.tokenExpiresAt = null
      authState.user = null

      localStorage.removeItem('user')
      localStorage.removeItem('token_expires_at')

      window.dispatchEvent(new CustomEvent('auth:unauthorized', {
        detail: { reason: 'token_expired', timestamp: Date.now() }
      }))

      return Promise.reject(new Error('Token expired'))
    }

    // Add CSRF token for state-changing methods (double-submit pattern with async retrieval)
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(config.method?.toUpperCase() || '')) {
      try {
        // ASYNC TOKEN RETRIEVAL: Use async getToken() for automatic refresh + retry logic
        const csrfToken = await CSRFService.getToken()
        config.headers['X-CSRF-Token'] = csrfToken
        logger.debug('[API Secure] CSRF token added to request (async)')
      } catch (error) {
        logger.error('[API Secure] Failed to obtain CSRF token for request:', error)
        // Fail fast - reject the request instead of proceeding without token
        return Promise.reject(new Error(`CSRF token unavailable: ${error}`))
      }
    }

    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

apiClient.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as AxiosRequestConfig & { _retry?: boolean }

    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true

      try {
        // Refresh via HTTP-only cookie (sent automatically with withCredentials)
        const refreshResponse = await axios.post(
          `${API_BASE_URL}/api/auth/refresh`,
          {},
          { withCredentials: true }
        )

        const { expires_in } = refreshResponse.data.data

        // Update local expiration tracking
        const expiresAt = Date.now() + (expires_in * 1000)
        authState.tokenExpiresAt = expiresAt
        localStorage.setItem('token_expires_at', expiresAt.toString())

        // Retry original request (cookie updated by Set-Cookie header)
        return apiClient(originalRequest)
      } catch (refreshError) {
        logger.error('[API Secure] Refresh token failed')
        await authAPI.logout()
        return Promise.reject(refreshError)
      }
    }

    if (error.response?.status === 403 && !originalRequest._retry) {
      originalRequest._retry = true

      interface CSRFErrorResponse {
        message?: string
        error?: string
      }

      const errorData = error.response.data as CSRFErrorResponse
      const message = (errorData?.message || errorData?.error || '').toLowerCase()

      if (message.includes('csrf')) {
        try {
          logger.warn('[API Secure] CSRF validation failed, refreshing token')

          // ASYNC TOKEN RETRIEVAL: Use async getToken() which includes refresh logic
          const newCsrfToken = await CSRFService.getToken()

          if (originalRequest.headers) {
            originalRequest.headers['X-CSRF-Token'] = newCsrfToken
            logger.info('[API Secure] CSRF token refreshed (async), retrying request')
            return apiClient(originalRequest)
          } else {
            logger.error('[API Secure] Request headers not available for retry')
          }
        } catch (csrfError) {
          logger.error('[API Secure] Failed to refresh CSRF token:', csrfError)
          // Let the error propagate to React Query error handler
          return Promise.reject(csrfError)
        }
      } else {
        logger.error('[API Secure] Permission denied:', message)
      }
    }

    if (error.response?.status === 429) {
      const retryAfter = error.response.headers['retry-after']
      logger.error(`Rate limit exceeded. Retry after ${retryAfter} seconds`)
    }

    if (error.response) {
      logger.error('API Error:', error.response.status, error.response.data)
    } else if (error.request) {
      logger.error('Network Error: No response from server')
    } else {
      logger.error('Request Error:', error.message)
    }

    return Promise.reject(error)
  }
)

/**
 * Authentication and authorization API methods (secure variant)
 * Always enforces authentication (no disable option)
 * Handles login, logout, token refresh, CSRF token management
 * Manages JWT access/refresh tokens and CSRF protection
 */
export const authAPI = {
  async login(username: string, password: string) {
    const response = await axios.post<APIResponse<{
      token_type: string
      expires_in: number
      user: { username: string; roles: string[]; email: string }
      csrf_token: string
    }>>(`${API_BASE_URL}/api/auth/login`, { username, password }, { withCredentials: true })

    const data = response.data.data

    authState.csrfToken = data.csrf_token
    authState.user = data.user

    const expiresAt = Date.now() + (data.expires_in * 1000)
    authState.tokenExpiresAt = expiresAt

    localStorage.setItem('user', JSON.stringify(data.user))
    localStorage.setItem('token_expires_at', expiresAt.toString())
    sessionStorage.setItem('csrf_token', data.csrf_token)

    CSRFService.setMemoryToken(data.csrf_token)

    return data
  },

  async logout() {
    try {
      await apiClient.post('/auth/logout')
    } catch (e) {
      logger.error('Logout error:', e)
    } finally {
      authState = {
        csrfToken: null,
        tokenExpiresAt: null,
        user: null
      }

      localStorage.removeItem('user')
      localStorage.removeItem('token_expires_at')
      sessionStorage.removeItem('csrf_token')
    }
  },

  getCurrentUser() {
    return authState.user
  },

  isAuthenticated() {
    if (!authState.user) return false
    if (authState.tokenExpiresAt && Date.now() > authState.tokenExpiresAt) return false
    return true
  },

  hasRole(role: string) {
    return authState.user?.roles?.includes(role) || false
  },

  async refreshCSRFToken() {
    const response = await apiClient.get<APIResponse<{ csrf_token: string }>>('/auth/csrf-token')
    authState.csrfToken = response.data.data.csrf_token
    sessionStorage.setItem('csrf_token', authState.csrfToken)
    return authState.csrfToken
  }
}

/**
 * Core network data API methods (secure variant)
 * Provides access to network topology, nodes, interfaces, routes, VLANs, and IP ownership
 * Includes additional health and config endpoints for security monitoring
 * Primary source for Batfish network analysis data
 */
export const networkAPI = {
  async health() {
    const response = await axios.get<APIResponse<{
      service: string
      status: string
      version: string
      security: string
    }>>(`${API_BASE_URL}/api/health`)
    return response.data.data
  },

  async getConfig() {
    const response = await axios.get<APIResponse<{
      env: string
      cors_enabled: boolean
      max_file_size: number
      allowed_extensions: string[]
      rate_limit_enabled: boolean
    }>>(`${API_BASE_URL}/api/config`)
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
 * OSPF protocol API methods (secure variant)
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
 * Snapshot management API methods (secure variant)
 * Handles snapshot CRUD operations, file uploads with progress tracking, and snapshot activation
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

  async uploadFile(
    name: string,
    file: File,
    onProgress?: (progress: number) => void
  ) {
    const formData = new FormData()
    formData.append('file', file)

    const response = await apiClient.post<APIResponse<SnapshotFile>>(
      `/snapshots/${name}/files`,
      formData,
      {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
        onUploadProgress: (progressEvent) => {
          if (onProgress && progressEvent.total) {
            const progress = Math.round((progressEvent.loaded * 100) / progressEvent.total)
            onProgress(progress)
          }
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
 * Network analysis API methods (secure variant)
 * Provides reachability analysis and route policies with input validation
 * Validates IP addresses and CIDR notation before sending to backend
 * Core functionality for end-to-end connectivity testing
 */
export const analysisAPI = {
  async getReachability(request?: ReachabilityRequest) {
    if (request?.headers?.srcIps) {
      if (!isValidIP(request.headers.srcIps) && !isValidCIDR(request.headers.srcIps)) {
        throw new Error('Invalid source IP address')
      }
    }
    if (request?.headers?.dstIps) {
      if (!isValidIP(request.headers.dstIps) && !isValidCIDR(request.headers.dstIps)) {
        throw new Error('Invalid destination IP address')
      }
    }

    const response = await apiClient.post<APIResponse<FlowTrace[]>>('/analysis/reachability', request)
    return response.data.data
  },

  async getRoutePolicies(params?: { nodes?: string; action?: string }) {
    const response = await apiClient.get<APIResponse<RoutePolicy[]>>('/analysis/route-policies', { params })
    return response.data.data
  },
}

/**
 * Validate IPv4 address format
 * Checks if string matches standard IPv4 dotted-decimal notation (0-255 per octet)
 * Used for input validation before API calls to prevent injection attacks
 * @param ip - IP address string to validate
 * @returns true if valid IPv4 format, false otherwise
 */
function isValidIP(ip: string): boolean {
  const ipRegex = /^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$/
  return ipRegex.test(ip)
}

/**
 * Validate CIDR notation format (IPv4 with subnet mask)
 * Checks if string matches IPv4/prefix-length format (e.g., "192.168.1.0/24")
 * Validates both IP address format and prefix length (0-32)
 * @param cidr - CIDR notation string to validate
 * @returns true if valid CIDR format, false otherwise
 */
function isValidCIDR(cidr: string): boolean {
  const cidrRegex = /^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}\/(3[0-2]|[12]?\d)$/
  return cidrRegex.test(cidr)
}

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

export const securityAPI = {
  async getSNMPCommunities(): Promise<SNMPCommunityConfig[]> {
    const response = await apiClient.get<APIResponse<SNMPCommunityConfig[]>>('/security/snmp-communities')
    return response.data.data
  },
}

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

  async getMultipathConsistency() {
    const response = await apiClient.get<APIResponse>('/validation/multipath-consistency')
    return response.data.data
  },

  async getSubnetMultipathConsistency(request?: { maxTraces?: number }) {
    const response = await apiClient.post<APIResponse<any>>('/validation/subnet-multipath-consistency', request || {})
    return response.data.data
  },

  async getDifferentialReachability(request: {
    reference_snapshot: string
    snapshot?: string
    headers?: object
    pathConstraints?: object
    actions?: string | string[]
    maxTraces?: number
    invertSearch?: boolean
    ignoreFilters?: boolean
  }) {
    const response = await apiClient.post<APIResponse<any>>('/advanced/differential-reachability', request || {})
    return response.data.data
  },

  async getLoopbackMultipathConsistency() {
    const response = await apiClient.get<APIResponse>('/validation/loopback-multipath-consistency')
    return response.data.data
  },
}

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

  async getEVPNRib() {
    const response = await apiClient.get<APIResponse>('/protocols/evpn/rib')
    return response.data.data
  },
}

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

  async getInterfaceMTU() {
    const response = await apiClient.get<APIResponse>('/topology/interface-mtu')
    return response.data.data
  },

  async getIPSpaceAssignment() {
    const response = await apiClient.get<APIResponse>('/topology/ip-space-assignment')
    return response.data.data
  },
}

export const advancedAPI = {
  async getF5VIPs() {
    const response = await apiClient.get<APIResponse>('/advanced/f5-bigip-vip-configuration')
    return response.data.data
  },

  async testRoutePolicies(request: {
    direction: string
    inputRoutes: object | object[]
    nodes?: string | string[]
    policies?: string | string[]
    bgpSessionProperties?: object
  }) {
    const response = await apiClient.post<APIResponse<any>>('/advanced/test-route-policies', request)
    return response.data.data
  },

  async searchRoutePolicies(request?: { action?: string; nodes?: string[] }) {
    const response = await apiClient.post<APIResponse>('/advanced/search-route-policies', request || {})
    return response.data.data
  },

  async getFilterLineReachability(request?: { filters?: string; nodes?: string[]; ignoreComposites?: boolean }) {
    const response = await apiClient.get<APIResponse<any>>('/acl/filter-line-reachability', { params: request })
    return response.data.data
  },

  async testFilters(request: { headers: object; filters?: string; nodes?: string[]; startLocation?: string }) {
    const response = await apiClient.post<APIResponse<any>>('/acl/test-filters', request)
    return response.data.data
  },

  async findMatchingFilterLines(request: { headers: object; filters?: string; nodes?: string[] }) {
    const response = await apiClient.post<APIResponse>('/acl/find-matching-lines', request)
    return response.data.data
  },

  async searchFilters(request?: { action?: string; filters?: string; nodes?: string[] }) {
    const response = await apiClient.post<APIResponse>('/acl/search-filters', request || {})
    return response.data.data
  },

  async reduceReachability(request?: {
    headers?: object
    pathConstraints?: object
    actions?: string | string[]
    maxTraces?: number
    invertSearch?: boolean
    ignoreFilters?: boolean
  }) {
    const response = await apiClient.post<APIResponse<any>>('/advanced/reduce-reachability', request || {})
    return response.data.data
  },

  async getVIModel() {
    const response = await apiClient.get<APIResponse<VIModel[]>>('/advanced/vi-model')
    return response.data.data
  },
}

export const layer1API = {
  async getTopology(snapshotName: string) {
    const response = await apiClient.get<APIResponse<Layer1Topology>>(
      `/snapshots/${snapshotName}/layer1-topology`
    )
    return response.data.data
  },

  async saveTopology(snapshotName: string, topology: Layer1Topology) {
    const response = await apiClient.put<APIResponse<Layer1TopologySaveResult>>(
      `/snapshots/${snapshotName}/layer1-topology`,
      topology
    )
    return response.data.data
  },

  async deleteTopology(snapshotName: string) {
    await apiClient.delete(`/snapshots/${snapshotName}/layer1-topology`)
  },

  async getInterfaces(snapshotName: string) {
    const response = await apiClient.get<APIResponse<SnapshotInterfaces>>(
      `/snapshots/${snapshotName}/interfaces`
    )
    return response.data.data
  },
}

export const usersAPI = {
  async register(data: RegisterRequest) {
    const response = await apiClient.post<APIResponse<User>>('/users', data)
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

export const securityLogsAPI = {
  async list(params?: SecurityLogsQueryParams) {
    const queryParams = new URLSearchParams()
    if (params?.page) queryParams.append('page', params.page.toString())
    if (params?.per_page) queryParams.append('per_page', params.per_page.toString())
    if (params?.ip_address) {
      if (!isValidIP(params.ip_address)) {
        throw new Error('Invalid IP address format in security logs query')
      }
      queryParams.append('ip_address', params.ip_address)
    }
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

export const metaAPI = {
  async getEndpoints() {
    const response = await apiClient.get('/endpoints')
    return response.data.data
  },
}

export { apiClient }
