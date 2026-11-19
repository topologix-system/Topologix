/**
 * Secure API client variant with enhanced input validation
 */
import axios, { AxiosHeaders, AxiosInstance, AxiosError, AxiosRequestConfig, type AxiosResponse } from 'axios'
import { runtimeConfig } from '../config/runtimeConfig'
import { logger } from '../utils/logger'
import { getSafeApiErrorLog } from '../utils/apiError'
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
  UpdateSnapshotRequest,
  UpdateSnapshotFileFormatRequest,
  SnapshotFileMutationResponse,
  ConfigFileContentResponse,
  UpdateConfigFileContentRequest,
  DeleteSnapshotFileResponse,
  SnapshotOwnerMigrationCandidate,
  AssignSnapshotOwnerRequest,
  AssignSnapshotOwnerResponse,
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
  HashKeyedResponse,
  ResultIdentityHeaders,
  ActivateSnapshotOptions,
  SnapshotVersionState,
  SnapshotVersionDetail,
  VersionListParams,
  VersionListResponse,
  CommitVersionRequest,
  CommitVersionResponse,
  RestoreVersionRequest,
  RestoreVersionResponse,
  VersionDiffResponse,
  VersionFileDiff,
  VersionDeleteRequest,
  SingleVersionDeleteRequest,
  VersionDeleteResponse,
  ClearResultCacheResponse,
} from '../types'

const API_BASE_URL = runtimeConfig.apiBaseUrl || 'http://localhost:5000'

// Auth session requests whose 401 must not start a token refresh or another logout
const AUTH_SESSION_PATHS = ['/auth/logout', '/auth/refresh']

const isAuthSessionRequest = (url: string | undefined): boolean =>
  !!url && AUTH_SESSION_PATHS.some((path) => url.split('?')[0].endsWith(path))

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
  } catch (_e) {
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

    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(config.method?.toUpperCase() || '')) {
      try {
        const csrfToken = await CSRFService.getToken()
        config.headers['X-CSRF-Token'] = csrfToken
        logger.debug('[API Secure] CSRF token added to request (async)')
      } catch (error) {
        const safeError = getSafeApiErrorLog(error)
        const safeMessage = typeof safeError.message === 'string' ? safeError.message : 'unknown error'
        logger.error('[API Secure] Failed to obtain CSRF token for request:', safeError)
        return Promise.reject(new Error(`CSRF token unavailable: ${safeMessage}`))
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

    if (error.response?.status === 401 && !originalRequest._retry && !isAuthSessionRequest(originalRequest.url)) {
      originalRequest._retry = true

      try {
        const refreshResponse = await axios.post(
          `${API_BASE_URL}/api/auth/refresh`,
          {},
          { withCredentials: true }
        )

        const { expires_in } = refreshResponse.data.data

        const expiresAt = Date.now() + (expires_in * 1000)
        authState.tokenExpiresAt = expiresAt
        localStorage.setItem('token_expires_at', expiresAt.toString())

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

          const newCsrfToken = await CSRFService.getToken()

          if (originalRequest.headers) {
            originalRequest.headers['X-CSRF-Token'] = newCsrfToken
            logger.info('[API Secure] CSRF token refreshed (async), retrying request')
            return apiClient(originalRequest)
          } else {
            logger.error('[API Secure] Request headers not available for retry')
          }
        } catch (csrfError) {
          logger.error('[API Secure] Failed to refresh CSRF token:', getSafeApiErrorLog(csrfError))
          return Promise.reject(csrfError)
        }
      } else {
        logger.error('[API Secure] Permission denied:', getSafeApiErrorLog(error))
      }
    }

    if (error.response?.status === 429) {
      const retryAfter = error.response.headers['retry-after']
      logger.error(`Rate limit exceeded. Retry after ${retryAfter} seconds`)
    }

    if (error.response) {
      logger.error('API Error:', getSafeApiErrorLog(error))
    } else if (error.request) {
      logger.error('Network Error: No response from server')
    } else {
      logger.error('Request Error:', getSafeApiErrorLog(error))
    }

    return Promise.reject(error)
  }
)

/**
 * Authentication and authorization API methods (secure variant)
 * Handles login, logout, token refresh, CSRF token management
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
      logger.error('Logout error:', getSafeApiErrorLog(e))
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

function readResultIdentity(headers: AxiosResponse['headers'] | undefined): ResultIdentityHeaders {
  const read = (name: string): string | undefined => {
    if (!headers) return undefined
    const value = headers instanceof AxiosHeaders ? headers.get(name) : headers[name.toLowerCase()]
    return value === undefined || value === null ? undefined : String(value)
  }
  return {
    snapshotId: read('X-Topologix-Snapshot-Id'),
    contentHash: read('X-Topologix-Content-Hash'),
    cacheStatus: read('X-Topologix-Cache'),
  }
}

/**
 * Core network data API methods (secure variant)
 * Provides access to network topology, nodes, interfaces, routes, VLANs, and IP ownership
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

  async getAllData(): Promise<HashKeyedResponse<AllNetworkData>> {
    const response = await apiClient.get<APIResponse<AllNetworkData>>('/network/all-data')
    return { data: response.data.data, identity: readResultIdentity(response.headers) }
  },

  async getNodes(): Promise<HashKeyedResponse<NodeProperties[]>> {
    const response = await apiClient.get<APIResponse<NodeProperties[]>>('/network/nodes')
    return { data: response.data.data, identity: readResultIdentity(response.headers) }
  },

  async getInterfaces(): Promise<HashKeyedResponse<InterfaceProperties[]>> {
    const response = await apiClient.get<APIResponse<InterfaceProperties[]>>('/network/interfaces')
    return { data: response.data.data, identity: readResultIdentity(response.headers) }
  },

  async getRoutes(): Promise<HashKeyedResponse<Route[]>> {
    const response = await apiClient.get<APIResponse<Route[]>>('/network/routes')
    return { data: response.data.data, identity: readResultIdentity(response.headers) }
  },

  async getVlans(): Promise<HashKeyedResponse<SwitchedVlanProperties[]>> {
    const response = await apiClient.get<APIResponse<SwitchedVlanProperties[]>>('/network/vlans')
    return { data: response.data.data, identity: readResultIdentity(response.headers) }
  },

  async getIPOwners(): Promise<HashKeyedResponse<IPOwner[]>> {
    const response = await apiClient.get<APIResponse<IPOwner[]>>('/network/ip-owners')
    return { data: response.data.data, identity: readResultIdentity(response.headers) }
  },
}

/**
 * OSPF protocol API methods (secure variant)
 * Provides access to OSPF processes, areas, interface configurations, and adjacency sessions
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

  async update(name: string, request: UpdateSnapshotRequest) {
    const response = await apiClient.patch<APIResponse<Snapshot>>(`/snapshots/${name}`, request)
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

  async updateFileFormat(
    name: string,
    filename: string,
    configurationFormatOverride: string | null
  ) {
    const request: UpdateSnapshotFileFormatRequest = {
      configuration_format_override: configurationFormatOverride,
    }
    const encodedFilename = encodeURIComponent(filename)
    const response = await apiClient.patch<APIResponse<SnapshotFileMutationResponse>>(
      `/snapshots/${name}/files/${encodedFilename}/format`,
      request
    )
    return response.data.data
  },

  async getConfigFileContent(name: string, filename: string) {
    const encodedFilename = encodeURIComponent(filename)
    const response = await apiClient.get<APIResponse<ConfigFileContentResponse>>(
      `/snapshots/${name}/files/${encodedFilename}/content`
    )
    return response.data.data
  },

  async updateConfigFileContent({
    name,
    filename,
    content,
    expectedSha256,
  }: UpdateConfigFileContentRequest) {
    const encodedFilename = encodeURIComponent(filename)
    const response = await apiClient.put<APIResponse<SnapshotFileMutationResponse>>(
      `/snapshots/${name}/files/${encodedFilename}/content`,
      {
        content,
        expected_sha256: expectedSha256,
      }
    )
    return response.data.data
  },

  async deleteFile(name: string, filename: string) {
    const encodedFilename = encodeURIComponent(filename)
    const response = await apiClient.delete<APIResponse<DeleteSnapshotFileResponse>>(
      `/snapshots/${name}/files/${encodedFilename}`
    )
    return response.data.data
  },

  async activate(name: string, options?: ActivateSnapshotOptions) {
    const response = await apiClient.post<APIResponse<NetworkInitializeResponse>>(
      `/snapshots/${name}/activate`,
      options?.if_stale ? { if_stale: true } : undefined
    )
    return response.data.data
  },

  async getVersionState(name: string) {
    const response = await apiClient.get<APIResponse<SnapshotVersionState>>(`/snapshots/${name}/version-state`)
    return response.data.data
  },

  async listVersions(name: string, params?: VersionListParams) {
    const response = await apiClient.get<APIResponse<VersionListResponse>>(`/snapshots/${name}/versions`, { params })
    return response.data.data
  },

  async getVersion(name: string, versionId: string) {
    const response = await apiClient.get<APIResponse<SnapshotVersionDetail>>(
      `/snapshots/${name}/versions/${encodeURIComponent(versionId)}`
    )
    return response.data.data
  },

  async commitVersion(name: string, request: CommitVersionRequest) {
    const response = await apiClient.post<APIResponse<CommitVersionResponse>>(`/snapshots/${name}/versions`, request)
    return response.data.data
  },

  async getVersionDiff(name: string, versionId: string, against: string) {
    const response = await apiClient.get<APIResponse<VersionDiffResponse>>(
      `/snapshots/${name}/versions/${encodeURIComponent(versionId)}/diff`,
      { params: { against } }
    )
    return response.data.data
  },

  async getVersionFileDiff(name: string, versionId: string, against: string, path: string) {
    const response = await apiClient.get<APIResponse<VersionFileDiff>>(
      `/snapshots/${name}/versions/${encodeURIComponent(versionId)}/diff/file`,
      { params: { against, path } }
    )
    return response.data.data
  },

  async restoreVersion(name: string, versionId: string, request?: RestoreVersionRequest) {
    const response = await apiClient.post<APIResponse<RestoreVersionResponse>>(
      `/snapshots/${name}/versions/${encodeURIComponent(versionId)}/restore`,
      request
    )
    return response.data.data
  },

  async deleteVersion(name: string, versionId: string, request?: SingleVersionDeleteRequest) {
    const response = await apiClient.delete<APIResponse<VersionDeleteResponse>>(
      `/snapshots/${name}/versions/${encodeURIComponent(versionId)}`,
      { data: request }
    )
    return response.data.data
  },

  async deleteVersions(name: string, request: VersionDeleteRequest) {
    const response = await apiClient.delete<APIResponse<VersionDeleteResponse>>(`/snapshots/${name}/versions`, {
      data: request,
    })
    return response.data.data
  },

  async clearResultCache(name: string) {
    const response = await apiClient.post<APIResponse<ClearResultCacheResponse>>(`/snapshots/${name}/cache/clear`)
    return response.data.data
  },
}

export const snapshotMigrationAPI = {
  async listUnowned() {
    const response = await apiClient.get<APIResponse<SnapshotOwnerMigrationCandidate[]>>(
      '/admin/snapshot-migrations/unowned'
    )
    return response.data.data
  },

  async assignOwner(request: AssignSnapshotOwnerRequest) {
    const response = await apiClient.post<APIResponse<AssignSnapshotOwnerResponse>>(
      '/admin/snapshot-migrations/assign-owner',
      request
    )
    return response.data.data
  },
}

/**
 * Network analysis API methods (secure variant)
 * Provides reachability analysis and route policies with input validation
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
 */
function isValidIP(ip: string): boolean {
  const ipRegex = /^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$/
  return ipRegex.test(ip)
}

/**
 * Validate CIDR notation format (IPv4 with subnet mask)
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
    const response = await apiClient.get<APIResponse<Record<string, unknown>[]>>('/validation/unused-structures')
    return response.data.data
  },

  async getUndefinedReferences() {
    const response = await apiClient.get<APIResponse<Record<string, unknown>[]>>('/validation/undefined-references')
    return response.data.data
  },

  async getForwardingLoops() {
    const response = await apiClient.get<APIResponse<Record<string, unknown>[]>>('/validation/detect-loops')
    return response.data.data
  },

  async getMultipathConsistency() {
    const response = await apiClient.get<APIResponse<Record<string, unknown>[]>>('/validation/multipath-consistency')
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
    const response = await apiClient.get<APIResponse<Record<string, unknown>[]>>('/validation/loopback-multipath-consistency')
    return response.data.data
  },
}

export const haAPI = {
  async getVRRPProperties() {
    const response = await apiClient.get<APIResponse<Record<string, unknown>[]>>('/ha/vrrp-properties')
    return response.data.data
  },

  async getHSRPProperties() {
    const response = await apiClient.get<APIResponse<Record<string, unknown>[]>>('/ha/hsrp-properties')
    return response.data.data
  },

  async getMLAGProperties() {
    const response = await apiClient.get<APIResponse<Record<string, unknown>[]>>('/ha/mlag-properties')
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
    const response = await apiClient.get<APIResponse<Record<string, unknown>[]>>('/protocols/eigrp/edges')
    return response.data.data
  },

  async getEIGRPInterfaces() {
    const response = await apiClient.get<APIResponse<Record<string, unknown>[]>>('/protocols/eigrp/interface-configuration')
    return response.data.data
  },

  async getISISEdges() {
    const response = await apiClient.get<APIResponse<Record<string, unknown>[]>>('/protocols/isis/edges')
    return response.data.data
  },

  async getISISInterfaces() {
    const response = await apiClient.get<APIResponse<Record<string, unknown>[]>>('/protocols/isis/interface-configuration')
    return response.data.data
  },

  async getISISLoopbackInterfaces() {
    const response = await apiClient.get<APIResponse<Record<string, unknown>[]>>('/protocols/isis-loopback-interfaces')
    return response.data.data
  },

  async getBFDSessionStatus() {
    const response = await apiClient.get<APIResponse<BFDSessionStatus[]>>('/protocols/bfd-session-status')
    return response.data.data
  },

  async getEVPNRib() {
    const response = await apiClient.get<APIResponse<Record<string, unknown>[]>>('/protocols/evpn/rib')
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
    const response = await apiClient.get<APIResponse<Record<string, unknown>[]>>('/protocols/evpn/vxlan-vni-properties')
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
    const response = await apiClient.get<APIResponse<Record<string, unknown>[]>>('/topology/interface-mtu')
    return response.data.data
  },

  async getIPSpaceAssignment() {
    const response = await apiClient.get<APIResponse<Record<string, unknown>[]>>('/topology/ip-space-assignment')
    return response.data.data
  },
}

export const advancedAPI = {
  async getF5VIPs() {
    const response = await apiClient.get<APIResponse<Record<string, unknown>[]>>('/advanced/f5-bigip-vip-configuration')
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

  async searchRoutePolicies(request?: {
    action?: string
    nodes?: string | string[]
    policies?: string | string[]
    inputConstraints?: object
    outputConstraints?: object
    perPath?: boolean
    pathOption?: string
  }) {
    const response = await apiClient.post<APIResponse<Record<string, unknown> | Record<string, unknown>[]>>('/advanced/search-route-policies', request || {})
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
    const response = await apiClient.post<APIResponse<Record<string, unknown> | Record<string, unknown>[]>>('/acl/find-matching-lines', request)
    return response.data.data
  },

  async searchFilters(request?: { action?: string; filters?: string; nodes?: string[] }) {
    const response = await apiClient.post<APIResponse<Record<string, unknown> | Record<string, unknown>[]>>('/acl/search-filters', request || {})
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
