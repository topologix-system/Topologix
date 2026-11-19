/**
 * Main API client for Topologix backend communication
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
  LpmRoute,
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
  SNMPCommunityConfig,
  ReachabilityRequest,
  Snapshot,
  SnapshotFile,
  SnapshotFileMutationResponse,
  SnapshotArtifactRecord,
  SnapshotArtifactTree,
  SnapshotArtifactTypeDefinition,
  SnapshotArtifactPreview,
  SnapshotArtifactPreviewRequest,
  SnapshotArtifactValidationResult,
  CreateSnapshotRequest,
  UpdateSnapshotRequest,
  UpdateSnapshotFileFormatRequest,
  ConfigFileContentResponse,
  UpdateConfigFileContentRequest,
  DeleteSnapshotFileResponse,
  SnapshotOwnerMigrationCandidate,
  AssignSnapshotOwnerRequest,
  AssignSnapshotOwnerResponse,
  UploadSnapshotArtifactRequest,
  UpdateSnapshotArtifactRequest,
  ReplaceSnapshotArtifactContentRequest,
  DeleteSnapshotArtifactResponse,
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
  CompareSnapshotsRequest,
  ComparisonResult,
  Layer1Topology,
  Layer1TopologySaveResult,
  SnapshotInterfaces,
  VXLANEdge,
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

const API_BASE_URL = runtimeConfig.apiBaseUrl || ''
const AUTH_ENABLED = runtimeConfig.authEnabled

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

let authState: AuthState = {
  csrfToken: null,
  tokenExpiresAt: null,
  user: null
}

if (AUTH_ENABLED) {
  const tokenExpiresAtStr = localStorage.getItem('token_expires_at')

  authState = {
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
}

const apiClient: AxiosInstance = axios.create({
  baseURL: `${API_BASE_URL}/api`,
  // The backend serializes Batfish-backed requests behind one lock, so a request can wait for a long-running query before it starts
  timeout: 120000,
  headers: {
    'Content-Type': 'application/json',
  },
  ...(AUTH_ENABLED ? { withCredentials: true } : {}),
})

if (AUTH_ENABLED) {
  apiClient.interceptors.request.use(
    async (config) => {
      if (authState.tokenExpiresAt && Date.now() > authState.tokenExpiresAt) {
        logger.warn('[API] Access token expired, clearing local state')

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
          logger.debug('[API] CSRF token added to request (async)')
        } catch (error) {
          const safeError = getSafeApiErrorLog(error)
          const safeMessage = typeof safeError.message === 'string' ? safeError.message : 'unknown error'
          logger.error('[API] Failed to obtain CSRF token for request:', safeError)
          return Promise.reject(new Error(`CSRF token unavailable: ${safeMessage}`))
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
          logger.error('[API] Refresh token failed')
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
            logger.warn('[API] CSRF validation failed, force-refreshing token')

            const newCsrfToken = await CSRFService.forceRefresh()

            if (originalRequest.headers) {
              originalRequest.headers['X-CSRF-Token'] = newCsrfToken
              logger.info('[API] CSRF token force-refreshed, retrying request')
              return apiClient(originalRequest)
            } else {
              logger.error('[API] Request headers not available for retry')
            }
          } catch (csrfError) {
            logger.error('[API] Failed to refresh CSRF token:', getSafeApiErrorLog(csrfError))
            return Promise.reject(csrfError)
          }
        } else {
          logger.error('[API] Permission denied:', getSafeApiErrorLog(error))
        }
      }

      if (error.response?.status === 429) {
        const retryAfter = error.response.headers['retry-after']
        logger.error(`Rate limit exceeded. Retry after ${retryAfter} seconds`)
      }
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

if (!AUTH_ENABLED) {
  apiClient.interceptors.response.use(
    (response) => response,
    (error: AxiosError) => {
      if (error.response?.status === 403) {
        const errorData = error.response.data as { message?: string; error?: string } | undefined
        const message = (errorData?.message || errorData?.error || '').toLowerCase()
        if (message.includes('csrf')) {
          logger.error(
            '[API] Received CSRF 403 while AUTH_ENABLED=false. ' +
            'The backend may have AUTH_ENABLED=true. ' +
            'Check that frontend and backend AUTH_ENABLED values match.'
          )
        }
      }
      return Promise.reject(error)
    }
  )
}

/**
 * Authentication and authorization API methods
 * Handles login, logout, token refresh, CSRF token management, and password reset
 */
export const authAPI = {
  async login(username: string, password: string) {
    if (!AUTH_ENABLED) {
      throw new Error('Authentication is not enabled')
    }

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

    CSRFService.setMemoryToken(data.csrf_token)

    return data
  },

  async logout() {
    if (!AUTH_ENABLED) {
      return
    }

    try {
      await apiClient.post('/auth/logout')
    } catch (e) {
      logger.error('Logout error:', getSafeApiErrorLog(e))
    } finally {
      authState.csrfToken = null
      authState.tokenExpiresAt = null
      authState.user = null

      localStorage.removeItem('user')
      localStorage.removeItem('token_expires_at')

      CSRFService.clearToken()
    }
  },

  getCurrentUser() {
    return AUTH_ENABLED ? authState.user : null
  },

  isAuthenticated() {
    if (!AUTH_ENABLED) return true

    if (!authState.user) return false

    if (authState.tokenExpiresAt && Date.now() > authState.tokenExpiresAt) return false

    return true
  },

  hasRole(role: string) {
    if (!AUTH_ENABLED) {
      return false
    }
    return authState.user?.roles?.includes(role) || false
  },

  async refreshCSRFToken() {
    if (!AUTH_ENABLED) {
      throw new Error('Authentication is not enabled')
    }

    // Use CSRFService to refresh token (uses axios directly to avoid interceptor loop)
    const newToken = await CSRFService.refreshToken()
    authState.csrfToken = newToken
    return newToken
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
 * Core network data API methods
 * Provides access to network topology, nodes, interfaces, routes, VLANs, and IP ownership
 */
export const networkAPI = {
  async health() {
    const response = await apiClient.get<APIResponse<{ service: string; status: string; auth_enabled: boolean }>>('/health')
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
    // Matches the 300 s window nginx allows for /api
    const response = await apiClient.get<APIResponse<AllNetworkData>>('/network/all-data', {
      timeout: 300000,
    })
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
 * OSPF protocol API methods
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
 * Network edges API methods
 * Provides access to physical, layer 3, OSPF, and BGP connectivity edges
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
 * Security analysis API methods
 * Provides SNMP community configuration for security validation
 */
export const securityAPI = {
  async getSNMPCommunities(): Promise<SNMPCommunityConfig[]> {
    const response = await apiClient.get<APIResponse<SNMPCommunityConfig[]>>('/security/snmp-communities')
    return response.data.data
  },
}

/**
 * Network validation API methods
 * Provides configuration parsing status, init issues, warnings, and network validation
 */
const PARSE_RESULT_TIMEOUT_MS = 120000

export const validationAPI = {
  async getFileParseStatus() {
    const response = await apiClient.get<APIResponse<FileParseStatus[]>>(
      '/validation/file-parse-status',
      { timeout: PARSE_RESULT_TIMEOUT_MS }
    )
    return response.data.data
  },

  async getInitIssues() {
    const response = await apiClient.get<APIResponse<InitIssue[]>>('/validation/init-issues', {
      timeout: PARSE_RESULT_TIMEOUT_MS,
    })
    return response.data.data
  },

  async getParseWarnings() {
    const response = await apiClient.get<APIResponse<ParseWarning[]>>('/validation/parse-warnings', {
      timeout: PARSE_RESULT_TIMEOUT_MS,
    })
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

  async resolveFilterSpecifier(request?: { filters?: string | string[]; nodes?: string | string[]; grammarVersion?: string }) {
    const response = await apiClient.post<APIResponse<any[]>>('/validation/resolve-filter-specifier', request || {})
    return response.data.data
  },

  async resolveNodeSpecifier(request?: { nodes?: string | string[]; grammarVersion?: string }) {
    const response = await apiClient.post<APIResponse<any[]>>('/validation/resolve-node-specifier', request || {})
    return response.data.data
  },

  async resolveInterfaceSpecifier(request?: { interfaces?: string | string[]; nodes?: string | string[]; grammarVersion?: string }) {
    const response = await apiClient.post<APIResponse<any[]>>('/validation/resolve-interface-specifier', request || {})
    return response.data.data
  },

  async compareFilters(request: {
    reference_snapshot: string
    snapshot?: string
    filters?: string | string[]
    nodes?: string | string[]
    ignoreComposites?: boolean
  }) {
    const response = await apiClient.post<APIResponse<any[]>>('/validation/compare-filters', request)
    return response.data.data
  },
}

/**
 * Network analysis API methods
 * Provides reachability analysis, route policies, traceroute, and bidirectional traceroute
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
    const response = await apiClient.post<APIResponse<TracerouteResponse[]>>(
      '/path/traceroute', request, { timeout: 120000 }
    )
    return response.data.data
  },

  async bidirectionalTraceroute(request?: TracerouteRequest) {
    const response = await apiClient.post<APIResponse<BidirectionalTracerouteResponse[]>>(
      '/path/bidirectional-traceroute', request, { timeout: 120000 }
    )
    return response.data.data
  },
}

/**
 * Snapshot management API methods
 * Handles snapshot CRUD operations, file uploads, and snapshot activation
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

  async uploadFile(name: string, file: File) {
    const formData = new FormData()
    formData.append('file', file)

    const response = await apiClient.post<APIResponse<SnapshotFileMutationResponse>>(
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

  async getArtifactTypes(name: string) {
    const response = await apiClient.get<APIResponse<SnapshotArtifactTypeDefinition[]>>(
      `/snapshots/${name}/artifact-types`
    )
    return response.data.data
  },

  async getArtifactTree(name: string) {
    const response = await apiClient.get<APIResponse<SnapshotArtifactTree>>(
      `/snapshots/${name}/artifact-tree`
    )
    return response.data.data
  },

  async previewArtifactChange(name: string, request: SnapshotArtifactPreviewRequest) {
    const response = await apiClient.post<APIResponse<SnapshotArtifactPreview>>(
      `/snapshots/${name}/artifacts/preview-change`,
      request
    )
    return response.data.data
  },

  async uploadArtifact({ name, artifactType, file, metadata, previewToken }: UploadSnapshotArtifactRequest) {
    const formData = new FormData()
    formData.append('artifact_type', artifactType)
    formData.append('metadata', JSON.stringify(metadata))
    formData.append('preview_token', previewToken)
    formData.append('file', file)

    const response = await apiClient.post<APIResponse<SnapshotArtifactRecord>>(
      `/snapshots/${name}/artifacts`,
      formData,
      {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      }
    )
    return response.data.data
  },

  async updateArtifact({ name, artifactId, artifactType, filename, metadata, previewToken }: UpdateSnapshotArtifactRequest) {
    const encodedArtifactId = encodeURIComponent(artifactId)
    const response = await apiClient.patch<APIResponse<SnapshotArtifactRecord>>(
      `/snapshots/${name}/artifacts/${encodedArtifactId}`,
      {
        artifact_type: artifactType,
        filename,
        metadata,
        preview_token: previewToken,
      }
    )
    return response.data.data
  },

  async replaceArtifactContent({ name, artifactId, file, previewToken }: ReplaceSnapshotArtifactContentRequest) {
    const formData = new FormData()
    formData.append('file', file)
    formData.append('preview_token', previewToken)
    const encodedArtifactId = encodeURIComponent(artifactId)

    const response = await apiClient.put<APIResponse<SnapshotArtifactRecord>>(
      `/snapshots/${name}/artifacts/${encodedArtifactId}/content`,
      formData,
      {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      }
    )
    return response.data.data
  },

  async deleteArtifact(name: string, artifactId: string, previewToken: string) {
    const encodedArtifactId = encodeURIComponent(artifactId)
    const response = await apiClient.delete<APIResponse<DeleteSnapshotArtifactResponse>>(
      `/snapshots/${name}/artifacts/${encodedArtifactId}`,
      {
        data: {
          preview_token: previewToken,
        },
      }
    )
    return response.data.data
  },

  async validateArtifacts(name: string) {
    const response = await apiClient.post<APIResponse<SnapshotArtifactValidationResult>>(
      `/snapshots/${name}/artifacts/validate`
    )
    return response.data.data
  },

  async activate(name: string, options?: ActivateSnapshotOptions) {
    // Matches nginx's 300 s /api limit: a client timeout would restore the previous snapshot in the UI while the backend still activates the new one
    const response = await apiClient.post<APIResponse<NetworkInitializeResponse>>(
      `/snapshots/${name}/activate`,
      options?.if_stale ? { if_stale: true } : undefined,
      { timeout: 300000 }
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

  async compare(request: CompareSnapshotsRequest) {
    const response = await apiClient.post<APIResponse<ComparisonResult>>(
      '/snapshots/compare',
      request
    )
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
 * Layer1 topology management API methods
 * Provides access to physical topology configuration for snapshots
 */
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

/**
 * High availability protocols API methods
 * Provides access to VRRP, HSRP, MLAG properties, duplicate router IDs, and switching
 */
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

/**
 * Additional routing protocols API methods
 * Provides EIGRP, IS-IS, and BFD protocol data
 */
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

/**
 * Network topology API methods
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

  async getLpmRoutes(request: { ip: string; nodes?: string | string[]; vrfs?: string | string[] }) {
    const response = await apiClient.post<APIResponse<LpmRoute[]>>('/topology/lpm-routes', request)
    return response.data.data
  },

  async getPrefixTracer(request: { prefix: string; nodes?: string | string[] }) {
    const response = await apiClient.post<APIResponse<any[]>>('/topology/prefix-tracer', request)
    return response.data.data
  },

  async getUserProvidedLayer1Edges(request?: { nodes?: string | string[]; remoteNodes?: string | string[] }) {
    const response = await apiClient.post<APIResponse<any[]>>('/topology/user-provided-layer1-edges', request || {})
    return response.data.data
  },
}

/**
 * Advanced analysis features API methods
 * Provides F5 load balancer VIPs, route policy testing, ACL analysis, and filter reachability
 */
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

  async resolveLocationSpecifier(request?: { locations?: string; grammarVersion?: string }) {
    const response = await apiClient.post<APIResponse<any[]>>('/advanced/resolve-location-specifier', request || {})
    return response.data.data
  },

  async resolveIpSpecifier(request?: { ips?: string; grammarVersion?: string }) {
    const response = await apiClient.post<APIResponse<any[]>>('/advanced/resolve-ip-specifier', request || {})
    return response.data.data
  },

  async resolveIpsOfLocationSpecifier(request: { locations: string; grammarVersion?: string }) {
    const response = await apiClient.post<APIResponse<any[]>>('/advanced/resolve-ips-of-location-specifier', request)
    return response.data.data
  },

  async bidirectionalReachability(request: { headers: object; pathConstraints?: object; returnFlowType?: string }) {
    const response = await apiClient.post<APIResponse<any[]>>('/advanced/bidirectional-reachability', request)
    return response.data.data
  },

  async getA10VirtualServerConfiguration(request?: { nodes?: string | string[]; virtualServerIps?: string }) {
    const response = await apiClient.post<APIResponse<any[]>>('/advanced/a10-virtual-server-configuration', request || {})
    return response.data.data
  },

  async transferBDDValidation(request?: {
    nodes?: string | string[]
    policies?: string | string[]
    retainAllPaths?: boolean
    seed?: number | string
  }) {
    const response = await apiClient.post<APIResponse<any[]>>('/advanced/transfer-bdd-validation', request || {}, { timeout: 120000 })
    return response.data.data
  },

  async comparePeerGroupPolicies(request: { reference_snapshot: string; snapshot?: string }) {
    const response = await apiClient.post<APIResponse<any[]>>('/advanced/compare-peer-group-policies', request, { timeout: 120000 })
    return response.data.data
  },

  async compareRoutePolicies(request: {
    policy: string
    referencePolicy: string
    reference_snapshot: string
    snapshot?: string
    nodes?: string | string[]
  }) {
    const response = await apiClient.post<APIResponse<any[]>>('/advanced/compare-route-policies', request, { timeout: 120000 })
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

/**
 * User management API methods
 * Handles user registration, listing, updates, password changes, and deletion
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
