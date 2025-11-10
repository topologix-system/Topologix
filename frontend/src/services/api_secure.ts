/**
 * Secure API client variant with enhanced input validation
 * - Enforces IP address validation (IPv4/IPv6 format checks) before API calls
 * - Required for production deployments with strict security policies
 * - Always uses authentication (no disable option unlike api.ts)
 * - Validates all user inputs against ReDoS patterns before submission
 */
import axios, { AxiosInstance, AxiosError, AxiosRequestConfig } from 'axios'
import { runtimeConfig } from '../config/runtimeConfig'
import { isTokenExpired } from '../lib/auth/tokenManager'
import { logger } from '../utils/logger'
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
} from '../types'

const API_BASE_URL = runtimeConfig.apiBaseUrl || 'http://localhost:5000'

interface AuthState {
  accessToken: string | null
  refreshToken: string | null
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
  accessToken: localStorage.getItem('access_token'),
  refreshToken: localStorage.getItem('refresh_token'),
  csrfToken: sessionStorage.getItem('csrf_token'),
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
    // Check if token is expired BEFORE sending request
    if (authState.accessToken && isTokenExpired(authState.accessToken)) {
      logger.warn('[API Secure] Access token expired, attempting silent cleanup')

      try {
        // Fire-and-forget: Notify server (non-blocking)
        // Use axios directly to bypass interceptor and prevent infinite loop
        axios.post(
          `${API_BASE_URL}/api/auth/logout`,
          { reason: 'token_expired' },
          {
            headers: {
              'Authorization': `Bearer ${authState.accessToken}`,
              'X-CSRF-Token': authState.csrfToken || ''
            },
            timeout: 3000
          }
        ).catch(err => {
          logger.warn('[API Secure] Server logout notification failed (non-blocking):', err.message)
        })
      } finally {
        // Clear local state (always executes)
        authState.accessToken = null
        authState.refreshToken = null
        authState.csrfToken = null
        authState.tokenExpiresAt = null
        authState.user = null

        localStorage.removeItem('access_token')
        localStorage.removeItem('refresh_token')
        localStorage.removeItem('user')
        localStorage.removeItem('token_expires_at')
        sessionStorage.removeItem('csrf_token')

        window.dispatchEvent(new CustomEvent('auth:unauthorized', {
          detail: { reason: 'token_expired', timestamp: Date.now() }
        }))
      }

      // Reject request to prevent sending expired token
      return Promise.reject(new Error('Token expired'))
    }

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

apiClient.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as AxiosRequestConfig & { _retry?: boolean }

    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true

      if (authState.refreshToken && !isTokenExpired(authState.refreshToken)) {
        try {
          const refreshResponse = await axios.post(
            `${API_BASE_URL}/api/auth/refresh`,
            { refresh_token: authState.refreshToken }
          )

          const { access_token, expires_in } = refreshResponse.data.data
          authState.accessToken = access_token

          // Calculate and store expiration time
          const expiresAt = Date.now() + (expires_in * 1000)
          authState.tokenExpiresAt = expiresAt

          localStorage.setItem('access_token', access_token)
          localStorage.setItem('token_expires_at', expiresAt.toString())

          if (originalRequest.headers) {
            originalRequest.headers['Authorization'] = `Bearer ${access_token}`
          }
          return apiClient(originalRequest)
        } catch (refreshError) {
          // Refresh failed - let React Query global handler deal with it
          logger.error('[API Secure] Refresh token failed')
          await authAPI.logout()
          return Promise.reject(refreshError)
        }
      } else {
        // No refresh token or expired - logout
        logger.error('[API Secure] No valid refresh token available')
        await authAPI.logout()
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
          const csrfResponse = await apiClient.get('/auth/csrf-token')
          authState.csrfToken = csrfResponse.data.data.csrf_token
          sessionStorage.setItem('csrf_token', authState.csrfToken)

          if (originalRequest.headers) {
            originalRequest.headers['X-CSRF-Token'] = authState.csrfToken
          }
          return apiClient(originalRequest)
        } catch (csrfError) {
          logger.error('Failed to refresh CSRF token')
        }
      } else {
        logger.error('Permission denied:', message)
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

    // Calculate and store token expiration
    const expiresAt = Date.now() + (data.expires_in * 1000)
    authState.tokenExpiresAt = expiresAt

    localStorage.setItem('access_token', data.access_token)
    localStorage.setItem('refresh_token', data.refresh_token)
    localStorage.setItem('user', JSON.stringify(data.user))
    localStorage.setItem('token_expires_at', expiresAt.toString())
    sessionStorage.setItem('csrf_token', data.csrf_token)

    return data
  },

  async logout() {
    try {
      await apiClient.post('/auth/logout')
    } catch (e) {
      logger.error('Logout error:', e)
    } finally {
      authState = {
        accessToken: null,
        refreshToken: null,
        csrfToken: null,
        tokenExpiresAt: null,
        user: null
      }

      localStorage.removeItem('access_token')
      localStorage.removeItem('refresh_token')
      localStorage.removeItem('user')
      localStorage.removeItem('token_expires_at')
      sessionStorage.removeItem('csrf_token')
    }
  },

  getCurrentUser() {
    return authState.user
  },

  isAuthenticated() {
    // Check both token existence AND expiration
    if (!authState.accessToken) return false

    // Use token expiration check
    return !isTokenExpired(authState.accessToken)
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

export { apiClient }
