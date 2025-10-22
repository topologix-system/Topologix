/**
 * Security audit log viewer with advanced filtering
 * - Implements ReDoS-protected IP address and username validation to prevent regex attacks
 * - Real-time input validation with debounced feedback (300ms) for better UX
 * - Pagination, sorting, and comprehensive statistics dashboard
 * - Admin-only access with role-based security checks (hasRole('admin'))
 * - Displays login attempts with filtering by IP, username, success status, date range
 */
import { useState, useCallback, useRef } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { AxiosError } from 'axios'
import {
  Shield,
  AlertCircle,
  AlertTriangle,
  ArrowLeft,
  ChevronLeft,
  ChevronRight,
  Activity,
  TrendingUp,
  Users,
  Globe,
} from 'lucide-react'
import { useSecurityLogs, useSecurityStats } from '../hooks/useSecurityLogs'
import { SecurityLogTable } from '../components/SecurityLogTable'
import { authAPI } from '../services/api'
import type { SecurityLogsQueryParams } from '../types'

export function SecurityLogsPage() {
  const { t } = useTranslation()

  // Check admin permission
  const isAdmin = authAPI.hasRole('admin')

  // State for filters and pagination
  const [page, setPage] = useState(1)
  const [perPage] = useState(50)
  const [filters, setFilters] = useState<Omit<SecurityLogsQueryParams, 'page' | 'per_page'>>({})

  // Separate input state from filter state for better UX
  const [ipInput, setIpInput] = useState('')
  const [ipValidationError, setIpValidationError] = useState<string | null>(null)
  const [usernameInput, setUsernameInput] = useState('')
  const [usernameValidationError, setUsernameValidationError] = useState<string | null>(null)

  // Debounce timer refs for real-time validation feedback
  const ipDebounceRef = useRef<NodeJS.Timeout | null>(null)
  const usernameDebounceRef = useRef<NodeJS.Timeout | null>(null)

  // Build query params
  const queryParams: SecurityLogsQueryParams = {
    page,
    per_page: perPage,
    ...filters,
  }

  // Fetch data
  const { data: logsData, isLoading: logsLoading, error: logsError } = useSecurityLogs(queryParams, isAdmin)
  const { data: stats, isLoading: statsLoading } = useSecurityStats(isAdmin)

  // Access denied for non-admin users
  if (!isAdmin) {
    return (
      <div className="flex items-center justify-center h-screen bg-gray-50">
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 flex items-start gap-2">
          <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" aria-hidden="true" />
          <div>
            <p className="text-sm font-medium text-red-800">Access Denied</p>
            <p className="text-xs text-red-600 mt-1">
              You need admin privileges to access this page.
            </p>
          </div>
        </div>
      </div>
    )
  }

  // Enhanced IP validation with detailed error messages
  const validateIPAddress = useCallback((ip: string): { valid: boolean; error: string | null } => {
    if (!ip.trim()) return { valid: true, error: null }

    // ReDoS protection: Length check before regex
    if (ip.length > 45) {
      return { valid: false, error: 'IP address too long (max 45 characters)' }
    }

    // IPv4 validation with octet range check (0-255)
    const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/
    if (ipv4Pattern.test(ip)) {
      const octets = ip.split('.')
      const invalidOctet = octets.find(octet => {
        const num = parseInt(octet, 10)
        return num < 0 || num > 255
      })

      if (invalidOctet) {
        return { valid: false, error: `Invalid octet: ${invalidOctet} (must be 0-255)` }
      }
      return { valid: true, error: null }
    }

    // IPv6 validation
    const ipv6Pattern = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/
    if (ipv6Pattern.test(ip)) {
      return { valid: true, error: null }
    }

    return { valid: false, error: 'Invalid IP format (must be IPv4 or IPv6)' }
  }, [])

  // Enhanced username validation with detailed error messages
  const validateUsername = useCallback((username: string): { valid: boolean; error: string | null } => {
    if (!username.trim()) return { valid: true, error: null }

    if (username.length > 100) {
      return { valid: false, error: 'Username too long (max 100 characters)' }
    }

    const usernamePattern = /^[a-zA-Z0-9_\-\.@]+$/
    if (!usernamePattern.test(username)) {
      return { valid: false, error: 'Invalid characters (use: a-z, 0-9, _, -, ., @)' }
    }

    return { valid: true, error: null }
  }, [])

  // Handle IP input change (allows unrestricted typing)
  const handleIPInputChange = useCallback((value: string) => {
    setIpInput(value)

    // Clear error while typing for better UX
    if (ipValidationError) {
      setIpValidationError(null)
    }

    // Debounced validation for real-time feedback
    if (ipDebounceRef.current) {
      clearTimeout(ipDebounceRef.current)
    }

    ipDebounceRef.current = setTimeout(() => {
      const { valid, error } = validateIPAddress(value)
      if (!valid) {
        setIpValidationError(error)
      }
    }, 500) // Validate 500ms after user stops typing
  }, [ipValidationError, validateIPAddress])

  // Handle IP blur (validate and apply filter)
  const handleIPBlur = useCallback(() => {
    const { valid, error } = validateIPAddress(ipInput)

    if (!valid) {
      setIpValidationError(error)
      return
    }

    // Valid: apply filter
    setIpValidationError(null)
    setFilters((prev) => ({
      ...prev,
      ip_address: ipInput.trim() || undefined,
    }))
    setPage(1)
  }, [ipInput, validateIPAddress])

  // Handle IP Enter key
  const handleIPKeyDown = useCallback((e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.currentTarget.blur() // Trigger blur validation
    }
  }, [])

  // Handle username input change
  const handleUsernameInputChange = useCallback((value: string) => {
    setUsernameInput(value)

    if (usernameValidationError) {
      setUsernameValidationError(null)
    }

    if (usernameDebounceRef.current) {
      clearTimeout(usernameDebounceRef.current)
    }

    usernameDebounceRef.current = setTimeout(() => {
      const { valid, error } = validateUsername(value)
      if (!valid) {
        setUsernameValidationError(error)
      }
    }, 500)
  }, [usernameValidationError, validateUsername])

  // Handle username blur
  const handleUsernameBlur = useCallback(() => {
    const { valid, error } = validateUsername(usernameInput)

    if (!valid) {
      setUsernameValidationError(error)
      return
    }

    setUsernameValidationError(null)
    setFilters((prev) => ({
      ...prev,
      username: usernameInput.trim() || undefined,
    }))
    setPage(1)
  }, [usernameInput, validateUsername])

  // Handle username Enter key
  const handleUsernameKeyDown = useCallback((e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.currentTarget.blur()
    }
  }, [])

  // Handle clear filters - reset input states
  const handleClearFilters = useCallback(() => {
    setFilters({})
    setIpInput('')
    setUsernameInput('')
    setIpValidationError(null)
    setUsernameValidationError(null)
    setPage(1)
  }, [])

  /**
   * Navigate to previous page of security logs
   * Prevents going below page 1
   */
  const handlePreviousPage = () => {
    setPage((prev) => Math.max(1, prev - 1))
  }

  /**
   * Navigate to next page of security logs
   * Prevents exceeding total_pages from API response
   */
  const handleNextPage = () => {
    if (logsData && page < logsData.total_pages) {
      setPage((prev) => prev + 1)
    }
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="mb-8">
          <Link
            to="/"
            className="inline-flex items-center text-sm text-gray-600 hover:text-gray-900 mb-4"
          >
            <ArrowLeft className="w-4 h-4 mr-1" />
            Back to Dashboard
          </Link>
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-primary-600" />
            <div>
              <h1 className="text-3xl font-bold text-gray-900">Security Logs</h1>
              <p className="text-gray-600 mt-1">Monitor login attempts and security events</p>
            </div>
          </div>
        </div>

        {/* Statistics Cards */}
        {statsLoading ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="bg-white rounded-lg shadow p-6 animate-pulse">
                <div className="h-4 bg-gray-200 rounded w-24 mb-4"></div>
                <div className="h-8 bg-gray-200 rounded w-16 mb-2"></div>
                <div className="h-3 bg-gray-200 rounded w-20"></div>
              </div>
            ))}
          </div>
        ) : stats && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <div className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Total Attempts</p>
                  <p className="text-2xl font-bold text-gray-900 mt-2">{stats.total_attempts}</p>
                  <p className="text-xs text-gray-500 mt-1">All time</p>
                </div>
                <Activity className="w-8 h-8 text-blue-600" />
              </div>
            </div>

            <div className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Success Rate</p>
                  <p className="text-2xl font-bold text-gray-900 mt-2">{stats.success_rate}%</p>
                  <p className="text-xs text-gray-500 mt-1">
                    {stats.failed_attempts} failed
                  </p>
                </div>
                <TrendingUp className="w-8 h-8 text-green-600" />
              </div>
            </div>

            <div className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Unique IPs</p>
                  <p className="text-2xl font-bold text-gray-900 mt-2">{stats.unique_ips}</p>
                  <p className="text-xs text-gray-500 mt-1">
                    {stats.blocked_ips} blocked
                  </p>
                </div>
                <Globe className="w-8 h-8 text-purple-600" />
              </div>
            </div>

            <div className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Last 24h</p>
                  <p className="text-2xl font-bold text-gray-900 mt-2">
                    {stats.recent_24h.total}
                  </p>
                  <p className="text-xs text-gray-500 mt-1">
                    {stats.recent_24h.failed} failed
                  </p>
                </div>
                <Users className="w-8 h-8 text-orange-600" />
              </div>
            </div>
          </div>
        )}

        {/* Most Targeted Accounts */}
        {stats && stats.most_targeted_accounts.length > 0 && (
          <div className="bg-white rounded-lg shadow p-6 mb-8">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">Most Targeted Accounts</h2>
            <div className="flex flex-wrap gap-2">
              {stats.most_targeted_accounts.map((account) => (
                <span
                  key={account.username}
                  className="inline-flex items-center px-3 py-1 rounded-full text-sm bg-red-100 text-red-800"
                >
                  {account.username}
                  <span className="ml-2 px-2 py-0.5 bg-red-200 rounded-full text-xs font-semibold">
                    {account.count}
                  </span>
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Filters */}
        <div className="bg-white rounded-lg shadow p-6 mb-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Filters</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* IP Address Filter - UPDATED */}
            <div>
              <label
                htmlFor="filter-ip"
                className="block text-sm font-medium text-gray-700 mb-1"
              >
                IP Address
              </label>
              <input
                type="text"
                id="filter-ip"
                className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 transition ${
                  ipValidationError
                    ? 'border-red-300 focus:ring-red-500 focus:border-red-500'
                    : 'border-gray-300 focus:ring-primary-500 focus:border-primary-500'
                }`}
                placeholder="192.168.1.1 or 2001:db8::1"
                value={ipInput}
                onChange={(e) => handleIPInputChange(e.target.value)}
                onBlur={handleIPBlur}
                onKeyDown={handleIPKeyDown}
                aria-invalid={!!ipValidationError}
                aria-describedby={ipValidationError ? 'ip-error' : undefined}
              />
              {ipValidationError && (
                <div
                  id="ip-error"
                  className="mt-1 flex items-start gap-1 text-xs text-red-600"
                  role="alert"
                >
                  <AlertTriangle className="w-3 h-3 flex-shrink-0 mt-0.5" aria-hidden="true" />
                  <span>{ipValidationError}</span>
                </div>
              )}
            </div>

            {/* Username Filter - UPDATED */}
            <div>
              <label
                htmlFor="filter-username"
                className="block text-sm font-medium text-gray-700 mb-1"
              >
                Username
              </label>
              <input
                type="text"
                id="filter-username"
                className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 transition ${
                  usernameValidationError
                    ? 'border-red-300 focus:ring-red-500 focus:border-red-500'
                    : 'border-gray-300 focus:ring-primary-500 focus:border-primary-500'
                }`}
                placeholder="admin"
                value={usernameInput}
                onChange={(e) => handleUsernameInputChange(e.target.value)}
                onBlur={handleUsernameBlur}
                onKeyDown={handleUsernameKeyDown}
                aria-invalid={!!usernameValidationError}
                aria-describedby={usernameValidationError ? 'username-error' : undefined}
              />
              {usernameValidationError && (
                <div
                  id="username-error"
                  className="mt-1 flex items-start gap-1 text-xs text-red-600"
                  role="alert"
                >
                  <AlertTriangle className="w-3 h-3 flex-shrink-0 mt-0.5" aria-hidden="true" />
                  <span>{usernameValidationError}</span>
                </div>
              )}
            </div>

            <div>
              <label htmlFor="filter-success" className="block text-sm font-medium text-gray-700 mb-1">
                Status
              </label>
              <select
                id="filter-success"
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-primary-500"
                value={filters.success === undefined ? '' : filters.success.toString()}
                onChange={(e) =>
                  handleFilterChange(
                    'success',
                    e.target.value === '' ? undefined : e.target.value === 'true'
                  )
                }
              >
                <option value="">All</option>
                <option value="true">Success</option>
                <option value="false">Failed</option>
              </select>
            </div>

            <div className="flex items-end">
              <button
                onClick={handleClearFilters}
                className="w-full px-4 py-2 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-md transition"
              >
                Clear Filters
              </button>
            </div>
          </div>
        </div>

        {/* Logs Table */}
        <div className="bg-white rounded-lg shadow overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-200">
            <h2 className="text-lg font-semibold text-gray-900">Login Attempts</h2>
          </div>

          {logsError ? (
            <div className="p-6">
              <div className="bg-red-50 border border-red-200 rounded-lg p-4 flex items-start gap-2">
                <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" aria-label="Error" />
                <div>
                  <p className="text-sm font-medium text-red-800">Error loading logs</p>
                  <p className="text-xs text-red-600 mt-1">
                    {logsError instanceof AxiosError && logsError.response?.status === 403
                      ? 'Access denied. Admin privileges required.'
                      : 'Failed to load security logs. Please try again later.'}
                  </p>
                </div>
              </div>
            </div>
          ) : (
            <SecurityLogTable logs={logsData?.logs || []} isLoading={logsLoading} />
          )}

          {/* Pagination */}
          {logsData && logsData.total_pages > 1 && (
            <div className="px-6 py-4 border-t border-gray-200 flex items-center justify-between">
              <div className="text-sm text-gray-700">
                Showing page {logsData.page} of {logsData.total_pages} ({logsData.total} total
                records)
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={handlePreviousPage}
                  disabled={page === 1}
                  aria-label="Previous page"
                  className="px-3 py-1 border border-gray-300 rounded-md hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <ChevronLeft className="w-5 h-5" aria-hidden="true" />
                </button>
                <button
                  onClick={handleNextPage}
                  disabled={page >= logsData.total_pages}
                  aria-label="Next page"
                  className="px-3 py-1 border border-gray-300 rounded-md hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <ChevronRight className="w-5 h-5" aria-hidden="true" />
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
