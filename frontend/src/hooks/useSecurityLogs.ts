/**
 * React Query hooks for security audit logs
 * Handles login attempt tracking, security statistics, and audit log queries
 */
import { useQuery, keepPreviousData } from '@tanstack/react-query'
import { securityLogsAPI } from '../services/api'
import type { SecurityLogsQueryParams } from '../types'

/**
 * Query key factory for security logs-related React Query caches
 * Includes parameterized list queries for pagination and filtering
 */
export const securityLogsKeys = {
  all: ['security-logs'] as const,
  lists: () => [...securityLogsKeys.all, 'list'] as const,
  list: (params?: SecurityLogsQueryParams) => [...securityLogsKeys.lists(), params] as const,
  stats: () => [...securityLogsKeys.all, 'stats'] as const,
}

/**
 * Query paginated security audit logs
 * Returns login attempts, actions, and security events with pagination
 */
export function useSecurityLogs(params?: SecurityLogsQueryParams, enabled = true) {
  return useQuery({
    queryKey: securityLogsKeys.list(params),
    queryFn: () => securityLogsAPI.list(params),
    enabled,
    staleTime: 30000,
    placeholderData: keepPreviousData,
  })
}

/**
 * Query security statistics and metrics
 */
export function useSecurityStats(enabled = true) {
  return useQuery({
    queryKey: securityLogsKeys.stats(),
    queryFn: () => securityLogsAPI.getStats(),
    enabled,
    staleTime: 60000,
  })
}
