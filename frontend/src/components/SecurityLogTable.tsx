/**
 * Security audit log table component with timezone-aware formatting
 * - Helper functions: parseAsUtc for timestamp normalization, timeAgo for relative times
 * - formatDateInTimezone using Intl.DateTimeFormat for configurable timezone display
 * - Success/fail indicators with color-coded status badges (green/red)
 * - Displays IP address, username, timestamp, user agent, and login success status
 * - Used in SecurityLogsPage for admin security audit tracking
 */
import { CheckCircle, XCircle, Monitor, User, Calendar } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import type { SecurityLog } from '../types'
import { TIMEZONE } from '../constants'
import { logger } from '../utils/logger'

/**
 * Parse timestamp string as UTC if no timezone indicator present
 * Handles timezone-naive timestamps from backend by appending 'Z'
 * @param timestamp - ISO 8601 timestamp string
 * @returns Date object in UTC
 */
function parseAsUtc(timestamp: string): Date {
  if (!timestamp.endsWith('Z') && !/[+-]\d{2}:\d{2}$/.test(timestamp)) {
    return new Date(timestamp + 'Z')
  }
  return new Date(timestamp)
}

/**
 * Convert date to human-readable relative time string
 * @param date - Date object to convert
 * @returns Relative time string (e.g., "5 minutes ago", "2 days ago")
 */
function timeAgo(date: Date): string {
  const now = new Date()
  const seconds = Math.floor((now.getTime() - date.getTime()) / 1000)

  if (seconds < 60) return 'just now'
  if (seconds < 3600) return `${Math.floor(seconds / 60)} minutes ago`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} hours ago`
  if (seconds < 2592000) return `${Math.floor(seconds / 86400)} days ago`
  if (seconds < 31536000) return `${Math.floor(seconds / 2592000)} months ago`
  return `${Math.floor(seconds / 31536000)} years ago`
}

/**
 * Format date in specified timezone using Intl.DateTimeFormat
 * Falls back to ISO string if timezone is invalid
 * @param date - Date object to format
 * @param timezone - IANA timezone identifier (e.g., "Asia/Tokyo")
 * @returns Formatted date string in "YYYY/MM/DD HH:mm:ss" format
 */
function formatDateInTimezone(date: Date, timezone: string): string {
  try {
    return new Intl.DateTimeFormat('ja-JP', {
      timeZone: timezone,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    }).format(date)
  } catch (error) {
    logger.error(`Invalid timezone: ${timezone}`, error)
    return date.toISOString().replace('T', ' ').substring(0, 19)
  }
}

interface SecurityLogTableProps {
  logs: SecurityLog[]
  isLoading?: boolean
}

export function SecurityLogTable({ logs, isLoading }: SecurityLogTableProps) {
  const { t } = useTranslation()

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600" />
      </div>
    )
  }

  if (!logs || logs.length === 0) {
    return (
      <div className="text-center py-12 text-gray-500">
        <p>{t('securityLogs.table.noLogs')}</p>
      </div>
    )
  }

  return (
    <table className="min-w-full divide-y divide-gray-200">
      <thead className="bg-gray-50">
        <tr>
          <th
            scope="col"
            className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
          >
            {t('securityLogs.table.status')}
          </th>
          <th
            scope="col"
            className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
          >
            {t('securityLogs.table.time')}
          </th>
          <th
            scope="col"
            className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
          >
            {t('securityLogs.table.ipAddress')}
          </th>
          <th
            scope="col"
            className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
          >
            {t('securityLogs.table.username')}
          </th>
          <th
            scope="col"
            className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
          >
            {t('securityLogs.table.userAgent')}
          </th>
        </tr>
      </thead>
      <tbody className="bg-white divide-y divide-gray-200">
        {logs.map((log) => (
          <tr key={log.id} className="hover:bg-gray-50">
            <td className="px-6 py-4 whitespace-nowrap">
              {log.success ? (
                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                  <CheckCircle className="w-4 h-4 mr-1" />
                  {t('securityLogs.table.success')}
                </span>
              ) : (
                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                  <XCircle className="w-4 h-4 mr-1" />
                  {t('securityLogs.table.failed')}
                </span>
              )}
            </td>
            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
              <div className="flex items-center">
                <Calendar className="w-4 h-4 mr-2 text-gray-400" />
                <div>
                  <div className="font-medium">
                    {formatDateInTimezone(parseAsUtc(log.attempt_time), TIMEZONE)}
                  </div>
                  <div className="text-xs text-gray-500">
                    {timeAgo(parseAsUtc(log.attempt_time))}
                  </div>
                </div>
              </div>
            </td>
            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 font-mono">
              {log.ip_address}
            </td>
            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
              {log.username ? (
                <div className="flex items-center">
                  <User className="w-4 h-4 mr-2 text-gray-400" />
                  <span className="font-medium">{log.username}</span>
                </div>
              ) : (
                <span className="text-gray-400 italic">N/A</span>
              )}
            </td>
            <td className="px-6 py-4 text-sm text-gray-500">
              {log.user_agent ? (
                <div className="flex items-center max-w-md">
                  <Monitor className="w-4 h-4 mr-2 flex-shrink-0 text-gray-400" />
                  <span className="truncate" title={log.user_agent}>
                    {log.user_agent}
                  </span>
                </div>
              ) : (
                <span className="text-gray-400 italic">N/A</span>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
