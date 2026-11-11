/**
 * Error handling type definitions and utilities
 * Provides type-safe error extraction from API responses
 */
import { AxiosError } from 'axios'
import i18n from 'i18next'

/**
 * Standard API error response structure
 * Used for type-safe error message extraction
 */
export interface ApiErrorResponse {
  message?: string
  error?: string
  code?: string
  details?: unknown
}

function nonEmptyString(value: unknown): string | null {
  return typeof value === 'string' && value.trim() !== '' ? value : null
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null
}

/**
 * Extract the server-provided reason from an API error response body
 * Reads `message`, then `error`, then `details.message` / `details.reason`
 * @param data - The response body (non-JSON bodies such as HTML yield null)
 * @returns The server message, or null when the body carries none
 */
export function extractResponseBodyMessage(data: unknown): string | null {
  const body = asRecord(data)
  if (!body) return null

  const direct = nonEmptyString(body.message) ?? nonEmptyString(body.error)
  if (direct) return direct

  const details = asRecord(body.details)
  if (!details) return null
  return nonEmptyString(details.message) ?? nonEmptyString(details.reason)
}

/**
 * Extract error message from AxiosError response
 * With a response: server response body message, then the fallback, then the AxiosError message
 * Without a response (network down, CORS, timeout): the localized network error for ERR_NETWORK,
 * otherwise the AxiosError message (e.g. "timeout of 120000ms exceeded"), then the fallback
 * @param error - The AxiosError to extract message from
 * @param fallback - Message used when the response body carries no message
 * @returns Extracted error message or fallback
 */
export function extractAxiosErrorMessage(
  error: AxiosError,
  fallback: string
): string {
  if (!error.response) {
    const networkMessage =
      error.code === AxiosError.ERR_NETWORK ? i18n.t('errors.networkError', { defaultValue: '' }) : ''
    return networkMessage || error.message || fallback
  }
  return extractResponseBodyMessage(error.response.data) ?? (fallback || error.message)
}

/**
 * Extract error message from unknown error type
 * Handles AxiosError, Error, and unknown types
 * @param error - The error to extract message from
 * @param fallback - Fallback message if extraction fails
 * @returns Extracted error message or fallback
 */
export function extractErrorMessage(
  error: unknown,
  fallback: string
): string {
  if (error instanceof AxiosError) {
    return extractAxiosErrorMessage(error, fallback)
  }
  if (error instanceof Error) {
    return error.message || fallback
  }
  return fallback
}
