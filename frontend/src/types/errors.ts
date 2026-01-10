/**
 * Error handling type definitions and utilities
 * Provides type-safe error extraction from API responses
 */
import { AxiosError } from 'axios'

/**
 * Standard API error response structure
 * Used for type-safe error message extraction
 */
export interface ApiErrorResponse {
  message?: string
  error?: string
  code?: string
}

/**
 * Type guard to check if an object has a message property
 */
function hasMessage(data: unknown): data is { message: string } {
  return (
    typeof data === 'object' &&
    data !== null &&
    'message' in data &&
    typeof (data as Record<string, unknown>).message === 'string'
  )
}

/**
 * Extract error message from AxiosError response
 * Safely handles unknown error types without unsafe type casts
 * @param error - The AxiosError to extract message from
 * @param fallback - Fallback message if extraction fails
 * @returns Extracted error message or fallback
 */
export function extractAxiosErrorMessage(
  error: AxiosError,
  fallback: string
): string {
  const data = error.response?.data
  if (hasMessage(data)) {
    return data.message
  }
  return error.message || fallback
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
    return error.message
  }
  return fallback
}
