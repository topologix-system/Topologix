/**
 * JWT Token Management Utilities
 * Handles token expiration checking without external dependencies
 * Provides token decoding, validation, and expiration time calculations
 */

import { logger } from '../../utils/logger'

interface DecodedToken {
  exp: number
  iat: number
  sub?: string
  [key: string]: unknown
}

/**
 * Decode JWT token without external library
 * Parses base64-encoded JWT payload to extract claims
 * @param token - JWT token string
 * @returns Decoded token payload or null if invalid
 */
export function decodeJWT(token: string): DecodedToken | null {
  try {
    const base64Url = token.split('.')[1]
    if (!base64Url) return null

    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/')
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    )

    return JSON.parse(jsonPayload)
  } catch (error) {
    logger.error('[tokenManager] Failed to decode JWT:', error)
    return null
  }
}

/**
 * Check if JWT token is expired
 * Includes 30-second buffer to handle clock skew between client and server
 * @param token - JWT token string
 * @returns true if token is expired or invalid, false otherwise
 */
export function isTokenExpired(token: string | null): boolean {
  if (!token) return true

  const decoded = decodeJWT(token)
  if (!decoded || !decoded.exp) return true

  // Token expiration is in seconds, Date.now() is in milliseconds
  const currentTime = Date.now() / 1000

  // Add 30 second buffer to handle clock skew
  return decoded.exp < currentTime + 30
}

/**
 * Get remaining time until token expires (in milliseconds)
 * Useful for implementing token refresh before expiration
 * @param token - JWT token string
 * @returns Milliseconds until expiration, or 0 if expired/invalid
 */
export function getTokenExpirationTime(token: string | null): number {
  if (!token) return 0

  const decoded = decodeJWT(token)
  if (!decoded || !decoded.exp) return 0

  const currentTime = Date.now()
  const expirationTime = decoded.exp * 1000

  return Math.max(0, expirationTime - currentTime)
}

/**
 * Get token expiration date as Date object
 * @param token - JWT token string
 * @returns Date object representing expiration time, or null if invalid
 */
export function getTokenExpirationDate(token: string | null): Date | null {
  if (!token) return null

  const decoded = decodeJWT(token)
  if (!decoded || !decoded.exp) return null

  return new Date(decoded.exp * 1000)
}
