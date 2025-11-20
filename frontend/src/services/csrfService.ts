/**
 * CSRF Token Management for Double-Submit Cookie Pattern
 *
 * Handles cookie reading and validation for stateless CSRF protection.
 * Follows OWASP 2024 best practices for client-side token management.
 *
 * Key Features:
 * - Cookie-based token storage (HttpOnly=false for JS access)
 * - Token expiration validation
 * - Automatic token refresh
 * - Integration with backend double-submit pattern
 */

import { logger } from '../utils/logger';
import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '';

export class CSRFService {
  private static readonly COOKIE_NAME = 'csrf_token';
  private static readonly HEADER_NAME = 'X-CSRF-Token';
  private static memoryToken: string | null = null;

  /**
   * Store CSRF token in memory for immediate availability
   * Used after login to prevent race condition with cookie propagation
   *
   * @param token CSRF token to store
   */
  static setMemoryToken(token: string): void {
    this.memoryToken = token;
    logger.debug('[CSRFService] Token stored in memory for immediate use');
  }

  /**
   * Read CSRF token from cookie
   * Note: Cookie must have HttpOnly=false for JavaScript access
   *
   * @returns CSRF token or null if not found
   */
  static getTokenFromCookie(): string | null {
    const cookies = document.cookie.split(';');

    for (const cookie of cookies) {
      const trimmed = cookie.trim();
      const equalsIndex = trimmed.indexOf('=');

      if (equalsIndex === -1) continue;

      const name = trimmed.substring(0, equalsIndex);
      const value = trimmed.substring(equalsIndex + 1);

      if (name === this.COOKIE_NAME) {
        const decodedValue = decodeURIComponent(value);
        logger.debug(`[CSRFService] Token found in cookie: ${decodedValue.substring(0, 20)}...`);
        return decodedValue;
      }
    }

    logger.debug('[CSRFService] No token found in cookie');
    return null;
  }

  /**
   * Check if CSRF token exists and is not expired
   *
   * @returns true if token is valid and not expired
   */
  static hasValidToken(): boolean {
    const token = this.getTokenFromCookie();
    if (!token) {
      logger.debug('[CSRFService] No token available');
      return false;
    }

    try {
      // Extract payload from signed token (format: payload_b64.signature)
      const [payloadB64] = token.split('.');
      if (!payloadB64) {
        logger.warn('[CSRFService] Invalid token format');
        return false;
      }

      // Decode base64 payload
      const payloadJson = atob(payloadB64);
      const payload = JSON.parse(payloadJson);

      // Check expiration
      const expires = new Date(payload.expires);
      const now = new Date();

      if (expires <= now) {
        logger.debug('[CSRFService] Token expired');
        return false;
      }

      logger.debug(`[CSRFService] Token valid (expires: ${expires.toISOString()})`);
      return true;
    } catch (error) {
      logger.warn('[CSRFService] Token validation error:', error);
      return false;
    }
  }

  /**
   * Request new CSRF token from server
   *
   * @returns Promise resolving to new CSRF token
   * @throws Error if token refresh fails
   */
  static async refreshToken(): Promise<string> {
    try {
      logger.info('[CSRFService] Refreshing CSRF token from server');

      // Get access token for authorization
      const accessToken = sessionStorage.getItem('access_token') || localStorage.getItem('access_token');
      if (!accessToken) {
        throw new Error('No access token available for CSRF token refresh');
      }

      const response = await axios.get(`${API_BASE_URL}/api/auth/csrf-token`, {
        headers: {
          'Authorization': `Bearer ${accessToken}`
        },
        withCredentials: true  // Important for cookie handling
      });

      if (!response.data || !response.data.data || !response.data.data.csrf_token) {
        throw new Error('Invalid CSRF token response from server');
      }

      const newToken = response.data.data.csrf_token;
      logger.info('[CSRFService] CSRF token refreshed successfully');
      return newToken;
    } catch (error) {
      logger.error('[CSRFService] Failed to refresh CSRF token:', error);
      throw new Error(`Failed to refresh CSRF token: ${error}`);
    }
  }

  /**
   * Get CSRF token asynchronously with automatic refresh and retry
   * This is the PRIMARY method for token retrieval in async contexts
   *
   * Uses multi-tier strategy:
   * 1. Check memory cache (immediate, post-login)
   * 2. Check cookie (valid existing token)
   * 3. Refresh from server with retry logic
   *
   * @param retryCount - Internal retry counter (default: 0)
   * @returns Promise resolving to valid CSRF token
   * @throws Error if token cannot be obtained after retries
   */
  static async getToken(retryCount = 0): Promise<string> {
    const MAX_RETRIES = 2;

    // Priority 1: Check memory token (immediate availability after login)
    if (this.memoryToken) {
      logger.debug('[CSRFService] Using memory token (async)');
      return this.memoryToken;
    }

    // Priority 2: Check cookie token (valid existing token)
    if (this.hasValidToken()) {
      const token = this.getTokenFromCookie();
      if (token) {
        logger.debug('[CSRFService] Using existing valid cookie token (async)');
        return token;
      }
    }

    // Priority 3: Refresh from server with retry logic
    try {
      logger.info('[CSRFService] Token invalid or missing, requesting new token');
      const newToken = await this.refreshToken();

      // Store in memory for immediate subsequent requests
      this.memoryToken = newToken;
      logger.debug('[CSRFService] New token stored in memory cache');

      return newToken;
    } catch (error) {
      if (retryCount < MAX_RETRIES) {
        logger.warn(`[CSRFService] Token refresh failed (attempt ${retryCount + 1}/${MAX_RETRIES}), retrying...`);

        // Exponential backoff: 100ms, 200ms
        const backoffMs = 100 * Math.pow(2, retryCount);
        await new Promise(resolve => setTimeout(resolve, backoffMs));

        return this.getToken(retryCount + 1);
      }

      logger.error(`[CSRFService] Token refresh failed after ${MAX_RETRIES} retries`);
      throw new Error(`Failed to obtain CSRF token after ${MAX_RETRIES} retries: ${error}`);
    }
  }

  /**
   * @deprecated Use async getToken() instead for better reliability
   *
   * Get CSRF token synchronously (returns null if not available)
   *
   * **DEPRECATED:** This method is deprecated and will be removed in a future version.
   * Use the async `getToken()` method in request interceptors instead for:
   * - Automatic token refresh on expiration
   * - Built-in retry logic with exponential backoff
   * - Better error handling
   *
   * This synchronous method is kept for backward compatibility during migration
   * but may return null in scenarios where async refresh would succeed.
   *
   * Uses memory-first strategy:
   * 1. Check memory cache (immediate availability after login)
   * 2. Check cookie (fallback for page reload)
   *
   * @returns CSRF token or null if not immediately available
   */
  static getTokenSync(): string | null {
    // Priority 1: Memory cache (immediate availability, no race condition)
    if (this.memoryToken) {
      logger.debug('[CSRFService] Token retrieved from memory (DEPRECATED METHOD - use async getToken())');
      return this.memoryToken;
    }

    // Priority 2: Cookie (fallback for page reload)
    if (this.hasValidToken()) {
      const token = this.getTokenFromCookie();
      if (token) {
        logger.debug('[CSRFService] Token retrieved from cookie (DEPRECATED METHOD - use async getToken())');
        return token;
      }
    }

    logger.warn('[CSRFService] getTokenSync() called but no token available - migrate to async getToken()');
    return null;
  }

  /**
   * Check if a token is immediately available without network request
   * Useful for deciding whether to make async refresh call
   *
   * @returns true if token is available in memory or valid cookie exists
   */
  static hasTokenAvailable(): boolean {
    return !!this.memoryToken || this.hasValidToken();
  }

  /**
   * Clear CSRF token (typically on logout)
   * Clears memory cache. Cookie clearing is handled by server.
   */
  static clearToken(): void {
    // Clear memory token
    this.memoryToken = null;
    // Cookie clearing is done by server (HttpOnly=false allows JS access but server manages lifecycle)
    logger.debug('[CSRFService] Memory token cleared');
  }
}
