/**
 * CSRF Token Management for Double-Submit Cookie Pattern
 */

import { logger } from '../utils/logger';
import axios from 'axios';
import { runtimeConfig } from '../config/runtimeConfig';
import { getSafeApiErrorLog } from '../utils/apiError';

const API_BASE_URL = runtimeConfig.apiBaseUrl || '';

export class CSRFService {
  private static readonly COOKIE_NAME = 'csrf_token';
  private static memoryToken: string | null = null;

  private static getSafeErrorMessage(error: unknown): string {
    const safeError = getSafeApiErrorLog(error);
    return typeof safeError.message === 'string' ? safeError.message : 'unknown error';
  }

  /**
   * Store CSRF token in memory for immediate availability
   */
  static setMemoryToken(token: string): void {
    this.memoryToken = token;
    logger.debug('[CSRFService] Token stored in memory for immediate use');
  }

  /**
   * Read CSRF token from cookie
   * Note: Cookie must have HttpOnly=false for JavaScript access
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
        logger.debug('[CSRFService] Token found in cookie');
        return decodedValue;
      }
    }

    logger.debug('[CSRFService] No token found in cookie');
    return null;
  }

  /**
   * Check if CSRF token exists and is not expired
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

      const payloadJson = atob(payloadB64);
      const payload = JSON.parse(payloadJson);

      const expires = new Date(payload.expires);
      const now = new Date();

      if (expires <= now) {
        logger.debug('[CSRFService] Token expired');
        return false;
      }

      logger.debug(`[CSRFService] Token valid (expires: ${expires.toISOString()})`);
      return true;
    } catch (error) {
      logger.warn('[CSRFService] Token validation error:', getSafeApiErrorLog(error));
      return false;
    }
  }

  /**
   * Request new CSRF token from server
   */
  static async refreshToken(): Promise<string> {
    try {
      logger.info('[CSRFService] Refreshing CSRF token from server');

      const response = await axios.get(`${API_BASE_URL}/api/auth/csrf-token`, {
        withCredentials: true,
        headers: {
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache',
        },
      });

      if (!response.data || !response.data.data || !response.data.data.csrf_token) {
        throw new Error('Invalid CSRF token response from server');
      }

      const newToken = response.data.data.csrf_token;
      logger.info('[CSRFService] CSRF token refreshed successfully');
      return newToken;
    } catch (error) {
      const safeMessage = this.getSafeErrorMessage(error);
      logger.error('[CSRFService] Failed to refresh CSRF token:', getSafeApiErrorLog(error));
      throw new Error(`Failed to refresh CSRF token: ${safeMessage}`);
    }
  }

  /**
   * Get CSRF token asynchronously with automatic refresh and retry
   */
  static async getToken(retryCount = 0): Promise<string> {
    const MAX_RETRIES = 2;

    if (this.memoryToken) {
      logger.debug('[CSRFService] Using memory token (async)');
      return this.memoryToken;
    }

    if (this.hasValidToken()) {
      const token = this.getTokenFromCookie();
      if (token) {
        logger.debug('[CSRFService] Using existing valid cookie token (async)');
        return token;
      }
    }

    try {
      logger.info('[CSRFService] Token invalid or missing, requesting new token');
      const newToken = await this.refreshToken();

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

      const safeMessage = this.getSafeErrorMessage(error);
      logger.error(`[CSRFService] Token refresh failed after ${MAX_RETRIES} retries`);
      throw new Error(`Failed to obtain CSRF token after ${MAX_RETRIES} retries: ${safeMessage}`);
    }
  }

  /**
   * @deprecated Use async getToken() instead for better reliability
   *
   * Get CSRF token synchronously (returns null if not available)
   */
  static getTokenSync(): string | null {
    if (this.memoryToken) {
      logger.debug('[CSRFService] Token retrieved from memory (DEPRECATED METHOD - use async getToken())');
      return this.memoryToken;
    }

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
   */
  static hasTokenAvailable(): boolean {
    return !!this.memoryToken || this.hasValidToken();
  }

  /**
   * Force-refresh CSRF token from server, bypassing memory and cookie cache.
   */
  static async forceRefresh(retryCount = 0): Promise<string> {
    const MAX_RETRIES = 2;
    this.memoryToken = null;
    logger.info('[CSRFService] Force-refreshing token (cache cleared)');
    try {
      const newToken = await this.refreshToken();
      this.memoryToken = newToken;
      return newToken;
    } catch (error) {
      if (retryCount < MAX_RETRIES) {
        logger.warn(`[CSRFService] Force-refresh failed (attempt ${retryCount + 1}/${MAX_RETRIES}), retrying...`);
        const backoffMs = 100 * Math.pow(2, retryCount);
        await new Promise(resolve => setTimeout(resolve, backoffMs));
        return this.forceRefresh(retryCount + 1);
      }
      const safeMessage = this.getSafeErrorMessage(error);
      logger.error(`[CSRFService] Force-refresh failed after ${MAX_RETRIES} retries`);
      throw new Error(`Failed to force-refresh CSRF token after ${MAX_RETRIES} retries: ${safeMessage}`);
    }
  }

  /**
   * Clear the in-memory CSRF token
   */
  static clearToken(): void {
    this.memoryToken = null;
    logger.debug('[CSRFService] Memory token cleared');
  }
}
