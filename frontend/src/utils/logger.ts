/**
 * Centralized logging utility for Topologix
 * Provides environment-aware logging that can be disabled in production
 * Uses Vite's import.meta.env for build-time optimization
 */

const isDevelopment = import.meta.env.DEV

/**
 * Logger interface with environment-aware methods
 * In production builds, debug and log are no-ops for performance
 * warn and error are always enabled for critical issues
 */
export const logger = {
  /**
   * Debug-level logging for detailed troubleshooting
   * Only active in development environment
   */
  debug: isDevelopment
    ? (...args: unknown[]) => console.debug(...args)
    : () => {},

  /**
   * Info-level logging for general information
   * Only active in development environment
   */
  log: isDevelopment
    ? (...args: unknown[]) => console.log(...args)
    : () => {},

  /**
   * Warning-level logging for non-critical issues
   * Always active in all environments
   */
  warn: (...args: unknown[]) => console.warn(...args),

  /**
   * Error-level logging for critical issues
   * Always active in all environments
   */
  error: (...args: unknown[]) => console.error(...args),
}
