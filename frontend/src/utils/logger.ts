/**
 * Centralized logging utility for Topologix
 */

const isDevelopment = import.meta.env.DEV

/**
 * Logger interface with environment-aware methods
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
   * Info-level logging
   * Only active in development environment
   */
  info: isDevelopment
    ? (...args: unknown[]) => console.info(...args)
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
