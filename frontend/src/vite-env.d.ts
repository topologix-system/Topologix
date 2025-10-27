/**
 * Vite environment type declarations
 * Extends ImportMetaEnv to include custom environment variables
 * Used for type-safe access to import.meta.env.VITE_* variables
 */
/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE_URL: string
  readonly VITE_AUTH_ENABLED: string
  readonly VITE_TIMEZONE: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
