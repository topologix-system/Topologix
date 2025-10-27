declare global {
  interface Window {
    __TOPOLOGIX_CONFIG__?: Partial<RuntimeConfig>
  }
}

export interface RuntimeConfig {
  apiBaseUrl: string
  authEnabled: boolean
  timezone: string
}

function getDefaultConfig(): RuntimeConfig {
  const parseBool = (value: string | undefined, fallback: boolean): boolean => {
    if (value === undefined) return fallback
    const normalized = value.toString().trim().toLowerCase()
    if (['true', '1', 'yes'].includes(normalized)) return true
    if (['false', '0', 'no'].includes(normalized)) return false
    return fallback
  }

  return {
    apiBaseUrl: import.meta.env.VITE_API_BASE_URL || '',
    authEnabled: parseBool(import.meta.env.VITE_AUTH_ENABLED, true),
    timezone: import.meta.env.VITE_TIMEZONE || 'Asia/Tokyo',
  }
}

export const runtimeConfig: RuntimeConfig = ((): RuntimeConfig => {
  const defaults = getDefaultConfig()

  if (typeof window === 'undefined') {
    return defaults
  }

  const overrides = window.__TOPOLOGIX_CONFIG__ || {}

  return {
    apiBaseUrl: overrides.apiBaseUrl ?? defaults.apiBaseUrl,
    authEnabled:
      typeof overrides.authEnabled === 'boolean' ? overrides.authEnabled : defaults.authEnabled,
    timezone: overrides.timezone ?? defaults.timezone,
  }
})()
