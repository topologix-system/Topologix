/**
 * Application-wide constants
 * Version number, environment flags, and timezone configuration
 */
import { runtimeConfig } from './config/runtimeConfig'

export const APP_VERSION = '0.8.0-Alpha'

export const IS_PRODUCTION = import.meta.env.PROD

export const TIMEZONE = runtimeConfig.timezone
