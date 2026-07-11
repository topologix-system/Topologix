/**
 * Application-wide constants
 * Version number, environment flags, and timezone configuration
 */
import { runtimeConfig } from './config/runtimeConfig'

export const APP_VERSION = '1.3.0'

export const IS_PRODUCTION = import.meta.env.PROD

export const TIMEZONE = runtimeConfig.timezone
