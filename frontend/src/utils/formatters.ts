/**
 * Data formatting utilities for UI display
 * - IP address, CIDR, timestamp formatters for network topology data
 * - Byte size (KB, MB, GB) and millisecond duration formatters
 * - Number abbreviation (K, M, B) for large values like route counts
 * - Consistent formatting across the application for better UX
 */

/**
 * Format date to localized string (year, month, day)
 * Uses Intl.DateTimeFormat for internationalization support
 * @param date - Date object, timestamp, or ISO string
 * @param locale - BCP 47 language tag (default: 'en')
 * @param options - Optional Intl date format options
 * @returns Formatted date string
 */
export function formatDate(
  date: Date | string | number,
  locale: string = 'en',
  options?: Intl.DateTimeFormatOptions
): string {
  const dateObj = typeof date === 'string' || typeof date === 'number' ? new Date(date) : date;

  const defaultOptions: Intl.DateTimeFormatOptions = {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    ...options,
  };

  return new Intl.DateTimeFormat(locale, defaultOptions).format(dateObj);
}

/**
 * Format date and time to localized string (year, month, day, hour, minute)
 * Combines date and time formatting for complete timestamp display
 * @param date - Date object, timestamp, or ISO string
 * @param locale - BCP 47 language tag (default: 'en')
 * @param options - Optional Intl date format options
 * @returns Formatted date-time string
 */
export function formatDateTime(
  date: Date | string | number,
  locale: string = 'en',
  options?: Intl.DateTimeFormatOptions
): string {
  const dateObj = typeof date === 'string' || typeof date === 'number' ? new Date(date) : date;

  const defaultOptions: Intl.DateTimeFormatOptions = {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    ...options,
  };

  return new Intl.DateTimeFormat(locale, defaultOptions).format(dateObj);
}

/**
 * Format time only to localized string (hour, minute, second)
 * Excludes date portion for time-only display
 * @param date - Date object, timestamp, or ISO string
 * @param locale - BCP 47 language tag (default: 'en')
 * @param options - Optional Intl date format options
 * @returns Formatted time string
 */
export function formatTime(
  date: Date | string | number,
  locale: string = 'en',
  options?: Intl.DateTimeFormatOptions
): string {
  const dateObj = typeof date === 'string' || typeof date === 'number' ? new Date(date) : date;

  const defaultOptions: Intl.DateTimeFormatOptions = {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    ...options,
  };

  return new Intl.DateTimeFormat(locale, defaultOptions).format(dateObj);
}

/**
 * Format date as relative time (e.g., "5 minutes ago", "2 days ago")
 * Uses Intl.RelativeTimeFormat for human-friendly time display
 * Automatically selects appropriate unit (seconds, minutes, hours, days, months, years)
 * @param date - Date object, timestamp, or ISO string
 * @param locale - BCP 47 language tag (default: 'en')
 * @returns Relative time string
 */
export function formatRelativeTime(
  date: Date | string | number,
  locale: string = 'en'
): string {
  const dateObj = typeof date === 'string' || typeof date === 'number' ? new Date(date) : date;
  const now = new Date();
  const diffInSeconds = Math.floor((now.getTime() - dateObj.getTime()) / 1000);

  const rtf = new Intl.RelativeTimeFormat(locale, { numeric: 'auto' });

  if (Math.abs(diffInSeconds) < 60) {
    return rtf.format(-diffInSeconds, 'second');
  }

  const diffInMinutes = Math.floor(diffInSeconds / 60);
  if (Math.abs(diffInMinutes) < 60) {
    return rtf.format(-diffInMinutes, 'minute');
  }

  const diffInHours = Math.floor(diffInMinutes / 60);
  if (Math.abs(diffInHours) < 24) {
    return rtf.format(-diffInHours, 'hour');
  }

  const diffInDays = Math.floor(diffInHours / 24);
  if (Math.abs(diffInDays) < 30) {
    return rtf.format(-diffInDays, 'day');
  }

  const diffInMonths = Math.floor(diffInDays / 30);
  if (Math.abs(diffInMonths) < 12) {
    return rtf.format(-diffInMonths, 'month');
  }

  const diffInYears = Math.floor(diffInMonths / 12);
  return rtf.format(-diffInYears, 'year');
}

/**
 * Format number with locale-specific separators
 * Uses Intl.NumberFormat for internationalization
 * @param value - Number to format
 * @param locale - BCP 47 language tag (default: 'en')
 * @param options - Optional Intl number format options
 * @returns Formatted number string
 */
export function formatNumber(
  value: number,
  locale: string = 'en',
  options?: Intl.NumberFormatOptions
): string {
  return new Intl.NumberFormat(locale, options).format(value);
}

/**
 * Format number as percentage (0-1 range to 0%-100%)
 * @param value - Decimal value (e.g., 0.75 for 75%)
 * @param locale - BCP 47 language tag (default: 'en')
 * @param decimals - Number of decimal places (default: 0)
 * @returns Formatted percentage string (e.g., "75%")
 */
export function formatPercent(
  value: number,
  locale: string = 'en',
  decimals: number = 0
): string {
  return new Intl.NumberFormat(locale, {
    style: 'percent',
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals,
  }).format(value);
}

/**
 * Format byte size to human-readable string (B, KB, MB, GB, TB)
 * Automatically selects appropriate unit based on size
 * @param bytes - Raw byte count
 * @param locale - BCP 47 language tag (default: 'en')
 * @param decimals - Number of decimal places (default: 2)
 * @returns Formatted size string (e.g., "1.25 MB")
 */
export function formatFileSize(
  bytes: number,
  locale: string = 'en',
  decimals: number = 2
): string {
  if (bytes === 0) return '0 Bytes';

  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  const value = bytes / Math.pow(k, i);

  return `${formatNumber(value, locale, {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals,
  })} ${sizes[i]}`;
}

/**
 * Format number as currency with symbol
 * Uses Intl.NumberFormat currency formatting
 * @param value - Numeric value to format
 * @param locale - BCP 47 language tag (default: 'en')
 * @param currency - ISO 4217 currency code (default: 'USD')
 * @returns Formatted currency string (e.g., "$1,234.56")
 */
export function formatCurrency(
  value: number,
  locale: string = 'en',
  currency: string = 'USD'
): string {
  return new Intl.NumberFormat(locale, {
    style: 'currency',
    currency,
  }).format(value);
}

/**
 * Format large numbers in compact notation (K, M, B)
 * Useful for route counts, interface counts, etc.
 * @param value - Number to format
 * @param locale - BCP 47 language tag (default: 'en')
 * @returns Compact number string (e.g., "1.2K", "3.5M")
 */
export function formatCompactNumber(
  value: number,
  locale: string = 'en'
): string {
  return new Intl.NumberFormat(locale, {
    notation: 'compact',
    compactDisplay: 'short',
  }).format(value);
}

/**
 * Format duration in seconds to human-readable string (hours, minutes, seconds)
 * Supports Japanese and English locales with appropriate units
 * @param seconds - Duration in seconds
 * @param locale - BCP 47 language tag (default: 'en')
 * @returns Formatted duration string (e.g., "2h 30m 15s" or "2時間 30分 15秒")
 */
export function formatDuration(
  seconds: number,
  locale: string = 'en'
): string {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = Math.floor(seconds % 60);

  const parts: string[] = [];

  if (hours > 0) {
    parts.push(`${hours}${locale === 'ja' ? '時間' : 'h'}`);
  }
  if (minutes > 0) {
    parts.push(`${minutes}${locale === 'ja' ? '分' : 'm'}`);
  }
  if (secs > 0 || parts.length === 0) {
    parts.push(`${secs}${locale === 'ja' ? '秒' : 's'}`);
  }

  return parts.join(' ');
}

/**
 * Format IP address (passthrough for future IPv6 formatting)
 * Currently returns IP as-is, placeholder for potential formatting
 * @param ip - IPv4 or IPv6 address string
 * @returns Formatted IP address string
 */
export function formatIPAddress(ip: string): string {
  return ip;
}

/**
 * Format MAC address to standard colon-separated uppercase format
 * Normalizes various MAC address formats (hyphens, colons, none) to XX:XX:XX:XX:XX:XX
 * @param mac - MAC address string in any format
 * @returns Standardized MAC address (e.g., "AA:BB:CC:DD:EE:FF")
 */
export function formatMACAddress(mac: string): string {
  return mac.replace(/[:-]/g, '').match(/.{1,2}/g)?.join(':').toUpperCase() || mac;
}

/**
 * Truncate long text with ellipsis
 * Useful for long interface names, hostnames, or descriptions
 * @param text - Text string to truncate
 * @param maxLength - Maximum length including ellipsis
 * @param ellipsis - Ellipsis string to append (default: "...")
 * @returns Truncated string with ellipsis if needed
 */
export function truncateText(
  text: string,
  maxLength: number,
  ellipsis: string = '...'
): string {
  if (text.length <= maxLength) {
    return text;
  }

  return text.slice(0, maxLength - ellipsis.length) + ellipsis;
}