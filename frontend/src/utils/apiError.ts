import { isAxiosError } from 'axios'

export interface StructuredApiError {
  message: string
  code?: string
  details?: unknown
  hints?: string[]
}

const SECRET_KEY_PATTERN = /password|secret|token|communities|community/i
const SECRET_MARKER_PATTERN = /(["']?[A-Za-z0-9_.-]*(?:password|secret|token|communities|community)[A-Za-z0-9_.-]*["']?)(\s*(?::|=)\s*|\s+)/gi

function sanitizeErrorText(value: string): string {
  const parts: string[] = []
  let cursor = 0
  let match: RegExpExecArray | null
  SECRET_MARKER_PATTERN.lastIndex = 0

  while ((match = SECRET_MARKER_PATTERN.exec(value)) !== null) {
    if (match.index > 0 && isIdentifierChar(value[match.index - 1])) {
      continue
    }

    const delimiter = match[2] ?? ''
    const valueStart = SECRET_MARKER_PATTERN.lastIndex
    if (!shouldRedactSecretValue(match[1] ?? '', delimiter, value, valueStart)) {
      continue
    }

    const valueEnd = secretValueEnd(value, valueStart)
    if (valueEnd <= valueStart) {
      continue
    }

    parts.push(value.slice(cursor, valueStart), '[redacted]')
    cursor = valueEnd
    SECRET_MARKER_PATTERN.lastIndex = valueEnd
  }

  parts.push(value.slice(cursor))
  return redactStandaloneBgpCommunities(parts.join(''))
}

function redactStandaloneBgpCommunities(value: string): string {
  return value.replace(/(?<![A-Za-z0-9_.:-])(?:\d{1,10}:){1,2}\d{1,10}(?![A-Za-z0-9_.:-])/g, '[redacted]')
}

function shouldRedactSecretValue(marker: string, delimiter: string, value: string, valueStart: number): boolean {
  if (delimiter.includes(':') || delimiter.includes('=')) return true
  if (valueStart >= value.length) return false
  if (value[valueStart] === '"' || value[valueStart] === "'" || value[valueStart] === '[' || value[valueStart] === '{') {
    return true
  }
  return marker.toLowerCase().includes('communit') && startsWithBgpCommunity(value, valueStart)
}

function startsWithBgpCommunity(value: string, valueStart: number): boolean {
  return /^(?:\d{1,10}:){1,2}\d{1,10}(?=$|[\s,;}\]])/.test(value.slice(valueStart))
}

function isIdentifierChar(value: string): boolean {
  return /^[A-Za-z0-9_]$/.test(value)
}

function secretValueEnd(value: string, start: number): number {
  if (start >= value.length) return start

  const first = value[start]
  if (first === '"' || first === "'") return consumeQuotedSecretValue(value, start, first)
  if (first === '[' || first === '{') return consumeBalancedSecretValue(value, start)

  let index = start
  while (index < value.length && !/[\s,;}\]]/.test(value[index])) {
    index += 1
  }
  return index
}

function consumeQuotedSecretValue(value: string, start: number, quote: string): number {
  let index = start + 1
  let escaped = false
  while (index < value.length) {
    const char = value[index]
    if (escaped) {
      escaped = false
    } else if (char === '\\') {
      escaped = true
    } else if (char === quote) {
      return index + 1
    }
    index += 1
  }
  return value.length
}

function consumeBalancedSecretValue(value: string, start: number): number {
  const pairs: Record<string, string> = { '[': ']', '{': '}' }
  const stack = [pairs[value[start]]]
  let index = start + 1
  let quote: string | null = null
  let escaped = false

  while (index < value.length) {
    const char = value[index]
    if (quote) {
      if (escaped) {
        escaped = false
      } else if (char === '\\') {
        escaped = true
      } else if (char === quote) {
        quote = null
      }
    } else if (char === '"' || char === "'") {
      quote = char
    } else if (char in pairs) {
      stack.push(pairs[char])
    } else if (stack.length > 0 && char === stack[stack.length - 1]) {
      stack.pop()
      if (stack.length === 0) return index + 1
    }
    index += 1
  }

  return value.length
}

export function sanitizeErrorPayload(value: unknown): unknown {
  if (typeof value === 'string') {
    return sanitizeErrorText(value)
  }
  if (Array.isArray(value)) {
    return value.map((item) => sanitizeErrorPayload(item))
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, item]) => [
        key,
        SECRET_KEY_PATTERN.test(key) ? '[redacted]' : sanitizeErrorPayload(item),
      ])
    )
  }
  return value
}

function isStructuredApiError(value: unknown): value is StructuredApiError {
  return Boolean(
    value &&
    typeof value === 'object' &&
    'message' in value &&
    typeof (value as { message?: unknown }).message === 'string'
  )
}

export function getStructuredApiError(error: unknown): StructuredApiError {
  if (isAxiosError(error)) {
    const responseData = sanitizeErrorPayload(error.response?.data)
    if (isStructuredApiError(responseData)) {
      return {
        message: responseData.message,
        code: typeof responseData.code === 'string' ? responseData.code : undefined,
        details: responseData.details,
        hints: Array.isArray(responseData.hints) ? responseData.hints : undefined,
      }
    }
    if (error.message) {
      return { message: sanitizeErrorText(error.message) }
    }
  }

  if (error instanceof Error) {
    return { message: sanitizeErrorText(error.message) }
  }

  return { message: sanitizeErrorText(String(error)) }
}

export function getSafeApiErrorLog(error: unknown): Record<string, unknown> {
  if (isAxiosError(error)) {
    const responseData = sanitizeErrorPayload(error.response?.data)
    const structured = isStructuredApiError(responseData) ? responseData : undefined
    return {
      status: error.response?.status,
      code: structured?.code,
      message: structured?.message ?? sanitizeErrorText(error.message),
    }
  }

  if (error instanceof Error) {
    return { message: sanitizeErrorText(error.message) }
  }

  return { message: sanitizeErrorText(String(error)) }
}
