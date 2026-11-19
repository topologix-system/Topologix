/**
 * Traceroute step detail as `key: value` lines: objects and arrays of objects nest below their key, arrays of
 * scalars join into one line, empty values are left out at every level and a `type` field comes first in its object
 */
export type StepDetailValue =
  | { kind: 'text'; text: string }
  | { kind: 'entries'; entries: StepDetailEntry[] }
  | { kind: 'list'; items: StepDetailValue[] }

export interface StepDetailEntry {
  key: string
  value: StepDetailValue
}

const isScalar = (value: unknown) => value === null || typeof value !== 'object'

const isEmptyScalar = (value: unknown) => value === null || value === undefined || value === ''

function orderedKeys(record: Record<string, unknown>): string[] {
  const keys = Object.keys(record)
  return keys.includes('type') ? ['type', ...keys.filter((key) => key !== 'type')] : keys
}

function describeValue(value: unknown): StepDetailValue | null {
  if (isEmptyScalar(value)) return null

  if (Array.isArray(value)) {
    if (value.every(isScalar)) {
      const texts = value.filter((item) => !isEmptyScalar(item)).map(String)
      return texts.length > 0 ? { kind: 'text', text: texts.join(', ') } : null
    }
    const items = value.map(describeValue).filter((item): item is StepDetailValue => item !== null)
    return items.length > 0 ? { kind: 'list', items } : null
  }

  if (typeof value === 'object') {
    const record = value as Record<string, unknown>
    const entries = orderedKeys(record).flatMap((key) => {
      const described = describeValue(record[key])
      return described ? [{ key, value: described }] : []
    })
    return entries.length > 0 ? { kind: 'entries', entries } : null
  }

  return { kind: 'text', text: String(value) }
}

function fallbackText(detail: unknown): string {
  try {
    return JSON.stringify(detail) ?? String(detail)
  } catch {
    return Object.prototype.toString.call(detail)
  }
}

/**
 * Display structure of a step detail, or null when it has nothing to show
 */
export function describeStepDetail(detail: unknown): StepDetailValue | null {
  try {
    return describeValue(detail)
  } catch {
    return { kind: 'text', text: fallbackText(detail) }
  }
}
