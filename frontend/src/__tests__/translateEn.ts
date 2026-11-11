import en from '../i18n/locales/en.json'

/**
 * English `t` for component tests: the en.json string at the key path with {{name}} placeholders filled,
 * or the key itself when en.json has no string there
 */
export function translateEn(key: string, params?: Record<string, unknown>): string {
  const value = key
    .split('.')
    .reduce<unknown>(
      (node, part) => (node && typeof node === 'object' ? (node as Record<string, unknown>)[part] : undefined),
      en
    )
  if (typeof value !== 'string') return key
  return value.replace(/\{\{(\w+)\}\}/g, (_, name: string) => String(params?.[name] ?? ''))
}
