import en from '../i18n/locales/en.json'

/**
 * English `t` for component tests: the en.json string at the key path, else its `_one` / `_other` form for a numeric
 * `count`, else the key itself; {{name}} placeholders are filled from `params`
 */
export function translateEn(key: string, params?: Record<string, unknown>): string {
  const lookup = (path: string) =>
    path
      .split('.')
      .reduce<unknown>(
        (node, part) => (node && typeof node === 'object' ? (node as Record<string, unknown>)[part] : undefined),
        en
      )
  let value = lookup(key)
  if (typeof value !== 'string' && typeof params?.count === 'number') {
    value = lookup(`${key}_${params.count === 1 ? 'one' : 'other'}`)
  }
  if (typeof value !== 'string') return key
  return value.replace(/\{\{(\w+)\}\}/g, (_, name: string) => String(params?.[name] ?? ''))
}
