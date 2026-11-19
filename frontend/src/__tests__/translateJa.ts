import ja from '../i18n/locales/ja.json'

/**
 * Japanese `t` for component tests: the ja.json string at the key path, else its `_other` form for a numeric
 * `count`, else the key itself; {{name}} placeholders are filled from `params`
 */
export function translateJa(key: string, params?: Record<string, unknown>): string {
  const lookup = (path: string) =>
    path
      .split('.')
      .reduce<unknown>(
        (node, part) => (node && typeof node === 'object' ? (node as Record<string, unknown>)[part] : undefined),
        ja
      )
  let value = lookup(key)
  if (typeof value !== 'string' && typeof params?.count === 'number') {
    value = lookup(`${key}_other`)
  }
  if (typeof value !== 'string') return key
  return value.replace(/\{\{(\w+)\}\}/g, (_, name: string) => String(params?.[name] ?? ''))
}
