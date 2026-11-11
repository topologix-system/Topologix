import { describe, expect, it } from 'vitest'

import en from './locales/en.json'
import ja from './locales/ja.json'

function keyPaths(node: unknown, prefix = ''): string[] {
  if (!node || typeof node !== 'object') return [prefix]
  return Object.entries(node).flatMap(([key, value]) => keyPaths(value, prefix ? `${prefix}.${key}` : key))
}

describe('locale files', () => {
  it('define the same keys in English and Japanese', () => {
    expect(keyPaths(ja).sort()).toEqual(keyPaths(en).sort())
  })
})
