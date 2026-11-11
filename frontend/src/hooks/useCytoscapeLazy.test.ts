import type { MutableRefObject } from 'react'
import { renderHook } from '@testing-library/react'
import type { Core } from 'cytoscape'
import { describe, expect, it, vi } from 'vitest'

import { useCytoscapeLazy } from './useCytoscapeLazy'

const PNG_BASE64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=='

function fakeCytoscapePng(options: { output?: string } = {}) {
  return options.output === 'base64' ? PNG_BASE64 : `data:image/png;base64,${PNG_BASE64}`
}

describe('useCytoscapeLazy exportPNG', () => {
  it('returns a PNG data URI usable as a download link href', () => {
    const png = vi.fn(fakeCytoscapePng)
    const { result } = renderHook(() => useCytoscapeLazy())
    ;(result.current.cyRef as MutableRefObject<Core | null>).current = { png } as unknown as Core

    expect(result.current.exportPNG()).toBe(`data:image/png;base64,${PNG_BASE64}`)
    expect(png).toHaveBeenCalledWith(expect.objectContaining({ full: true, scale: 2 }))
  })
})
