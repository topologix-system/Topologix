import { afterEach, describe, expect, it, vi } from 'vitest'

import { applyLineSeparator, detectLineSeparator } from './lineSeparator'
import { loadNetworkConfigCodeMirror } from './loadCodeMirror'

describe('detectLineSeparator', () => {
  it('returns CRLF for content with CRLF line breaks and LF otherwise', () => {
    expect(detectLineSeparator('hostname r1\r\ninterface Gi0/0\r\n')).toBe('\r\n')
    expect(detectLineSeparator('hostname r1\ninterface Gi0/0\n')).toBe('\n')
    expect(detectLineSeparator('hostname r1')).toBe('\n')
    expect(detectLineSeparator('')).toBe('\n')
  })
})

describe('applyLineSeparator', () => {
  it('writes every line break as CRLF for a CRLF file without doubling existing CRs', () => {
    expect(applyLineSeparator('hostname r1\ninterface Gi0/0\n', '\r\n')).toBe('hostname r1\r\ninterface Gi0/0\r\n')
    expect(applyLineSeparator('a\r\nb\nc', '\r\n')).toBe('a\r\nb\r\nc')
  })

  it('returns LF text unchanged for an LF file', () => {
    expect(applyLineSeparator('hostname r1\ninterface Gi0/0\n', '\n')).toBe('hostname r1\ninterface Gi0/0\n')
  })
})

describe('loadNetworkConfigCodeMirror', () => {
  const views: Array<{ destroy: () => void }> = []

  afterEach(() => {
    views.splice(0).forEach((view) => view.destroy())
    document.body.innerHTML = ''
  })

  async function editFirstLine(doc: string) {
    const bundle = await loadNetworkConfigCodeMirror()
    const onChange = vi.fn()
    const view = new bundle.EditorView({ state: bundle.createState(doc, onChange), parent: document.body })
    views.push(view)
    view.dispatch({ changes: { from: 0, to: 'hostname r1'.length, insert: 'hostname r2' } })
    return onChange
  }

  it('reports the edited text of a CRLF file with CRLF line breaks', async () => {
    const onChange = await editFirstLine('hostname r1\r\ninterface Gi0/0\r\n description uplink\r\n')
    expect(onChange).toHaveBeenLastCalledWith('hostname r2\r\ninterface Gi0/0\r\n description uplink\r\n')
  })

  it('reports the edited text of an LF file with LF line breaks', async () => {
    const onChange = await editFirstLine('hostname r1\ninterface Gi0/0\n')
    expect(onChange).toHaveBeenLastCalledWith('hostname r2\ninterface Gi0/0\n')
  })
})
