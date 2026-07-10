import { fireEvent, render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ConfigFileEditor } from './ConfigFileEditor'
import { loadNetworkConfigCodeMirror } from '../lib/codemirror/loadCodeMirror'

vi.mock('../lib/codemirror/loadCodeMirror', () => ({
  loadNetworkConfigCodeMirror: vi.fn(() => Promise.reject(new Error('CodeMirror unavailable'))),
}))

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string, params?: Record<string, string>) => {
      const translations: Record<string, string> = {
        'common.save': 'Save',
        'common.cancel': 'Cancel',
        'snapshots.configEditor.title': `Editing ${params?.name ?? ''}`,
        'snapshots.configEditor.rancidHint': 'RANCID header hint',
        'snapshots.configEditor.textareaAria': `Plain text editor for ${params?.name ?? ''}`,
        'snapshots.configEditor.codemirrorAria': `Code editor for ${params?.name ?? ''}`,
        'snapshots.configEditor.loadingEditor': 'Loading editor...',
        'snapshots.configEditor.saving': 'Saving...',
      }
      return translations[key] ?? key
    },
  }),
}))

describe('ConfigFileEditor', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders textarea fallback when forceFallback is set and saves edited content', () => {
    const onSave = vi.fn()
    const onDraftChange = vi.fn()
    const { rerender } = render(
      <ConfigFileEditor
        filename="router.cfg"
        draft="hostname router1\ninterface Ethernet0\n"
        forceFallback
        onDraftChange={onDraftChange}
        onSave={onSave}
        onCancel={vi.fn()}
      />
    )

    const textarea = screen.getByRole('textbox', { name: /plain text editor for router\.cfg/i })
    fireEvent.change(textarea, {
      target: { value: 'hostname router2\ninterface Ethernet0\nrouter ospf 1\n' },
    })
    expect(onDraftChange).toHaveBeenCalledWith(
      'hostname router2\ninterface Ethernet0\nrouter ospf 1\n'
    )
    rerender(
      <ConfigFileEditor
        filename="router.cfg"
        draft="hostname router2\ninterface Ethernet0\nrouter ospf 1\n"
        forceFallback
        onDraftChange={onDraftChange}
        onSave={onSave}
        onCancel={vi.fn()}
      />
    )
    fireEvent.click(screen.getByRole('button', { name: /save/i }))

    expect(onSave).toHaveBeenCalledWith()
    expect(loadNetworkConfigCodeMirror).not.toHaveBeenCalled()
  })

  it('renders textarea fallback when the CodeMirror dynamic import rejects', async () => {
    const onSave = vi.fn()
    render(
      <ConfigFileEditor
        filename="switch.cfg"
        draft="hostname switch1\ninterface Ethernet1\n"
        onDraftChange={vi.fn()}
        onSave={onSave}
        onCancel={vi.fn()}
      />
    )

    const textarea = await screen.findByRole('textbox', { name: /plain text editor for switch\.cfg/i })
    fireEvent.change(textarea, {
      target: { value: 'hostname switch2\ninterface Ethernet1\nrouter bgp 65000\n' },
    })
    fireEvent.click(screen.getByRole('button', { name: /save/i }))

    expect(loadNetworkConfigCodeMirror).toHaveBeenCalled()
    expect(onSave).toHaveBeenCalledWith()
  })
})
