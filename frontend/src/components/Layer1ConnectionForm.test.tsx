import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import type { SnapshotInterfaces } from '../types/layer1'
import { Layer1ConnectionForm } from './Layer1ConnectionForm'

vi.mock('../hooks', async () => {
  const { useComboboxFilter } = await import('../hooks/useComboboxFilter')
  return { useComboboxFilter }
})

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}))

const INTERFACES: SnapshotInterfaces = {
  r1: { hostname: 'r1', interfaces: [{ name: 'Gi0/0', active: true }] },
  r2: { hostname: 'r2', interfaces: [{ name: 'Gi0/0', active: true }] },
}

describe('Layer1ConnectionForm', () => {
  it('clears the four fields and calls onCancel when Cancel is pressed', () => {
    const onCancel = vi.fn()
    render(
      <Layer1ConnectionForm
        interfaces={INTERFACES}
        editingEdge={{ node1: { hostname: 'r1', interfaceName: 'Gi0/0' }, node2: { hostname: 'r2', interfaceName: 'Gi0/0' } }}
        onSubmit={vi.fn()}
        onCancel={onCancel}
      />
    )
    const values = () => screen.getAllByRole('combobox').map((input) => (input as HTMLInputElement).value)
    expect(values()).toEqual(['r1', 'Gi0/0', 'r2', 'Gi0/0'])

    fireEvent.click(screen.getByRole('button', { name: 'layer1Editor.cancel' }))

    expect(onCancel).toHaveBeenCalledTimes(1)
    expect(values()).toEqual(['', '', '', ''])
  })
})
