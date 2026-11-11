import { useState } from 'react'
import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { getRovingTargetIndex, useRovingTabIndex, type RovingOrientation } from './useRovingTabIndex'

describe('getRovingTargetIndex', () => {
  it('moves forward and backward with wrap-around', () => {
    expect(getRovingTargetIndex('ArrowRight', 0, 3)).toBe(1)
    expect(getRovingTargetIndex('ArrowDown', 2, 3)).toBe(0)
    expect(getRovingTargetIndex('ArrowLeft', 0, 3)).toBe(2)
    expect(getRovingTargetIndex('ArrowUp', 2, 3)).toBe(1)
  })

  it('jumps to the first and last item with Home and End', () => {
    expect(getRovingTargetIndex('Home', 2, 4)).toBe(0)
    expect(getRovingTargetIndex('End', 0, 4)).toBe(3)
  })

  it('ignores keys outside the orientation and non-navigation keys', () => {
    expect(getRovingTargetIndex('ArrowDown', 0, 3, 'horizontal')).toBeNull()
    expect(getRovingTargetIndex('ArrowRight', 0, 3, 'vertical')).toBeNull()
    expect(getRovingTargetIndex('Enter', 0, 3)).toBeNull()
    expect(getRovingTargetIndex('a', 0, 3)).toBeNull()
  })

  it('handles an unknown current index and an empty list', () => {
    expect(getRovingTargetIndex('ArrowRight', -1, 3)).toBe(0)
    expect(getRovingTargetIndex('ArrowLeft', -1, 3)).toBe(2)
    expect(getRovingTargetIndex('ArrowRight', 0, 0)).toBeNull()
  })
})

const ITEMS = ['first', 'second', 'third'] as const
type Item = typeof ITEMS[number]

function TabList({ onSelect, orientation }: { onSelect?: (item: Item) => void; orientation?: RovingOrientation }) {
  const [active, setActive] = useState<Item>('first')
  const { getItemProps } = useRovingTabIndex({
    items: ITEMS,
    activeItem: active,
    orientation,
    onSelect: (item) => {
      onSelect?.(item)
      setActive(item)
    },
  })
  return (
    <div role="tablist">
      {ITEMS.map((item) => (
        <button key={item} id={item} role="tab" aria-selected={item === active} onClick={() => setActive(item)} {...getItemProps(item)}>
          {item}
        </button>
      ))}
    </div>
  )
}

describe('useRovingTabIndex', () => {
  it('keeps only the active item in the tab sequence', () => {
    render(<TabList />)
    expect(screen.getByRole('tab', { name: 'first' })).toHaveAttribute('tabindex', '0')
    expect(screen.getByRole('tab', { name: 'second' })).toHaveAttribute('tabindex', '-1')
    expect(screen.getByRole('tab', { name: 'third' })).toHaveAttribute('tabindex', '-1')
  })

  it('moves selection and focus with arrow keys, Home and End', () => {
    const onSelect = vi.fn()
    render(<TabList onSelect={onSelect} />)
    const first = screen.getByRole('tab', { name: 'first' })
    first.focus()

    fireEvent.keyDown(first, { key: 'ArrowRight' })
    const second = screen.getByRole('tab', { name: 'second' })
    expect(onSelect).toHaveBeenLastCalledWith('second')
    expect(document.activeElement).toBe(second)
    expect(second).toHaveAttribute('aria-selected', 'true')
    expect(second).toHaveAttribute('tabindex', '0')
    expect(first).toHaveAttribute('tabindex', '-1')

    fireEvent.keyDown(second, { key: 'End' })
    expect(document.activeElement).toBe(screen.getByRole('tab', { name: 'third' }))

    fireEvent.keyDown(document.activeElement as HTMLElement, { key: 'ArrowRight' })
    expect(document.activeElement).toBe(first)

    fireEvent.keyDown(first, { key: 'ArrowLeft' })
    expect(onSelect).toHaveBeenLastCalledWith('third')

    fireEvent.keyDown(document.activeElement as HTMLElement, { key: 'Home' })
    expect(document.activeElement).toBe(first)
    expect(first).toHaveAttribute('aria-selected', 'true')
  })

  it('does not select on keys outside the orientation or with modifiers', () => {
    const onSelect = vi.fn()
    render(<TabList onSelect={onSelect} orientation="horizontal" />)
    const first = screen.getByRole('tab', { name: 'first' })
    fireEvent.keyDown(first, { key: 'ArrowDown' })
    fireEvent.keyDown(first, { key: 'ArrowRight', altKey: true })
    expect(onSelect).not.toHaveBeenCalled()
  })
})
