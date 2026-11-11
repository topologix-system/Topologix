/**
 * Roving tabindex for WAI-ARIA tablists and radiogroups
 * - Only the active item is in the Tab sequence (tabIndex 0), the others get -1
 * - Arrow keys, Home and End move both selection and focus (automatic activation)
 */
import { useCallback, useRef, type KeyboardEvent } from 'react'

export type RovingOrientation = 'horizontal' | 'vertical' | 'both'

const NEXT_KEYS: Record<RovingOrientation, readonly string[]> = {
  horizontal: ['ArrowRight'],
  vertical: ['ArrowDown'],
  both: ['ArrowRight', 'ArrowDown'],
}

const PREVIOUS_KEYS: Record<RovingOrientation, readonly string[]> = {
  horizontal: ['ArrowLeft'],
  vertical: ['ArrowUp'],
  both: ['ArrowLeft', 'ArrowUp'],
}

/**
 * Index of the item a key press moves to, or null when the key is not a navigation key
 * Arrow navigation wraps around at both ends
 */
export function getRovingTargetIndex(
  key: string,
  currentIndex: number,
  count: number,
  orientation: RovingOrientation = 'both'
): number | null {
  if (count <= 0) return null
  if (key === 'Home') return 0
  if (key === 'End') return count - 1

  const hasCurrent = currentIndex >= 0 && currentIndex < count
  if (NEXT_KEYS[orientation].includes(key)) {
    return hasCurrent ? (currentIndex + 1) % count : 0
  }
  if (PREVIOUS_KEYS[orientation].includes(key)) {
    return hasCurrent ? (currentIndex - 1 + count) % count : count - 1
  }
  return null
}

interface UseRovingTabIndexOptions<T extends string> {
  items: readonly T[]
  activeItem: T
  onSelect: (item: T) => void
  orientation?: RovingOrientation
}

export interface RovingItemProps {
  ref: (element: HTMLElement | null) => void
  tabIndex: number
  onKeyDown: (event: KeyboardEvent<HTMLElement>) => void
}

export function useRovingTabIndex<T extends string>({
  items,
  activeItem,
  onSelect,
  orientation = 'both',
}: UseRovingTabIndexOptions<T>) {
  const elementsRef = useRef(new Map<T, HTMLElement>())
  const refCallbacksRef = useRef(new Map<T, (element: HTMLElement | null) => void>())
  const tabbableItem = items.includes(activeItem) ? activeItem : items[0]

  const getRef = useCallback((item: T) => {
    let callback = refCallbacksRef.current.get(item)
    if (!callback) {
      callback = (element: HTMLElement | null) => {
        if (element) {
          elementsRef.current.set(item, element)
        } else {
          elementsRef.current.delete(item)
        }
      }
      refCallbacksRef.current.set(item, callback)
    }
    return callback
  }, [])

  const getItemProps = useCallback((item: T): RovingItemProps => ({
    ref: getRef(item),
    tabIndex: item === tabbableItem ? 0 : -1,
    onKeyDown: (event: KeyboardEvent<HTMLElement>) => {
      if (event.altKey || event.ctrlKey || event.metaKey) return
      const targetIndex = getRovingTargetIndex(event.key, items.indexOf(item), items.length, orientation)
      if (targetIndex === null) return
      event.preventDefault()
      const target = items[targetIndex]
      if (target !== activeItem) {
        onSelect(target)
      }
      elementsRef.current.get(target)?.focus()
    },
  }), [activeItem, getRef, items, onSelect, orientation, tabbableItem])

  return { getItemProps }
}
