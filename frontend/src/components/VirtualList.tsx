/**
 * Generic virtualized list component using @tanstack/react-virtual
 * - Performance optimization: only renders visible items + overscan buffer (default 5 items)
 * - Supports both vertical (default) and horizontal virtualization modes
 * - Flexible sizing: fixed itemHeight or dynamic estimateSize callback
 * - Custom item rendering: renderItem prop for full control over item display
 * - React.memo wrapper prevents unnecessary re-renders on parent updates
 * - Used for rendering large datasets (10K+ routes, interfaces, etc.) efficiently
 * - Generic type parameter T allows reuse across different data types
 */
import { useRef, memo, ReactNode } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'

interface VirtualListProps<T> {
  items: T[]
  height: number | string
  itemHeight?: number
  renderItem: (item: T, index: number) => ReactNode
  overscan?: number
  className?: string
  emptyMessage?: string
  getItemKey?: (item: T, index: number) => string | number
  estimateSize?: (index: number) => number
  horizontal?: boolean
}

export const VirtualList = memo(function VirtualList<T>({
  items,
  height,
  itemHeight = 50,
  renderItem,
  overscan = 5,
  className = '',
  emptyMessage = 'No items to display',
  getItemKey,
  estimateSize,
  horizontal = false,
}: VirtualListProps<T>) {
  const parentRef = useRef<HTMLDivElement>(null)

  const virtualizer = useVirtualizer({
    count: items.length,
    getScrollElement: () => parentRef.current,
    estimateSize: estimateSize || (() => itemHeight),
    overscan,
    horizontal,
  })

  if (items.length === 0) {
    return (
      <div className={`flex items-center justify-center p-4 text-gray-500 ${className}`} style={{ height }}>
        {emptyMessage}
      </div>
    )
  }

  const virtualItems = virtualizer.getVirtualItems()
  const totalSize = horizontal
    ? virtualizer.getTotalSize()
    : virtualizer.getTotalSize()

  return (
    <div
      ref={parentRef}
      className={`overflow-auto ${className}`}
      style={{
        height: typeof height === 'number' ? `${height}px` : height,
        width: '100%',
      }}
    >
      <div
        style={{
          [horizontal ? 'width' : 'height']: `${totalSize}px`,
          [horizontal ? 'height' : 'width']: '100%',
          position: 'relative',
        }}
      >
        {virtualItems.map((virtualRow) => {
          const item = items[virtualRow.index]
          const key = getItemKey ? getItemKey(item, virtualRow.index) : virtualRow.index

          return (
            <div
              key={key}
              style={{
                position: 'absolute',
                [horizontal ? 'left' : 'top']: 0,
                [horizontal ? 'top' : 'left']: 0,
                [horizontal ? 'width' : 'height']: `${virtualRow.size}px`,
                [horizontal ? 'height' : 'width']: '100%',
                transform: horizontal
                  ? `translateX(${virtualRow.start}px)`
                  : `translateY(${virtualRow.start}px)`,
              }}
            >
              {renderItem(item, virtualRow.index)}
            </div>
          )
        })}
      </div>
    </div>
  )
}) as <T>(props: VirtualListProps<T>) => JSX.Element

interface VirtualTableProps<T> {
  items: T[]
  height: number | string
  rowHeight?: number
  columns: Array<{
    key: string
    header: string
    width?: string
    render: (item: T) => ReactNode
  }>
  onRowClick?: (item: T, index: number) => void
  selectedIndex?: number
  className?: string
  emptyMessage?: string
}

/**
 * Virtualized table component with column headers and row selection
 * - Built on VirtualList: inherits performance optimization for large datasets
 * - Column configuration: flexible width, custom render functions per column
 * - Interactive: optional row click handler and selected row highlighting
 * - Sticky header: column headers remain visible during vertical scroll
 * - Higher overscan (10 items) for smoother table scrolling experience
 * - Used for tabular data display (BGP routes, interfaces, ACLs, etc.)
 */
export const VirtualTable = memo(function VirtualTable<T>({
  items,
  height,
  rowHeight = 40,
  columns,
  onRowClick,
  selectedIndex,
  className = '',
  emptyMessage = 'No data available',
}: VirtualTableProps<T>) {
  const parentRef = useRef<HTMLDivElement>(null)

  const virtualizer = useVirtualizer({
    count: items.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => rowHeight,
    overscan: 10,
  })

  if (items.length === 0) {
    return (
      <div className={`flex items-center justify-center p-4 text-gray-500 ${className}`} style={{ height }}>
        {emptyMessage}
      </div>
    )
  }

  const virtualItems = virtualizer.getVirtualItems()

  return (
    <div className={`border border-gray-200 rounded-lg overflow-hidden ${className}`}>
      <div className="sticky top-0 z-10 bg-gray-50 border-b border-gray-200">
        <div className="flex">
          {columns.map((column) => (
            <div
              key={column.key}
              className="px-3 py-2 font-semibold text-sm text-gray-700"
              style={{ width: column.width || `${100 / columns.length}%` }}
            >
              {column.header}
            </div>
          ))}
        </div>
      </div>

      <div
        ref={parentRef}
        className="overflow-auto"
        style={{
          height: typeof height === 'number' ? `${height}px` : height,
        }}
      >
        <div
          style={{
            height: `${virtualizer.getTotalSize()}px`,
            width: '100%',
            position: 'relative',
          }}
        >
          {virtualItems.map((virtualRow) => {
            const item = items[virtualRow.index]
            const isSelected = selectedIndex === virtualRow.index

            return (
              <div
                key={virtualRow.index}
                className={`
                  flex border-b border-gray-100 hover:bg-gray-50 transition-colors
                  ${isSelected ? 'bg-blue-50' : ''}
                  ${onRowClick ? 'cursor-pointer' : ''}
                `}
                style={{
                  position: 'absolute',
                  top: 0,
                  left: 0,
                  width: '100%',
                  height: `${virtualRow.size}px`,
                  transform: `translateY(${virtualRow.start}px)`,
                }}
                onClick={() => onRowClick?.(item, virtualRow.index)}
              >
                {columns.map((column) => (
                  <div
                    key={column.key}
                    className="px-3 py-2 text-sm text-gray-600 truncate"
                    style={{ width: column.width || `${100 / columns.length}%` }}
                  >
                    {column.render(item)}
                  </div>
                ))}
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}) as <T>(props: VirtualTableProps<T>) => JSX.Element