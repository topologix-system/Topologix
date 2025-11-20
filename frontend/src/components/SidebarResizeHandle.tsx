/**
 * Draggable sidebar resize handle component
 * - Mouse event handling: tracks drag with mousedown/mousemove/mouseup listeners
 * - Width constraints: MIN_WIDTH (280px) to MAX_WIDTH (800px) enforced during drag
 * - Zustand store integration: persists sidebar width preference to localStorage
 * - Visual feedback: hover state, active drag state, grip icon indicator
 * - Global cursor override during drag: prevents text selection and shows resize cursor
 * - Used in Sidebar component for user-adjustable sidebar width
 */
import { useCallback, useEffect, useRef, useState } from 'react'
import { GripVertical } from 'lucide-react'
import { useUIStore } from '../store'

/**
 * Sidebar width constraints (pixels)
 * MIN_WIDTH: Minimum readable width for sidebar content
 * MAX_WIDTH: Maximum width to prevent sidebar from dominating viewport
 */
const MIN_WIDTH = 280
const MAX_WIDTH = 800

export function SidebarResizeHandle() {
  const [isResizing, setIsResizing] = useState(false)
  const startXRef = useRef(0)
  const startWidthRef = useRef(0)
  const setSidebarWidth = useUIStore((state) => state.setSidebarWidth)
  const currentWidth = useUIStore((state) => state.sidebarWidth)

  /**
   * Initialize resize operation on mouse down
   * Captures initial mouse position and sidebar width for delta calculation
   */
  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    console.log('[SidebarResizeHandle] Mouse down, starting resize')
    setIsResizing(true)
    startXRef.current = e.clientX
    startWidthRef.current = currentWidth
    e.preventDefault()
  }, [currentWidth])

  /**
   * Handle resize drag operation and cleanup
   * - Attaches global mousemove/mouseup listeners when dragging starts
   * - Calculates new width based on mouse delta, clamped to MIN/MAX constraints
   * - Overrides body cursor and disables text selection during drag
   * - Cleans up listeners and resets styles when drag ends
   * Note: useEffect is appropriate here for DOM event listener management (not data fetching)
   */
  useEffect(() => {
    if (!isResizing) return

    const handleMouseMove = (e: MouseEvent) => {
      const deltaX = startXRef.current - e.clientX
      const newWidth = Math.max(MIN_WIDTH, Math.min(MAX_WIDTH, startWidthRef.current + deltaX))

      console.log('[SidebarResizeHandle] deltaX:', deltaX, 'newWidth:', newWidth)
      setSidebarWidth(newWidth)
    }

    const handleMouseUp = () => {
      console.log('[SidebarResizeHandle] Mouse up, resize complete')
      setIsResizing(false)
    }

    document.addEventListener('mousemove', handleMouseMove)
    document.addEventListener('mouseup', handleMouseUp)

    document.body.style.userSelect = 'none'
    document.body.style.cursor = 'ew-resize'

    return () => {
      document.removeEventListener('mousemove', handleMouseMove)
      document.removeEventListener('mouseup', handleMouseUp)
      document.body.style.userSelect = ''
      document.body.style.cursor = ''
    }
  }, [isResizing, setSidebarWidth])

  return (
    <div
      onMouseDown={handleMouseDown}
      className={`absolute left-0 top-0 bottom-0 w-1 cursor-ew-resize group hover:bg-primary-400 transition-colors ${
        isResizing ? 'bg-primary-500' : 'bg-transparent'
      }`}
      role="separator"
      aria-label="Drag to resize sidebar"
      aria-orientation="vertical"
      title="Drag to resize"
    >
      <div className="absolute left-0 top-1/2 -translate-y-1/2 -translate-x-2 opacity-0 group-hover:opacity-100 transition-opacity">
        <div className="bg-gray-700 text-white rounded p-1">
          <GripVertical className="w-3 h-3" aria-hidden="true" />
        </div>
      </div>
    </div>
  )
}