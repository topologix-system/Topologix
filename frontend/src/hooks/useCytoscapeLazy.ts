/**
 * React hook for lazy-loaded Cytoscape.js graph instance with async initialization
 * - Dynamic imports for code splitting: reduces initial bundle size significantly
 * - Handles position save/restore across graph updates and snapshot switches
 * - Same API as useCytoscape but with async initialize() returning Promise<Core>
 * - Extensive console logging for debugging initialization and layout issues
 * - Used by TopologyViewer for optimal performance and user position persistence
 */
import { useRef, useCallback, useState, useEffect, useMemo } from 'react'
import type { Core, ElementDefinition } from 'cytoscape'
import { getLayoutConfig } from '../lib/cytoscape/layouts'
import type { LayoutName, CytoscapeConfig } from '../lib/cytoscape/types'

let cytoscapeModule: typeof import('cytoscape') | null = null
let cytoscapeLoaded = false

async function loadCytoscape() {
  if (cytoscapeLoaded && cytoscapeModule) return cytoscapeModule

  try {
    const [cytoscape, cola, coseBilkent, dagre] = await Promise.all([
      import('cytoscape'),
      import('cytoscape-cola'),
      import('cytoscape-cose-bilkent'),
      import('cytoscape-dagre'),
    ])

    cytoscapeModule =
      (typeof cytoscape === 'function' ? cytoscape :
       cytoscape.default && typeof cytoscape.default === 'function' ? cytoscape.default :
       (cytoscape as any).cytoscape && typeof (cytoscape as any).cytoscape === 'function' ?
         (cytoscape as any).cytoscape : null)

    if (!cytoscapeModule || typeof cytoscapeModule !== 'function') {
      console.error('[useCytoscapeLazy] Failed to load Cytoscape module correctly. Module type:', typeof cytoscape, 'Module:', cytoscape)
      throw new Error('Cytoscape module is not a function')
    }

    const colaModule = (cola as any).default || (cola as any).cola || cola
    const coseBilkentModule = (coseBilkent as any).default || (coseBilkent as any).coseBilkent || coseBilkent
    const dagreModule = (dagre as any).default || (dagre as any).dagre || dagre

    if (cytoscapeModule && typeof cytoscapeModule.use === 'function') {
      cytoscapeModule.use(colaModule)
      cytoscapeModule.use(coseBilkentModule)
      cytoscapeModule.use(dagreModule)
      console.log('[useCytoscapeLazy] Cytoscape extensions registered successfully')
    } else {
      console.error('[useCytoscapeLazy] Cannot register extensions - Cytoscape.use is not a function')
    }

    cytoscapeLoaded = true
    return cytoscapeModule
  } catch (error) {
    console.error('[useCytoscapeLazy] Error loading Cytoscape modules:', error)
    cytoscapeModule = null
    cytoscapeLoaded = false
    return null
  }
}

export interface NodePositions {
  [nodeId: string]: { x: number; y: number }
}

export interface UseCytoscapeLazyReturn {
  cyRef: React.RefObject<Core | null>
  isLoaded: boolean
  initialize: (container: HTMLElement, elements?: ElementDefinition[]) => Promise<Core | null>
  destroy: () => void
  updateElements: (elements: ElementDefinition[]) => void
  applyLayout: (layoutName: LayoutName) => void
  fit: () => void
  center: () => void
  zoomIn: () => void
  zoomOut: () => void
  resetZoom: () => void
  getSelectedNodes: () => any[]
  getSelectedEdges: () => any[]
  highlightNode: (nodeId: string) => void
  unhighlightAll: () => void
  exportPNG: () => string
  exportJSON: () => any
  saveNodePositions: () => NodePositions
  restoreNodePositions: (positions: NodePositions) => void
}

/**
 * Custom hook for managing lazy-loaded Cytoscape.js graph instance
 * Async version with code splitting for optimal bundle size
 * Includes position save/restore for user layout persistence
 * Used by TopologyViewer for performance-optimized graph rendering
 * @param config - Optional Cytoscape configuration overrides
 * @returns Object with graph ref, loading state, and manipulation methods
 */
export function useCytoscapeLazy(config?: CytoscapeConfig): UseCytoscapeLazyReturn {
  const cyRef = useRef<Core | null>(null)
  const [isLoaded, setIsLoaded] = useState(false)
  const updateTimeoutRef = useRef<NodeJS.Timeout | null>(null)

  const initialize = useCallback(async (container: HTMLElement, elements?: ElementDefinition[]) => {
    console.log('[useCytoscapeLazy] Initializing Cytoscape instance with', elements?.length || 0, 'elements')

    try {
      if (cyRef.current) {
        console.log('[useCytoscapeLazy] Destroying existing Cytoscape instance')
        cyRef.current.destroy()
        cyRef.current = null
        setIsLoaded(false)
      }

      if (updateTimeoutRef.current) {
        clearTimeout(updateTimeoutRef.current)
        updateTimeoutRef.current = null
      }

      console.log('[useCytoscapeLazy] Loading Cytoscape modules')
      const cytoscape = await loadCytoscape()
      if (!cytoscape) {
        console.error('[useCytoscapeLazy] Cytoscape module could not be loaded')
        return null
      }
      console.log('[useCytoscapeLazy] Cytoscape modules loaded successfully')

      console.log('[useCytoscapeLazy] Loading Cytoscape styles')
      const { defaultStyles } = await import('../lib/cytoscape/styles')

      const initialElements = elements || config?.elements || []
      console.log('[useCytoscapeLazy] Creating Cytoscape instance with', initialElements.length, 'elements')

      const cytoscapeConfig = {
        container,
        elements: initialElements,
        style: config?.style || defaultStyles,
        layout: config?.layout || getLayoutConfig('cola'),
        minZoom: config?.minZoom || 0.1,
        maxZoom: config?.maxZoom || 3,
        wheelSensitivity: config?.wheelSensitivity || 0.2,
        textureOnViewport: true,
        hideEdgesOnViewport: true,
        hideLabelsOnViewport: true,
        pixelRatio: 'auto',
        ...config,
      }

      if (typeof cytoscape !== 'function') {
        console.error('[useCytoscapeLazy] Cytoscape is not a function:', typeof cytoscape, cytoscape)
        return null
      }

      cyRef.current = cytoscape(cytoscapeConfig)
      console.log('[useCytoscapeLazy] Cytoscape instance created successfully')
      console.log('[useCytoscapeLazy] Initial element count:', cyRef.current.elements().length)

      setIsLoaded(true)
      return cyRef.current
    } catch (error) {
      console.error('[useCytoscapeLazy] Failed to initialize Cytoscape:', error)
      console.error('[useCytoscapeLazy] Error details:', {
        message: (error as any)?.message,
        stack: (error as any)?.stack,
        containerExists: !!container,
        elementsCount: elements?.length || 0
      })
      setIsLoaded(false)
      cyRef.current = null
      return null
    }
  }, [config])

  const destroy = useCallback(() => {
    console.log('[useCytoscapeLazy] Destroying Cytoscape instance')

    if (updateTimeoutRef.current) {
      console.log('[useCytoscapeLazy] Clearing pending layout timeout')
      clearTimeout(updateTimeoutRef.current)
      updateTimeoutRef.current = null
    }

    if (cyRef.current) {
      try {
        console.log('[useCytoscapeLazy] Destroying Cytoscape instance with', cyRef.current.elements().length, 'elements')
        cyRef.current.destroy()
        cyRef.current = null
        setIsLoaded(false)
        console.log('[useCytoscapeLazy] Cytoscape instance destroyed successfully')
      } catch (error) {
        console.error('[useCytoscapeLazy] Error destroying Cytoscape instance:', error)
        cyRef.current = null
        setIsLoaded(false)
      }
    } else {
      console.log('[useCytoscapeLazy] No Cytoscape instance to destroy')
    }
  }, [])

  const updateElements = useCallback((elements: ElementDefinition[], applyLayout: boolean = true) => {
    console.log('[useCytoscapeLazy] updateElements called with', elements.length, 'elements, applyLayout:', applyLayout)

    if (!cyRef.current) {
      console.error('[useCytoscapeLazy] Cannot update elements: Cytoscape instance not initialized')
      return
    }

    try {
      if (updateTimeoutRef.current) {
        clearTimeout(updateTimeoutRef.current)
        updateTimeoutRef.current = null
      }

      console.log('[useCytoscapeLazy] Updating elements in batch mode')

      cyRef.current.batch(() => {
        const cy = cyRef.current!
        const existingElements = cy.elements()

        console.log('[useCytoscapeLazy] Removing', existingElements.length, 'existing elements')
        existingElements.remove()

        console.log('[useCytoscapeLazy] Adding', elements.length, 'new elements')
        cy.add(elements)
      })

      console.log('[useCytoscapeLazy] Elements updated successfully, current count:', cyRef.current.elements().length)

      if (applyLayout && cyRef.current && cyRef.current.elements().length > 0) {
        console.log('[useCytoscapeLazy] Applying layout immediately')
        try {
          const layout = cyRef.current.layout(getLayoutConfig('cola'))
          layout.run()
          console.log('[useCytoscapeLazy] Layout applied successfully')
        } catch (layoutError) {
          console.error('[useCytoscapeLazy] Error applying layout:', layoutError)
          try {
            console.log('[useCytoscapeLazy] Trying fallback grid layout')
            const fallbackLayout = cyRef.current.layout({ name: 'grid' })
            fallbackLayout.run()
          } catch (fallbackError) {
            console.error('[useCytoscapeLazy] Fallback layout also failed:', fallbackError)
          }
        }
      } else if (!applyLayout) {
        console.log('[useCytoscapeLazy] Skipping layout application (applyLayout=false)')
      } else if (cyRef.current) {
        console.log('[useCytoscapeLazy] No elements to layout')
      }
    } catch (error) {
      console.error('[useCytoscapeLazy] Error updating elements:', error)
      console.error('[useCytoscapeLazy] Error details:', {
        message: (error as any)?.message,
        stack: (error as any)?.stack,
        elementsCount: elements.length
      })
    }
  }, [])

  const applyLayout = useCallback((layoutName: LayoutName) => {
    if (!cyRef.current) return

    const layout = cyRef.current.layout({
      ...getLayoutConfig(layoutName),
      animate: true,
      animationDuration: 500,
      animationEasing: 'ease-out',
    })
    layout.run()
  }, [])

  const fit = useCallback(() => {
    if (!cyRef.current) return
    cyRef.current.fit(undefined, 50)
  }, [])

  const center = useCallback(() => {
    if (!cyRef.current) return
    cyRef.current.center()
  }, [])

  const zoomIn = useCallback(() => {
    if (!cyRef.current) return
    const currentZoom = cyRef.current.zoom()
    cyRef.current.animate({
      zoom: currentZoom * 1.2,
      center: cyRef.current.extent().midpoint,
    }, {
      duration: 200,
    })
  }, [])

  const zoomOut = useCallback(() => {
    if (!cyRef.current) return
    const currentZoom = cyRef.current.zoom()
    cyRef.current.animate({
      zoom: currentZoom * 0.8,
      center: cyRef.current.extent().midpoint,
    }, {
      duration: 200,
    })
  }, [])

  const resetZoom = useCallback(() => {
    if (!cyRef.current) return
    cyRef.current.animate({
      zoom: 1,
      center: cyRef.current.extent().midpoint,
    }, {
      duration: 200,
    })
  }, [])

  const getSelectedNodes = useCallback(() => {
    if (!cyRef.current) return []
    return cyRef.current.$('node:selected').map((node) => node.data())
  }, [])

  const getSelectedEdges = useCallback(() => {
    if (!cyRef.current) return []
    return cyRef.current.$('edge:selected').map((edge) => edge.data())
  }, [])

  const highlightNode = useCallback((nodeId: string) => {
    if (!cyRef.current) return

    const node = cyRef.current.$(`#${nodeId}`)
    if (node.length === 0) return

    cyRef.current.batch(() => {
      cyRef.current!.elements().addClass('dimmed')

      node.removeClass('dimmed').addClass('highlighted')
      node.neighborhood().removeClass('dimmed').addClass('highlighted')
    })
  }, [])

  const unhighlightAll = useCallback(() => {
    if (!cyRef.current) return
    cyRef.current.batch(() => {
      cyRef.current!.elements().removeClass('dimmed highlighted')
    })
  }, [])

  const exportPNG = useCallback(() => {
    if (!cyRef.current) return ''
    return cyRef.current.png({ output: 'base64', full: true, scale: 2 })
  }, [])

  const exportJSON = useCallback(() => {
    if (!cyRef.current) return null
    return cyRef.current.json()
  }, [])

  const saveNodePositions = useCallback((): NodePositions => {
    if (!cyRef.current) {
      console.log('[useCytoscapeLazy] Cannot save positions: Cytoscape instance not initialized')
      return {}
    }

    const positions: NodePositions = {}
    cyRef.current.nodes().forEach((node) => {
      const pos = node.position()
      positions[node.id()] = { x: pos.x, y: pos.y }
    })

    console.log(`[useCytoscapeLazy] Saved positions for ${Object.keys(positions).length} nodes`)
    return positions
  }, [])

  const restoreNodePositions = useCallback((positions: NodePositions) => {
    if (!cyRef.current) {
      console.log('[useCytoscapeLazy] Cannot restore positions: Cytoscape instance not initialized')
      return
    }

    if (!positions || Object.keys(positions).length === 0) {
      console.log('[useCytoscapeLazy] No positions to restore')
      return
    }

    let restoredCount = 0
    cyRef.current.batch(() => {
      cyRef.current!.nodes().forEach((node) => {
        const savedPosition = positions[node.id()]
        if (savedPosition) {
          node.position(savedPosition)
          restoredCount++
        }
      })
    })

    console.log(`[useCytoscapeLazy] Restored positions for ${restoredCount} of ${Object.keys(positions).length} saved nodes`)
  }, [])

  useEffect(() => {
    return () => {
      if (updateTimeoutRef.current) {
        clearTimeout(updateTimeoutRef.current)
      }
    }
  }, [])

  return useMemo(() => ({
    cyRef,
    isLoaded,
    initialize,
    destroy,
    updateElements,
    applyLayout,
    fit,
    center,
    zoomIn,
    zoomOut,
    resetZoom,
    getSelectedNodes,
    getSelectedEdges,
    highlightNode,
    unhighlightAll,
    exportPNG,
    exportJSON,
    saveNodePositions,
    restoreNodePositions,
  }), [
    isLoaded,
    initialize,
    destroy,
    updateElements,
    applyLayout,
    fit,
    center,
    zoomIn,
    zoomOut,
    resetZoom,
    getSelectedNodes,
    getSelectedEdges,
    highlightNode,
    unhighlightAll,
    exportPNG,
    exportJSON,
    saveNodePositions,
    restoreNodePositions,
  ])
}