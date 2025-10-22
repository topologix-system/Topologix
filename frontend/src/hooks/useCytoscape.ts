/**
 * React hook for synchronous Cytoscape.js graph instance management
 * - Provides immediate initialization with pre-loaded Cytoscape modules
 * - Graph manipulation API: zoom, fit, center, highlight, selection, export
 * - Handles instance lifecycle (initialize, destroy, updateElements)
 * - Used when Cytoscape is already in the bundle (not lazy loaded)
 */
import { useRef, useCallback } from 'react'
import cytoscape, { type Core, type ElementDefinition } from 'cytoscape'
import cola from 'cytoscape-cola'
import coseBilkent from 'cytoscape-cose-bilkent'
import dagre from 'cytoscape-dagre'

import { defaultStyles } from '../lib/cytoscape/styles'
import { getLayoutConfig } from '../lib/cytoscape/layouts'
import type { LayoutName, CytoscapeConfig } from '../lib/cytoscape/types'

cytoscape.use(cola)
cytoscape.use(coseBilkent)
cytoscape.use(dagre)

export interface UseCytoscapeReturn {
  cyRef: React.RefObject<Core | null>
  initialize: (container: HTMLElement, elements?: ElementDefinition[]) => Core
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
}

/**
 * Custom hook for managing Cytoscape.js graph instance (synchronous version)
 * Provides complete graph manipulation API with lifecycle management
 * Used when Cytoscape is already bundled (not lazy loaded)
 * @param config - Optional Cytoscape configuration overrides
 * @returns Object with graph ref and manipulation methods
 */
export function useCytoscape(config?: CytoscapeConfig): UseCytoscapeReturn {
  const cyRef = useRef<Core | null>(null)

  const initialize = useCallback((container: HTMLElement, elements?: ElementDefinition[]) => {
    // Destroy existing instance
    if (cyRef.current) {
      cyRef.current.destroy()
    }

    // Create new instance
    cyRef.current = cytoscape({
      container,
      elements: elements || config?.elements || [],
      style: config?.style || defaultStyles,
      layout: config?.layout || getLayoutConfig('cola'),
      minZoom: config?.minZoom || 0.1,
      maxZoom: config?.maxZoom || 3,
      wheelSensitivity: config?.wheelSensitivity || 0.2,
      ...config,
    })

    return cyRef.current
  }, [config])

  const destroy = useCallback(() => {
    if (cyRef.current) {
      cyRef.current.destroy()
      cyRef.current = null
    }
  }, [])

  const updateElements = useCallback((elements: ElementDefinition[]) => {
    if (!cyRef.current) return

    cyRef.current.elements().remove()
    cyRef.current.add(elements)
    cyRef.current.layout(getLayoutConfig('cola')).run()
  }, [])

  const applyLayout = useCallback((layoutName: LayoutName) => {
    if (!cyRef.current) return

    const layout = cyRef.current.layout(getLayoutConfig(layoutName))
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
    cyRef.current.zoom(currentZoom * 1.2)
    cyRef.current.center()
  }, [])

  const zoomOut = useCallback(() => {
    if (!cyRef.current) return
    const currentZoom = cyRef.current.zoom()
    cyRef.current.zoom(currentZoom * 0.8)
    cyRef.current.center()
  }, [])

  const resetZoom = useCallback(() => {
    if (!cyRef.current) return
    cyRef.current.zoom(1)
    cyRef.current.center()
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

    // Dim all elements
    cyRef.current.elements().addClass('dimmed')

    // Highlight selected node and neighbors
    node.removeClass('dimmed').addClass('highlighted')
    node.neighborhood().removeClass('dimmed').addClass('highlighted')
  }, [])

  const unhighlightAll = useCallback(() => {
    if (!cyRef.current) return
    cyRef.current.elements().removeClass('dimmed highlighted')
  }, [])

  const exportPNG = useCallback(() => {
    if (!cyRef.current) return ''
    return cyRef.current.png({ output: 'base64', full: true, scale: 2 })
  }, [])

  const exportJSON = useCallback(() => {
    if (!cyRef.current) return null
    return cyRef.current.json()
  }, [])

  return {
    cyRef,
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
  }
}