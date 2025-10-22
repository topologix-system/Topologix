import { useRef, useCallback, useEffect, memo, useState } from 'react'
import {
  ZoomIn,
  ZoomOut,
  Maximize,
  Download,
  RefreshCw,
  Layers,
  ChevronDown,
  ChevronUp,
} from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { useCytoscapeLazy } from '../hooks/useCytoscapeLazy'
import { useAllNetworkData } from '../hooks'
import { useUIStore, usePositionStore, useSnapshotStore } from '../store'
import { buildGraphElements } from '../lib/cytoscape'
import type { LayoutName, LayerType } from '../lib/cytoscape/types'

/**
 * Main network topology visualization component using Cytoscape.js
 * Handles graph rendering, user interactions, and position persistence
 * Uses React Query for data fetching (NO useEffect for data)
 */
export const TopologyViewer = memo(function TopologyViewer() {
  const { t } = useTranslation()
  const [layersDropdownOpen, setLayersDropdownOpen] = useState(false)

  // Refs for managing Cytoscape lifecycle and preventing race conditions
  const cytoscapeInitializedRef = useRef(false) // Tracks if Cytoscape is fully initialized
  const containerRef = useRef<HTMLDivElement | null>(null) // DOM container reference
  const isUpdatingRef = useRef(false) // Prevents concurrent initialization
  const savePositionTimeoutRef = useRef<NodeJS.Timeout | null>(null) // Debounce timer for position saving

  const currentLayout = useUIStore((state) => state.currentLayout)
  const setCurrentLayout = useUIStore((state) => state.setCurrentLayout)
  const setSelectedNode = useUIStore((state) => state.setSelectedNode)
  const setSelectedEdge = useUIStore((state) => state.setSelectedEdge)
  const visibleLayers = useUIStore((state) => state.visibleLayers)
  const toggleVisibleLayer = useUIStore((state) => state.toggleVisibleLayer)

  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)
  const savePositions = usePositionStore((state) => state.savePositions)
  const getPositions = usePositionStore((state) => state.getPositions)

  // Fetch network data using React Query (NO useEffect for data fetching!)
  const { data: networkData, isLoading, isFetching, error, refetch } = useAllNetworkData()

  // Lazy-loaded Cytoscape instance (initialized only when needed)
  const cy = useCytoscapeLazy()

  /**
   * Initializes Cytoscape instance when container ref is available
   * Prevents duplicate initialization and handles async setup
   */
  const handleContainerRef = useCallback(
    async (node: HTMLDivElement | null) => {
      console.log('[TopologyViewer] handleContainerRef called, node:', !!node)

      if (!node) {
        console.log('[TopologyViewer] No container node provided')
        return
      }

      containerRef.current = node

      if (cy.cyRef.current) {
        console.log('[TopologyViewer] Cytoscape instance already exists, skipping initialization')
        cytoscapeInitializedRef.current = true
        return
      }

      if (isUpdatingRef.current) {
        console.log('[TopologyViewer] Already initializing, skipping')
        return
      }

      console.log('[TopologyViewer] Initializing Cytoscape')
      isUpdatingRef.current = true
      cytoscapeInitializedRef.current = false

      try {
        const instance = await cy.initialize(node, [])

        if (!instance) {
          console.error('[TopologyViewer] Failed to initialize Cytoscape')
          cytoscapeInitializedRef.current = false
          isUpdatingRef.current = false
          return
        }

        console.log('[TopologyViewer] Cytoscape initialized successfully')
        cytoscapeInitializedRef.current = true

        if (networkData) {
          console.log('[TopologyViewer] Network data available, adding elements')
          const elements = buildGraphElements(networkData.node_properties, {
            physical: networkData.edges,
            layer3: networkData.layer3_edges,
            ospf: networkData.ospf_edges,
            bgp: networkData.bgp_edges,
            vxlan: networkData.vxlan_edges,
            eigrp: networkData.eigrp_edges,
            isis: networkData.isis_edges,
            ipsec: networkData.ipsec_edges,
            'switched-vlan': networkData.switched_vlan_edges,
          }, visibleLayers)
          console.log('[TopologyViewer] Built', elements.nodes.length, 'nodes and', elements.edges.length, 'edges')
          cy.updateElements([...elements.nodes, ...elements.edges])
        }
      } finally {
        isUpdatingRef.current = false
      }
    },
    [networkData, setSelectedNode, setSelectedEdge, visibleLayers]
  )

  /**
   * Refreshes network data and updates graph elements
   * Preserves current layout and zoom level
   */
  const handleRefresh = useCallback(() => {
    console.log('[TopologyViewer] Refresh button clicked')
    refetch()

    if (networkData) {
      console.log('[TopologyViewer] Refreshing with existing network data')
      const elements = buildGraphElements(networkData.node_properties, {
        physical: networkData.edges,
        layer3: networkData.layer3_edges,
        ospf: networkData.ospf_edges,
        bgp: networkData.bgp_edges,
        vxlan: networkData.vxlan_edges,
        eigrp: networkData.eigrp_edges,
        isis: networkData.isis_edges,
        ipsec: networkData.ipsec_edges,
        'switched-vlan': networkData.switched_vlan_edges,
      }, visibleLayers)

      console.log('[TopologyViewer] Refresh: updating with', elements.nodes.length, 'nodes and', elements.edges.length, 'edges')
      cy.updateElements([...elements.nodes, ...elements.edges])
    } else {
      console.log('[TopologyViewer] No network data to refresh')
    }
  }, [networkData, cy, refetch, visibleLayers])

  /**
   * Main effect: Updates graph when network data or layers change
   * Handles position restoration for snapshot switching
   * IMPORTANT: Data fetching is done via React Query, not useEffect
   */
  useEffect(() => {
    console.log('[TopologyViewer] useEffect triggered for networkData update')
    console.log('[TopologyViewer] networkData:', !!networkData, 'cytoscapeInitialized:', cytoscapeInitializedRef.current, 'cyRef:', !!cy.cyRef.current)

    if (!networkData) {
      console.log('[TopologyViewer] No network data available')
      return
    }

    if (!cy.cyRef.current) {
      console.log('[TopologyViewer] Cytoscape instance not available')

      if (containerRef.current && !isUpdatingRef.current) {
        console.log('[TopologyViewer] Container exists, triggering initialization')
        cytoscapeInitializedRef.current = false
        handleContainerRef(containerRef.current)
      }
      return
    }

    if (isUpdatingRef.current) {
      console.log('[TopologyViewer] Initialization in progress, skipping update')
      return
    }

    // Build graph elements from all network data layers
    console.log('[TopologyViewer] Building graph elements from network data')
    const elements = buildGraphElements(networkData.node_properties, {
      physical: networkData.edges,
      layer3: networkData.layer3_edges,
      ospf: networkData.ospf_edges,
      bgp: networkData.bgp_edges,
      vxlan: networkData.vxlan_edges,
      eigrp: networkData.eigrp_edges,
      isis: networkData.isis_edges,
      ipsec: networkData.ipsec_edges,
      'switched-vlan': networkData.switched_vlan_edges,
    }, visibleLayers)

    // Check for saved node positions from previous snapshot view
    const savedPositions = currentSnapshotName ? getPositions(currentSnapshotName) : null
    const hasSavedPositions = savedPositions && Object.keys(savedPositions).length > 0

    // Restore saved positions or apply automatic layout
    if (hasSavedPositions) {
      console.log(`[TopologyViewer] Found ${Object.keys(savedPositions).length} saved positions for snapshot: ${currentSnapshotName}`)
      console.log('[TopologyViewer] Updating graph WITHOUT layout (will restore saved positions)')
      cy.updateElements([...elements.nodes, ...elements.edges], false)

      console.log('[TopologyViewer] Restoring node positions immediately')
      cy.restoreNodePositions(savedPositions)

      setTimeout(() => {
        cy.fit()
      }, 50)
    } else {
      console.log(`[TopologyViewer] No saved positions for snapshot: ${currentSnapshotName}, applying layout`)
      cy.updateElements([...elements.nodes, ...elements.edges], true)
    }
  }, [networkData, cy, handleContainerRef, visibleLayers, currentSnapshotName, getPositions])

  /**
   * Cleanup effect: Destroys Cytoscape instance on component unmount
   * IMPORTANT: Empty dependency array prevents premature cleanup in React Strict Mode
   */
  useEffect(() => {
    return () => {
      if (cytoscapeInitializedRef.current && cy.cyRef.current) {
        console.log('[TopologyViewer] Component unmounting, destroying Cytoscape')
        cy.destroy()
        cytoscapeInitializedRef.current = false
      }
    }
  }, [])

  /**
   * Event listeners effect: Manages graph interaction handlers
   * Handles node/edge selection, background clicks, and position saving
   * Includes proper cleanup to prevent memory leaks
   */
  useEffect(() => {
    console.log('[TopologyViewer] Setting up event listeners, initialized:', cytoscapeInitializedRef.current)

    if (!cy.cyRef.current || !cytoscapeInitializedRef.current) {
      console.log('[TopologyViewer] Cytoscape not ready for event listeners')
      return
    }

    const instance = cy.cyRef.current
    console.log('[TopologyViewer] Registering event listeners on Cytoscape instance')

    /**
     * Handle node selection with error handling and data validation
     * Updates selected node in global store when user taps/clicks a node
     */
    const handleNodeTap = (event: any) => {
      try {
        const nodeId = event.target?.data?.('id')

        if (!nodeId) {
          console.warn('[TopologyViewer] Node tapped but no ID found:', event.target)
          return
        }

        console.log('[TopologyViewer] Node tapped:', nodeId)
        setSelectedNode(nodeId)
      } catch (error) {
        console.error('[TopologyViewer] Error handling node tap:', error, {
          target: event.target,
          hasData: typeof event.target?.data === 'function'
        })
      }
    }

    /**
     * Handle edge selection with error handling and data validation
     * Updates selected edge in global store when user taps/clicks an edge
     */
    const handleEdgeTap = (event: any) => {
      try {
        const edgeId = event.target?.data?.('id')

        if (!edgeId) {
          console.warn('[TopologyViewer] Edge tapped but no ID found:', event.target)
          return
        }

        console.log('[TopologyViewer] Edge tapped:', edgeId)
        setSelectedEdge(edgeId)
      } catch (error) {
        console.error('[TopologyViewer] Error handling edge tap:', error, {
          target: event.target,
          hasData: typeof event.target?.data === 'function'
        })
      }
    }

    /**
     * Clear selection when clicking graph background
     * Deselects both nodes and edges when user clicks empty canvas area
     */
    const handleBackgroundTap = (event: any) => {
      try {
        if (event.target === instance) {
          console.log('[TopologyViewer] Background tapped, clearing selection')
          setSelectedNode(null)
          setSelectedEdge(null)
        }
      } catch (error) {
        console.error('[TopologyViewer] Error handling background tap:', error)
      }
    }

    /**
     * Debounced position saving when node is dragged
     * Waits 500ms after drag ends before persisting positions
     */
    const handleNodeFree = () => {
      try {
        // Clear existing debounce timer
        if (savePositionTimeoutRef.current) {
          clearTimeout(savePositionTimeoutRef.current)
        }

        // Save positions after 500ms delay (debounce)
        savePositionTimeoutRef.current = setTimeout(() => {
          if (!currentSnapshotName) {
            console.log('[TopologyViewer] Cannot save positions: no snapshot selected')
            return
          }

          const positions = cy.saveNodePositions()
          savePositions(currentSnapshotName, positions)
          console.log(`[TopologyViewer] Node positions saved for snapshot: ${currentSnapshotName}`)
        }, 500)
      } catch (error) {
        console.error('[TopologyViewer] Error handling node free event:', error)
      }
    }

    instance.on('tap', 'node', handleNodeTap)
    instance.on('tap', 'edge', handleEdgeTap)
    instance.on('tap', handleBackgroundTap)
    instance.on('free', 'node', handleNodeFree)

    console.log('[TopologyViewer] Event listeners registered successfully')

    return () => {
      console.log('[TopologyViewer] Cleaning up event listeners')

      if (savePositionTimeoutRef.current) {
        clearTimeout(savePositionTimeoutRef.current)
        savePositionTimeoutRef.current = null
      }

      if (instance && !instance.destroyed()) {
        try {
          instance.off('tap', 'node', handleNodeTap)
          instance.off('tap', 'edge', handleEdgeTap)
          instance.off('tap', handleBackgroundTap)
          instance.off('free', 'node', handleNodeFree)
          console.log('[TopologyViewer] Event listeners removed successfully')
        } catch (error) {
          console.error('[TopologyViewer] Error removing event listeners:', error)
        }
      } else {
        console.log('[TopologyViewer] Cytoscape instance already destroyed, skipping cleanup')
      }
    }
  }, [cy, cytoscapeInitializedRef.current, setSelectedNode, setSelectedEdge, currentSnapshotName, savePositions])

  /**
   * Applies selected layout algorithm to graph
   */
  const handleLayoutChange = useCallback(
    (layoutName: LayoutName) => {
      cy.applyLayout(layoutName)
      setCurrentLayout(layoutName)
    },
    [cy, setCurrentLayout]
  )

  /**
   * Exports current graph view as PNG image
   * Triggers browser download with timestamped filename
   */
  const handleExportPNG = useCallback(() => {
    try {
      if (!cy.cyRef.current) {
        throw new Error(t('topologyViewer.errors.notInitialized'))
      }

      const png = cy.exportPNG()

      if (!png) {
        throw new Error(t('topologyViewer.errors.pngFailed'))
      }

      const link = document.createElement('a')
      link.download = `topology-${new Date().toISOString().split('T')[0]}.png`
      link.href = png
      link.click()

      setTimeout(() => {
        link.remove()
      }, 100)
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : t('topologyViewer.errors.exportFailed')
      console.error('PNG Export Error:', error)
      alert(`Export Failed: ${errorMessage}`)
    }
  }, [cy, t])

  if (isLoading || (!networkData && isFetching)) {
    return (
      <div className="flex items-center justify-center h-full" role="status" aria-live="polite">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600 mx-auto" aria-hidden="true"></div>
          <p className="mt-4 text-gray-600">{t('topologyViewer.loading')}</p>
          <span className="sr-only">{t('topologyViewer.loadingDetail')}</span>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-full" role="alert" aria-live="assertive">
        <div className="text-center">
          <p className="text-red-600 font-semibold">{t('topologyViewer.errors.loadFailed')}</p>
          <p className="text-sm text-gray-600 mt-2">{t('topologyViewer.errors.connectionIssue')}</p>
          <button
            onClick={handleRefresh}
            className="mt-4 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-2 transition-colors"
            aria-label="Retry loading network data"
          >
            Retry
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="relative w-full h-full">
      <div
        ref={handleContainerRef}
        className="w-full h-full bg-white"
        role="img"
        aria-label="Network topology graph visualization"
      />

      {isFetching && networkData && (
        <div className="absolute inset-0 bg-white/80 flex items-center justify-center z-10" role="status" aria-live="polite">
          <div className="text-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600 mx-auto" aria-hidden="true"></div>
            <p className="mt-4 text-gray-600">{t('topologyViewer.loading')}</p>
            <span className="sr-only">{t('topologyViewer.loadingDetail')}</span>
          </div>
        </div>
      )}

      <nav className="absolute top-4 left-4 bg-white rounded-lg shadow-lg p-2 flex flex-col gap-2" aria-label="Topology controls">
        <button
          onClick={() => cy.zoomIn()}
          className="p-2 hover:bg-gray-100 rounded transition-colors focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-1"
          aria-label={t('topologyViewer.controls.zoomIn')}
          title="Zoom In"
        >
          <ZoomIn className="w-5 h-5" aria-hidden="true" />
          <span className="sr-only">{t('topologyViewer.controls.zoomIn')}</span>
        </button>
        <button
          onClick={() => cy.zoomOut()}
          className="p-2 hover:bg-gray-100 rounded transition-colors focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-1"
          aria-label={t('topologyViewer.controls.zoomOut')}
          title="Zoom Out"
        >
          <ZoomOut className="w-5 h-5" aria-hidden="true" />
          <span className="sr-only">{t('topologyViewer.controls.zoomOut')}</span>
        </button>
        <button
          onClick={() => cy.fit()}
          className="p-2 hover:bg-gray-100 rounded transition-colors focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-1"
          aria-label={t('topologyViewer.controls.fitToScreen')}
          title="Fit to Screen"
        >
          <Maximize className="w-5 h-5" aria-hidden="true" />
          <span className="sr-only">{t('topologyViewer.controls.fitToScreen')}</span>
        </button>
        <div className="border-t border-gray-200 my-1" role="separator" aria-hidden="true" />
        <button
          onClick={handleRefresh}
          className="p-2 hover:bg-gray-100 rounded transition-colors focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-1"
          aria-label={t('topologyViewer.controls.refresh')}
          title="Refresh"
        >
          <RefreshCw className="w-5 h-5" aria-hidden="true" />
          <span className="sr-only">{t('topologyViewer.controls.refresh')}</span>
        </button>
        <button
          onClick={handleExportPNG}
          className="p-2 hover:bg-gray-100 rounded transition-colors focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-1"
          aria-label={t('topologyViewer.controls.exportPng')}
          title="Export PNG"
        >
          <Download className="w-5 h-5" aria-hidden="true" />
          <span className="sr-only">{t('topologyViewer.controls.exportPng')}</span>
        </button>
      </nav>

      <div className="absolute top-4 right-4 bg-white rounded-lg shadow-lg p-3 min-w-[200px]">
        <button
          className="flex items-center justify-between w-full gap-2 px-1 hover:bg-gray-50 rounded transition-colors"
          onClick={() => setLayersDropdownOpen(!layersDropdownOpen)}
          aria-expanded={layersDropdownOpen}
          aria-haspopup="true"
        >
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-gray-600" aria-hidden="true" />
            <span className="text-sm font-medium text-gray-700">{t('topologyViewer.layers.title')}</span>
          </div>
          {layersDropdownOpen ? (
            <ChevronUp className="w-4 h-4 text-gray-600" aria-hidden="true" />
          ) : (
            <ChevronDown className="w-4 h-4 text-gray-600" aria-hidden="true" />
          )}
        </button>

        {layersDropdownOpen && (
          <div className="mt-3 space-y-2 border-t pt-3" role="group" aria-label={t('topologyViewer.layers.title')}>
            <label className="flex items-center gap-2 cursor-pointer hover:bg-gray-50 px-2 py-1 rounded">
              <input
                type="checkbox"
                checked={visibleLayers.has('physical')}
                onChange={() => toggleVisibleLayer('physical')}
                className="w-4 h-4 text-primary-600 focus:ring-2 focus:ring-primary-600 focus:ring-offset-1 rounded"
              />
              <span className="text-sm text-gray-700">{t('topologyViewer.layers.physical')}</span>
            </label>

            <label className="flex items-center gap-2 cursor-pointer hover:bg-gray-50 px-2 py-1 rounded">
              <input
                type="checkbox"
                checked={visibleLayers.has('layer3')}
                onChange={() => toggleVisibleLayer('layer3')}
                className="w-4 h-4 text-primary-600 focus:ring-2 focus:ring-primary-600 focus:ring-offset-1 rounded"
              />
              <span className="text-sm text-gray-700">{t('topologyViewer.layers.layer3')}</span>
            </label>

            <label className="flex items-center gap-2 cursor-pointer hover:bg-gray-50 px-2 py-1 rounded">
              <input
                type="checkbox"
                checked={visibleLayers.has('ospf')}
                onChange={() => toggleVisibleLayer('ospf')}
                className="w-4 h-4 text-primary-600 focus:ring-2 focus:ring-primary-600 focus:ring-offset-1 rounded"
              />
              <span className="text-sm text-gray-700">{t('topologyViewer.layers.ospf')}</span>
            </label>

            <label className="flex items-center gap-2 cursor-pointer hover:bg-gray-50 px-2 py-1 rounded">
              <input
                type="checkbox"
                checked={visibleLayers.has('bgp')}
                onChange={() => toggleVisibleLayer('bgp')}
                className="w-4 h-4 text-primary-600 focus:ring-2 focus:ring-primary-600 focus:ring-offset-1 rounded"
              />
              <span className="text-sm text-gray-700">{t('topologyViewer.layers.bgp')}</span>
            </label>

            <label className="flex items-center gap-2 cursor-pointer hover:bg-gray-50 px-2 py-1 rounded">
              <input
                type="checkbox"
                checked={visibleLayers.has('vxlan')}
                onChange={() => toggleVisibleLayer('vxlan')}
                className="w-4 h-4 text-primary-600 focus:ring-2 focus:ring-primary-600 focus:ring-offset-1 rounded"
              />
              <span className="text-sm text-gray-700">{t('topologyViewer.layers.vxlan')}</span>
            </label>

            <label className="flex items-center gap-2 cursor-pointer hover:bg-gray-50 px-2 py-1 rounded">
              <input
                type="checkbox"
                checked={visibleLayers.has('eigrp')}
                onChange={() => toggleVisibleLayer('eigrp')}
                className="w-4 h-4 text-primary-600 focus:ring-2 focus:ring-primary-600 focus:ring-offset-1 rounded"
              />
              <span className="text-sm text-gray-700">{t('topologyViewer.layers.eigrp')}</span>
            </label>

            <label className="flex items-center gap-2 cursor-pointer hover:bg-gray-50 px-2 py-1 rounded">
              <input
                type="checkbox"
                checked={visibleLayers.has('isis')}
                onChange={() => toggleVisibleLayer('isis')}
                className="w-4 h-4 text-primary-600 focus:ring-2 focus:ring-primary-600 focus:ring-offset-1 rounded"
              />
              <span className="text-sm text-gray-700">{t('topologyViewer.layers.isis')}</span>
            </label>

            <label className="flex items-center gap-2 cursor-pointer hover:bg-gray-50 px-2 py-1 rounded">
              <input
                type="checkbox"
                checked={visibleLayers.has('ipsec')}
                onChange={() => toggleVisibleLayer('ipsec')}
                className="w-4 h-4 text-primary-600 focus:ring-2 focus:ring-primary-600 focus:ring-offset-1 rounded"
              />
              <span className="text-sm text-gray-700">{t('topologyViewer.layers.ipsec')}</span>
            </label>

            <label className="flex items-center gap-2 cursor-pointer hover:bg-gray-50 px-2 py-1 rounded">
              <input
                type="checkbox"
                checked={visibleLayers.has('switched-vlan')}
                onChange={() => toggleVisibleLayer('switched-vlan')}
                className="w-4 h-4 text-primary-600 focus:ring-2 focus:ring-primary-600 focus:ring-offset-1 rounded"
              />
              <span className="text-sm text-gray-700">{t('topologyViewer.layers.switchedVlan')}</span>
            </label>
          </div>
        )}
      </div>
    </div>
  )
})