/**
 * Main UI state management with Zustand
 * - Manages sidebar visibility, active tab, node selections, filters, layout preferences
 * - Persists user preferences to localStorage with custom serialization
 * - Custom Set serialization/deserialization for layer visibility filters (Set<LayerType>)
 * - Integrated with Redux DevTools for state debugging in development
 * - Handles filter toggles, node selection, and graph interaction state
 */
import { create } from 'zustand'
import { devtools, persist } from 'zustand/middleware'
import type { LayoutName, LayerType } from '../lib/cytoscape/types'

/**
 * View mode for topology display
 * - topology: Full screen graph visualization
 * - table: Data table view (future feature)
 * - split: Split screen graph and table
 */
export type ViewMode = 'topology' | 'table' | 'split'

/**
 * Theme preference options
 * System theme follows OS/browser preference
 */
export type Theme = 'light' | 'dark' | 'system'

/**
 * Sidebar tab identifiers for different analysis panels
 * Used to switch between overview, node details, validation, etc.
 */
export type SidebarTab = 'overview' | 'node-details' | 'edge-details' | 'ospf' | 'validation' | 'analysis' | 'traceroute'

/**
 * UI store state and actions
 * Comprehensive UI preferences and interaction state
 */
interface UIState {
  sidebarOpen: boolean
  sidebarTab: SidebarTab
  sidebarWidth: number

  selectedNodeId: string | null
  selectedEdgeId: string | null

  viewMode: ViewMode
  showMinimap: boolean

  currentLayout: LayoutName
  showLabels: boolean
  showEdgeLabels: boolean

  theme: Theme

  nodeTypeFilter: Set<string>
  protocolFilter: Set<string>
  visibleLayers: Set<LayerType>

  setSidebarOpen: (open: boolean) => void
  setSidebarTab: (tab: SidebarTab) => void
  setSidebarWidth: (width: number) => void

  setSelectedNode: (nodeId: string | null) => void
  setSelectedEdge: (edgeId: string | null) => void
  clearSelection: () => void

  setViewMode: (mode: ViewMode) => void
  setShowMinimap: (show: boolean) => void

  setCurrentLayout: (layout: LayoutName) => void
  setShowLabels: (show: boolean) => void
  setShowEdgeLabels: (show: boolean) => void

  setTheme: (theme: Theme) => void

  toggleNodeTypeFilter: (nodeType: string) => void
  toggleProtocolFilter: (protocol: string) => void
  toggleVisibleLayer: (layer: LayerType) => void
  setVisibleLayers: (layers: Set<LayerType>) => void
  clearFilters: () => void
}

/**
 * Zustand UI store with Redux DevTools and localStorage persistence
 * Persists user preferences (layout, labels, theme) across sessions
 * Custom Set serialization for layer visibility filters
 * Integrated with DevTools for state debugging
 */
export const useUIStore = create<UIState>()(
  devtools(
    persist(
      (set) => ({
        sidebarOpen: true,
        sidebarTab: 'overview',
        sidebarWidth: 320,

        selectedNodeId: null,
        selectedEdgeId: null,

        viewMode: 'topology',
        showMinimap: false,

        currentLayout: 'cola',
        showLabels: true,
        showEdgeLabels: false,

        theme: 'system',

        nodeTypeFilter: new Set(),
        protocolFilter: new Set(),
        visibleLayers: new Set(['physical', 'layer3', 'ospf', 'bgp']),

        setSidebarOpen: (open) => set({ sidebarOpen: open }),
        setSidebarTab: (tab) => set({ sidebarTab: tab, sidebarOpen: true }),
        setSidebarWidth: (width) => set({ sidebarWidth: width }),

        setSelectedNode: (nodeId) =>
          set({
            selectedNodeId: nodeId,
            selectedEdgeId: null,
            sidebarTab: nodeId ? 'node-details' : 'overview',
          }),

        setSelectedEdge: (edgeId) =>
          set({
            selectedEdgeId: edgeId,
            selectedNodeId: null,
            sidebarTab: edgeId ? 'edge-details' : 'overview',
          }),

        clearSelection: () =>
          set({
            selectedNodeId: null,
            selectedEdgeId: null,
          }),

        setViewMode: (mode) => set({ viewMode: mode }),
        setShowMinimap: (show) => set({ showMinimap: show }),

        setCurrentLayout: (layout) => set({ currentLayout: layout }),
        setShowLabels: (show) => set({ showLabels: show }),
        setShowEdgeLabels: (show) => set({ showEdgeLabels: show }),

        setTheme: (theme) => set({ theme }),

        toggleNodeTypeFilter: (nodeType) =>
          set((state) => {
            const newFilter = new Set(state.nodeTypeFilter)
            if (newFilter.has(nodeType)) {
              newFilter.delete(nodeType)
            } else {
              newFilter.add(nodeType)
            }
            return { nodeTypeFilter: newFilter }
          }),

        toggleProtocolFilter: (protocol) =>
          set((state) => {
            const newFilter = new Set(state.protocolFilter)
            if (newFilter.has(protocol)) {
              newFilter.delete(protocol)
            } else {
              newFilter.add(protocol)
            }
            return { protocolFilter: newFilter }
          }),

        toggleVisibleLayer: (layer) =>
          set((state) => {
            const newLayers = new Set(state.visibleLayers)
            if (newLayers.has(layer)) {
              newLayers.delete(layer)
            } else {
              newLayers.add(layer)
            }
            return { visibleLayers: newLayers }
          }),

        setVisibleLayers: (layers) => set({ visibleLayers: layers }),

        clearFilters: () =>
          set({
            nodeTypeFilter: new Set(),
            protocolFilter: new Set(),
          }),
      }),
      {
        name: 'topologix-ui-storage',
        partialize: (state) => ({
          sidebarWidth: state.sidebarWidth,
          viewMode: state.viewMode,
          showMinimap: state.showMinimap,
          currentLayout: state.currentLayout,
          showLabels: state.showLabels,
          showEdgeLabels: state.showEdgeLabels,
          theme: state.theme,
          visibleLayers: Array.from(state.visibleLayers),
        }),
        merge: (persistedState: any, currentState: UIState) => ({
          ...currentState,
          ...persistedState,
          visibleLayers: new Set(persistedState?.visibleLayers || ['physical', 'layer3', 'ospf', 'bgp']),
        }),
      }
    ),
    { name: 'UIStore' }
  )
)