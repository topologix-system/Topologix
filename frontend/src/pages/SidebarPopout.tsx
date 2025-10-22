/**
 * Standalone sidebar window for multi-monitor setups
 * - Opened via popout button in main Sidebar component (window.open)
 * - Shares Zustand state with main window: sidebar tab selection synchronized
 * - Lazy-loaded panels (all 6 tabs) with Suspense fallback for performance
 * - Dynamic window title updates based on active tab for easy window identification
 * - Includes NodeSelector for consistent node filtering across windows
 * - Full feature parity with main window sidebar panels
 */
import { useEffect, lazy, Suspense } from 'react'
import { Info, Router, Link, AlertCircle, Search, Network } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useUIStore, type SidebarTab } from '../store'
import { NodeSelector } from '../components/NodeSelector'

// Lazy load panels to reduce initial bundle size and API requests
const OverviewPanel = lazy(() => import('../components/panels/OverviewPanel'))
const NodeDetailsPanel = lazy(() => import('../components/panels/NodeDetailsPanel'))
const EdgeDetailsPanel = lazy(() => import('../components/panels/EdgeDetailsPanel'))
const ValidationPanel = lazy(() => import('../components/panels/ValidationPanel'))
const NetworkAnalysisPanel = lazy(() => import('../components/panels/NetworkAnalysisPanel'))
const TraceroutePanel = lazy(() => import('../components/panels/TraceroutePanel'))

export function SidebarPopout() {
  const { t } = useTranslation()
  const sidebarTab = useUIStore((state) => state.sidebarTab)
  const setSidebarTab = useUIStore((state) => state.setSidebarTab)

  /**
   * Tab configuration array for popout window
   * Matches main window sidebar tabs for consistent UX
   * Each tab maps to a lazy-loaded panel component
   */
  const tabs: Array<{ id: SidebarTab; label: string; icon: React.ReactNode }> = [
    { id: 'overview', label: t('sidebar.tabs.overview'), icon: <Info className="w-4 h-4" /> },
    { id: 'node-details', label: t('sidebar.tabs.nodeDetails'), icon: <Router className="w-4 h-4" /> },
    { id: 'edge-details', label: t('sidebar.tabs.edgeDetails'), icon: <Link className="w-4 h-4" /> },
    { id: 'validation', label: t('sidebar.tabs.validation'), icon: <AlertCircle className="w-4 h-4" /> },
    { id: 'analysis', label: t('sidebar.tabs.analysis'), icon: <Search className="w-4 h-4" /> },
    { id: 'traceroute', label: t('sidebar.tabs.traceroute'), icon: <Network className="w-4 h-4" /> },
  ]

  // Update window title based on active tab
  useEffect(() => {
    const tabLabel = tabs.find((tab) => tab.id === sidebarTab)?.label || 'Sidebar'
    document.title = `Topologix - ${tabLabel}`
    console.log('[SidebarPopout] Active tab changed to:', sidebarTab)
  }, [sidebarTab, tabs, t])

  return (
    <div className="h-screen flex flex-col bg-white">
      {/* Header */}
      <div className="px-4 py-3 border-b border-gray-200 bg-gray-50">
        <h1 className="text-lg font-bold text-gray-900">Topologix</h1>
        <p className="text-xs text-gray-600">{t('app.subtitle', 'Network Topology Visualization')}</p>
      </div>

      {/* Node Selector */}
      <div className="px-4 py-3 border-b border-gray-200 bg-white">
        <NodeSelector />
      </div>

      {/* Tabs */}
      <div
        className="flex border-b border-gray-200 overflow-x-auto"
        role="tablist"
        aria-label={t('sidebar.ariaTabList')}
      >
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setSidebarTab(tab.id)}
            role="tab"
            aria-selected={sidebarTab === tab.id}
            aria-controls={`tabpanel-${tab.id}`}
            id={`tab-${tab.id}`}
            tabIndex={sidebarTab === tab.id ? 0 : -1}
            className={`flex items-center gap-2 px-4 py-3 text-sm font-medium transition-colors whitespace-nowrap focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-inset ${
              sidebarTab === tab.id
                ? 'text-primary-600 border-b-2 border-primary-600 bg-primary-50'
                : 'text-gray-600 hover:text-gray-900 hover:bg-gray-50'
            }`}
          >
            <span aria-hidden="true">{tab.icon}</span>
            {tab.label}
          </button>
        ))}
      </div>

      {/* Panel Content */}
      <div
        className="flex-1 overflow-y-auto p-4"
        role="tabpanel"
        id={`tabpanel-${sidebarTab}`}
        aria-labelledby={`tab-${sidebarTab}`}
        tabIndex={0}
      >
        <Suspense fallback={
          <div className="flex items-center justify-center py-8" role="status">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600" />
            <span className="sr-only">{t('common.loading')}</span>
          </div>
        }>
          {sidebarTab === 'overview' && <OverviewPanel />}
          {sidebarTab === 'node-details' && <NodeDetailsPanel />}
          {sidebarTab === 'edge-details' && <EdgeDetailsPanel />}
          {sidebarTab === 'validation' && <ValidationPanel />}
          {sidebarTab === 'analysis' && <NetworkAnalysisPanel />}
          {sidebarTab === 'traceroute' && <TraceroutePanel />}
        </Suspense>
      </div>
    </div>
  )
}