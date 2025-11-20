import { useCallback, lazy, Suspense } from 'react'
import { Info, Router, Link, AlertCircle, Search, Network, ExternalLink } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useUIStore, type SidebarTab } from '../store'
import { SidebarResizeHandle } from './SidebarResizeHandle'

// Lazy-loaded panels to improve initial page load performance
const OverviewPanel = lazy(() => import('./panels/OverviewPanel'))
const NodeDetailsPanel = lazy(() => import('./panels/NodeDetailsPanel'))
const EdgeDetailsPanel = lazy(() => import('./panels/EdgeDetailsPanel'))
const ValidationPanel = lazy(() => import('./panels/ValidationPanel'))
const NetworkAnalysisPanel = lazy(() => import('./panels/NetworkAnalysisPanel'))
const TraceroutePanel = lazy(() => import('./panels/TraceroutePanel'))

/**
 * Resizable sidebar with tabbed panels
 * Supports popout to separate window for multi-monitor setups
 */
export function Sidebar() {
  const { t } = useTranslation()
  const sidebarTab = useUIStore((state) => state.sidebarTab)
  const setSidebarTab = useUIStore((state) => state.setSidebarTab)
  const sidebarWidth = useUIStore((state) => state.sidebarWidth)

  /**
   * Opens sidebar in a centered popout window
   * Useful for multi-monitor setups
   */
  const handlePopout = useCallback(() => {
    console.log('[Sidebar] Opening sidebar in new window')
    const width = 800
    const height = 600
    const left = window.screenX + (window.outerWidth - width) / 2
    const top = window.screenY + (window.outerHeight - height) / 2

    window.open(
      '/sidebar-popout',
      'Topologix Sidebar',
      `width=${width},height=${height},left=${left},top=${top},resizable=yes,scrollbars=yes`
    )
  }, [])

  /**
   * Sidebar tab configuration array
   * Defines all available tabs with their icons, labels, and routing keys
   * Each tab corresponds to a lazy-loaded panel component rendered below
   */
  const tabs: Array<{ id: SidebarTab; label: string; icon: React.ReactNode }> = [
    { id: 'overview', label: t('sidebar.tabs.overview'), icon: <Info className="w-4 h-4" /> },
    { id: 'node-details', label: t('sidebar.tabs.nodeDetails'), icon: <Router className="w-4 h-4" /> },
    { id: 'edge-details', label: t('sidebar.tabs.edgeDetails'), icon: <Link className="w-4 h-4" /> },
    { id: 'validation', label: t('sidebar.tabs.validation'), icon: <AlertCircle className="w-4 h-4" /> },
    { id: 'analysis', label: t('sidebar.tabs.analysis'), icon: <Search className="w-4 h-4" /> },
    { id: 'traceroute', label: t('sidebar.tabs.traceroute'), icon: <Network className="w-4 h-4" /> },
  ]

  return (
    <aside
      id="main-sidebar"
      className="absolute top-0 right-0 bottom-0 bg-white border-l border-gray-200 flex flex-col"
      style={{ width: `${sidebarWidth}px` }}
      role="complementary"
      aria-label={t('sidebar.ariaLabel')}
    >
      <SidebarResizeHandle />

      <div className="flex items-center justify-between px-4 py-2 border-b border-gray-200 bg-gray-50">
        <span className="text-sm font-medium text-gray-700">{t('sidebar.title', 'Sidebar')}</span>
        <button
          onClick={handlePopout}
          className="p-1.5 hover:bg-gray-200 rounded transition-colors focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-1"
          aria-label={t('sidebar.popout', 'Open in new window')}
          title={t('sidebar.popout', 'Open in new window')}
        >
          <ExternalLink className="w-4 h-4 text-gray-600" aria-hidden="true" />
          <span className="sr-only">{t('sidebar.popout', 'Open in new window')}</span>
        </button>
      </div>

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

      {/* Panel content area with lazy-loaded components */}
      <div
        className="flex-1 overflow-y-auto p-4"
        role="tabpanel"
        id={`tabpanel-${sidebarTab}`}
        aria-labelledby={`tab-${sidebarTab}`}
        tabIndex={0}
      >
        {/* Conditionally render panel based on active tab
            Suspense handles loading state while lazy components are fetched */}
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
    </aside>
  )
}