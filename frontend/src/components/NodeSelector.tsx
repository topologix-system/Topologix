import { useTranslation } from 'react-i18next'
import { Router } from 'lucide-react'
import { useNodes } from '../hooks'
import { useUIStore } from '../store'

/**
 * Node selector dropdown component
 * Allows users to select network nodes from the topology
 * Fetches node data using React Query (NO useEffect)
 * Updates global UI store with selected node ID
 */
export function NodeSelector() {
  const { t } = useTranslation()
  const selectedNodeId = useUIStore((state) => state.selectedNodeId)
  const setSelectedNode = useUIStore((state) => state.setSelectedNode)
  const { data: nodes, isLoading, isError } = useNodes()

  /**
   * Handle node selection change from dropdown
   * Updates global state with selected node ID (null for deselection)
   */
  const handleNodeChange = (event: React.ChangeEvent<HTMLSelectElement>) => {
    const nodeId = event.target.value
    console.log('[NodeSelector] Node selection changed:', nodeId)

    if (nodeId === '') {
      setSelectedNode(null)
    } else {
      setSelectedNode(nodeId)
    }
  }

  if (isError) {
    return (
      <div className="flex items-center gap-2 text-sm text-red-600" role="alert">
        <Router className="w-4 h-4" aria-hidden="true" />
        <span>{t('nodeSelector.error', 'Failed to load nodes')}</span>
      </div>
    )
  }

  return (
    <div className="flex items-center gap-2">
      <Router className="w-4 h-4 text-gray-600" aria-hidden="true" />
      <select
        id="node-selector"
        value={selectedNodeId || ''}
        onChange={handleNodeChange}
        disabled={isLoading}
        className="flex-1 px-3 py-1.5 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-1 disabled:opacity-50 disabled:cursor-not-allowed"
        aria-label={t('nodeSelector.label', 'Select node')}
      >
        <option value="">
          {isLoading
            ? t('nodeSelector.loading', 'Loading nodes...')
            : t('nodeSelector.placeholder', 'Select a node...')}
        </option>
        {nodes?.map((node) => (
          <option key={node.node} value={node.node}>
            {node.node}
          </option>
        ))}
      </select>
    </div>
  )
}
