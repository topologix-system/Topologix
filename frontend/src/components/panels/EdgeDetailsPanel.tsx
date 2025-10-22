/**
 * Edge details panel displaying properties of selected network connections
 * - Supports 4 edge types: physical, layer3, OSPF, BGP with type-specific details
 * - useMemo optimization for edge lookup from selectedEdgeId in Zustand store
 * - Shows interface names, IP addresses, VLAN info, protocol-specific metrics
 * - Bidirectional edge matching: finds edge by either direction (A-B or B-A)
 * - Extracts source/target node names from interface strings for display
 */
import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { Link2, Activity, Database, Zap } from 'lucide-react'
import { useUIStore } from '../../store'
import { useAllNetworkData } from '../../hooks'
import type { PhysicalEdge, Layer3Edge, BGPEdge } from '../../types/edges'
import type { OSPFEdge } from '../../types/ospf'

interface EdgeData {
  type: 'physical' | 'layer3' | 'ospf' | 'bgp'
  data: PhysicalEdge | Layer3Edge | OSPFEdge | BGPEdge | null
  sourceNode: string | null
  targetNode: string | null
}

export function EdgeDetailsPanel() {
  const { t } = useTranslation()
  const selectedEdgeId = useUIStore((state) => state.selectedEdgeId)
  const { data: networkData, isLoading } = useAllNetworkData()

  /**
   * Find and normalize edge data from network topology
   * - Searches through 4 edge types: physical, layer3, OSPF, BGP
   * - Supports bidirectional matching: finds edge regardless of direction
   * - Extracts source/target node names from interface strings
   * - Returns null if edge not found in any collection
   * - Memoized to prevent unnecessary recalculation on re-renders
   */
  const edgeData = useMemo<EdgeData | null>(() => {
    if (!selectedEdgeId || !networkData) return null

    const parts = selectedEdgeId.split('-')
    if (parts.length < 2) return null

    const physicalEdge = networkData.edges.find(
      (edge) =>
        `${edge.interface}-${edge.remote_interface}` === selectedEdgeId ||
        `${edge.remote_interface}-${edge.interface}` === selectedEdgeId
    )
    if (physicalEdge) {
      const [sourceNode] = physicalEdge.interface.split('[')
      const [targetNode] = physicalEdge.remote_interface.split('[')
      return {
        type: 'physical',
        data: physicalEdge,
        sourceNode,
        targetNode,
      }
    }

    const layer3Edge = networkData.layer3_edges.find(
      (edge) =>
        `${edge.interface}-${edge.remote_interface}` === selectedEdgeId ||
        `${edge.remote_interface}-${edge.interface}` === selectedEdgeId
    )
    if (layer3Edge) {
      const [sourceNode] = layer3Edge.interface.split('[')
      const [targetNode] = layer3Edge.remote_interface.split('[')
      return {
        type: 'layer3',
        data: layer3Edge,
        sourceNode,
        targetNode,
      }
    }

    const ospfEdge = networkData.ospf_edges.find(
      (edge) =>
        `${edge.interface}-${edge.remote_interface}` === selectedEdgeId ||
        `${edge.remote_interface}-${edge.interface}` === selectedEdgeId
    )
    if (ospfEdge) {
      const [sourceNode] = ospfEdge.interface.split('[')
      const [targetNode] = ospfEdge.remote_interface.split('[')
      return {
        type: 'ospf',
        data: ospfEdge,
        sourceNode,
        targetNode,
      }
    }

    const bgpEdge = networkData.bgp_edges?.find(
      (edge) => {
        const nodeMatch = `${edge.node}-${edge.remote_node}` === selectedEdgeId ||
                         `${edge.remote_node}-${edge.node}` === selectedEdgeId

        if (edge.interface && edge.remote_interface) {
          const interfaceMatch = `${edge.interface}-${edge.remote_interface}` === selectedEdgeId ||
                                `${edge.remote_interface}-${edge.interface}` === selectedEdgeId
          return nodeMatch || interfaceMatch
        }

        return nodeMatch
      }
    )
    if (bgpEdge) {
      return {
        type: 'bgp',
        data: bgpEdge,
        sourceNode: bgpEdge.node,
        targetNode: bgpEdge.remote_node,
      }
    }

    return {
      type: 'physical',
      data: null,
      sourceNode: parts[0],
      targetNode: parts[1],
    }
  }, [selectedEdgeId, networkData])

  if (!selectedEdgeId) {
    return (
      <div className="text-center text-gray-700 py-8" role="status">
        <p>{t('edgeDetails.selectEdge')}</p>
      </div>
    )
  }

  if (isLoading) {
    return (
      <div className="space-y-4" role="region" aria-label="Edge details" aria-busy="true">
        <h2 className="text-lg font-semibold text-gray-900">{t('edgeDetails.title')}</h2>
        <div className="flex items-center justify-center py-8">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600" aria-hidden="true"></div>
          <span className="sr-only">{t('edgeDetails.loading')}</span>
        </div>
      </div>
    )
  }

  if (!edgeData) {
    return (
      <div className="space-y-4" role="region" aria-label="Edge details">
        <h2 className="text-lg font-semibold text-gray-900">{t('edgeDetails.title')}</h2>
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4" role="alert">
          <p className="text-sm text-yellow-800">
            {t('edgeDetails.notFound')}
          </p>
          <p className="text-xs text-yellow-700 mt-1">{t('edgeDetails.fields.edgeId')}: {selectedEdgeId}</p>
        </div>
      </div>
    )
  }

  /**
   * Returns appropriate icon component for edge type
   * Maps edge type to colored icon: physical=gray, layer3=blue, ospf=green, bgp=purple
   */
  const getEdgeTypeIcon = () => {
    switch (edgeData.type) {
      case 'physical':
        return <Link2 className="w-5 h-5 text-gray-600" aria-hidden="true" />
      case 'layer3':
        return <Database className="w-5 h-5 text-blue-600" aria-hidden="true" />
      case 'ospf':
        return <Activity className="w-5 h-5 text-green-600" aria-hidden="true" />
      case 'bgp':
        return <Zap className="w-5 h-5 text-purple-600" aria-hidden="true" />
      default:
        return <Link2 className="w-5 h-5 text-gray-600" aria-hidden="true" />
    }
  }

  /**
   * Returns styled badge component displaying edge type
   * Color-coded badges with uppercase text: Physical, Layer3, OSPF, BGP
   */
  const getEdgeTypeBadge = () => {
    const colors: Record<string, string> = {
      physical: 'bg-gray-100 text-gray-800',
      layer3: 'bg-blue-100 text-blue-800',
      ospf: 'bg-green-100 text-green-800',
      bgp: 'bg-purple-100 text-purple-800',
    }
    return (
      <span className={`px-2 py-1 rounded-full text-xs font-medium ${colors[edgeData.type]}`}>
        {edgeData.type.toUpperCase()}
      </span>
    )
  }

  return (
    <div className="space-y-4" role="region" aria-label="Edge details">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
          {getEdgeTypeIcon()}
          {t('edgeDetails.title')}
        </h2>
        {getEdgeTypeBadge()}
      </div>

      <div className="bg-white border border-gray-200 rounded-lg p-4 space-y-3">
        <h3 className="text-sm font-semibold text-gray-900 mb-2">{t('edgeDetails.sections.connection')}</h3>

        <div className="space-y-2">
          <div>
            <span className="text-xs font-medium text-gray-500">{t('edgeDetails.fields.sourceNode')}</span>
            <p className="text-sm text-gray-900 font-mono">{edgeData.sourceNode || t('common.unknown')}</p>
          </div>

          <div>
            <span className="text-xs font-medium text-gray-500">{t('edgeDetails.fields.targetNode')}</span>
            <p className="text-sm text-gray-900 font-mono">{edgeData.targetNode || t('common.unknown')}</p>
          </div>
        </div>
      </div>

      {edgeData.data && (
        <div className="bg-white border border-gray-200 rounded-lg p-4 space-y-3">
          <h3 className="text-sm font-semibold text-gray-900 mb-2">{t('common.interfaces')}</h3>

          <div className="space-y-3">
            <div className="bg-gray-50 rounded p-3">
              <span className="text-xs font-medium text-gray-500 block mb-1">{t('edgeDetails.fields.sourceInterface')}</span>
              <p className="text-sm text-gray-900 font-mono break-all">
                {'interface' in edgeData.data ? edgeData.data.interface : t('common.notAvailable')}
              </p>
            </div>

            <div className="bg-gray-50 rounded p-3">
              <span className="text-xs font-medium text-gray-500 block mb-1">{t('edgeDetails.fields.targetInterface')}</span>
              <p className="text-sm text-gray-900 font-mono break-all">
                {'remote_interface' in edgeData.data ? edgeData.data.remote_interface : t('common.notAvailable')}
              </p>
            </div>
          </div>
        </div>
      )}

      {edgeData.type === 'layer3' && edgeData.data && 'ips' in edgeData.data && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 space-y-3">
          <h3 className="text-sm font-semibold text-blue-900 mb-2">{t('edgeDetails.sections.layer3Info')}</h3>

          <div className="space-y-3">
            <div>
              <span className="text-xs font-medium text-blue-700 block mb-1">{t('edgeDetails.fields.sourceIps')}</span>
              <div className="space-y-1">
                {edgeData.data.ips.length > 0 ? (
                  edgeData.data.ips.map((ip, idx) => (
                    <p key={idx} className="text-sm text-blue-900 font-mono">
                      {ip}
                    </p>
                  ))
                ) : (
                  <p className="text-sm text-blue-700 italic">{t('edgeDetails.noIps')}</p>
                )}
              </div>
            </div>

            <div>
              <span className="text-xs font-medium text-blue-700 block mb-1">{t('edgeDetails.fields.targetIps')}</span>
              <div className="space-y-1">
                {edgeData.data.remote_ips.length > 0 ? (
                  edgeData.data.remote_ips.map((ip, idx) => (
                    <p key={idx} className="text-sm text-blue-900 font-mono">
                      {ip}
                    </p>
                  ))
                ) : (
                  <p className="text-sm text-blue-700 italic">{t('edgeDetails.noIps')}</p>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {edgeData.type === 'ospf' && edgeData.data && 'ip' in edgeData.data && (
        <div className="bg-green-50 border border-green-200 rounded-lg p-4 space-y-3">
          <h3 className="text-sm font-semibold text-green-900 mb-2">{t('edgeDetails.sections.ospfInfo')}</h3>

          <div className="space-y-2">
            <div>
              <span className="text-xs font-medium text-green-700 block mb-1">{t('edgeDetails.fields.sourceIp')}</span>
              <p className="text-sm text-green-900 font-mono">{edgeData.data.ip}</p>
            </div>

            <div>
              <span className="text-xs font-medium text-green-700 block mb-1">{t('edgeDetails.fields.targetIp')}</span>
              <p className="text-sm text-green-900 font-mono">{edgeData.data.remote_ip}</p>
            </div>
          </div>
        </div>
      )}

      {edgeData.type === 'bgp' && edgeData.data && 'local_asn' in edgeData.data && (
        <div className="bg-purple-50 border border-purple-200 rounded-lg p-4 space-y-3">
          <h3 className="text-sm font-semibold text-purple-900 mb-2">{t('edgeDetails.sections.bgpInfo')}</h3>

          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <span className="text-xs font-medium text-purple-700 block mb-1">{t('edgeDetails.fields.localAsn')}</span>
                <p className="text-sm text-purple-900 font-mono">{edgeData.data.local_asn || t('common.notAvailable')}</p>
              </div>
              <div>
                <span className="text-xs font-medium text-purple-700 block mb-1">{t('edgeDetails.fields.remoteAsn')}</span>
                <p className="text-sm text-purple-900 font-mono">{edgeData.data.remote_asn || t('common.notAvailable')}</p>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <span className="text-xs font-medium text-purple-700 block mb-1">{t('edgeDetails.fields.localIp')}</span>
                <p className="text-sm text-purple-900 font-mono">{edgeData.data.local_ip || t('common.notAvailable')}</p>
              </div>
              <div>
                <span className="text-xs font-medium text-purple-700 block mb-1">{t('edgeDetails.fields.remoteIp')}</span>
                <p className="text-sm text-purple-900 font-mono">{edgeData.data.remote_ip || t('common.notAvailable')}</p>
              </div>
            </div>

            {edgeData.data.import_policy && edgeData.data.import_policy.length > 0 && (
              <div>
                <span className="text-xs font-medium text-purple-700 block mb-1">{t('edgeDetails.fields.importPolicy')}</span>
                <div className="space-y-1">
                  {edgeData.data.import_policy.map((policy, idx) => (
                    <p key={idx} className="text-sm text-purple-900 font-mono bg-purple-100 px-2 py-1 rounded">
                      {policy}
                    </p>
                  ))}
                </div>
              </div>
            )}

            {edgeData.data.export_policy && edgeData.data.export_policy.length > 0 && (
              <div>
                <span className="text-xs font-medium text-purple-700 block mb-1">{t('edgeDetails.fields.exportPolicy')}</span>
                <div className="space-y-1">
                  {edgeData.data.export_policy.map((policy, idx) => (
                    <p key={idx} className="text-sm text-purple-900 font-mono bg-purple-100 px-2 py-1 rounded">
                      {policy}
                    </p>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      <div className="bg-gray-50 rounded-lg p-3 mt-4">
        <span className="text-xs font-medium text-gray-500 block mb-1">{t('edgeDetails.fields.edgeId')}</span>
        <p className="text-xs text-gray-700 font-mono break-all">{selectedEdgeId}</p>
      </div>
    </div>
  )
}

export default EdgeDetailsPanel