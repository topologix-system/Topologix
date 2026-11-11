/**
 * Edge details panel displaying properties of selected network connections
 * - Supports all topology edge types: physical, layer1, layer3, OSPF, BGP, VXLAN, EIGRP, IS-IS, IPsec
 * - Finds the source edge record by rebuilding the Cytoscape stable edge ID of every candidate edge
 * - Works from the edge ID alone (pop-out window ?edge=<id>)
 * - Shows endpoint nodes, interfaces, IP addresses and protocol-specific details
 */
import { useMemo, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Link2, Activity, Database, Zap, Cloud, Share2, Circle, Lock } from 'lucide-react'
import { useUIStore } from '../../store'
import { useAllNetworkData } from '../../hooks'
import type { AllNetworkData } from '../../types/api'
import {
  findEdgeByStableId,
  resolveStableEdgeEndpoints,
  type StableEdgeMatch,
  type StableEdgeType,
} from '../../lib/cytoscape/utils'

export interface EdgeDetails {
  type: StableEdgeType
  match: StableEdgeMatch | null
  sourceNode: string | null
  targetNode: string | null
}

/**
 * Resolve the selected Cytoscape edge ID to its edge record and endpoint nodes
 * Falls back to the type and endpoints encoded in the ID when no record matches
 * @param edgeId - Cytoscape edge ID ("edge-<type>-<source>-<target>[-<ports>]")
 * @param data - Aggregated network data the topology graph was built from
 * @returns Edge details, or null when the ID does not carry a known edge type
 */
export function resolveEdgeDetails(edgeId: string, data: Partial<AllNetworkData>): EdgeDetails | null {
  const match = findEdgeByStableId(edgeId, {
    physical: data.edges,
    layer1: data.layer1_edges,
    layer3: data.layer3_edges,
    ospf: data.ospf_edges,
    bgp: data.bgp_edges,
    vxlan: data.vxlan_edges,
    eigrp: data.eigrp_edges,
    isis: data.isis_edges,
    ipsec: data.ipsec_edges,
  })
  if (match) {
    return { type: match.type, match, sourceNode: match.source, targetNode: match.target }
  }

  const nodeNames = (data.node_properties ?? []).map((node) => node.node)
  const resolved = resolveStableEdgeEndpoints(edgeId, nodeNames)
  if (!resolved) return null
  return { type: resolved.type, match: null, sourceNode: resolved.source, targetNode: resolved.target }
}

/**
 * Local and remote interface strings of a matched edge, or null for edge types without interfaces
 */
function getEdgeInterfaces(match: StableEdgeMatch): { source: string | null; target: string | null } | null {
  switch (match.type) {
    case 'vxlan':
      return null
    case 'ipsec':
      return { source: match.edge.local_interface || null, target: match.edge.remote_interface || null }
    case 'bgp':
      return { source: match.edge.interface || null, target: match.edge.remote_interface || null }
    default:
      return { source: match.edge.interface || null, target: match.edge.remote_interface || null }
  }
}

const EDGE_TYPE_ICONS: Record<StableEdgeType, ReactNode> = {
  physical: <Link2 className="w-5 h-5 text-gray-600" aria-hidden="true" />,
  layer1: <Link2 className="w-5 h-5 text-slate-600" aria-hidden="true" />,
  layer3: <Database className="w-5 h-5 text-blue-600" aria-hidden="true" />,
  ospf: <Activity className="w-5 h-5 text-green-600" aria-hidden="true" />,
  bgp: <Zap className="w-5 h-5 text-purple-600" aria-hidden="true" />,
  vxlan: <Cloud className="w-5 h-5 text-cyan-600" aria-hidden="true" />,
  eigrp: <Share2 className="w-5 h-5 text-orange-600" aria-hidden="true" />,
  isis: <Circle className="w-5 h-5 text-teal-600" aria-hidden="true" />,
  ipsec: <Lock className="w-5 h-5 text-red-600" aria-hidden="true" />,
}

const EDGE_TYPE_BADGE_COLORS: Record<StableEdgeType, string> = {
  physical: 'bg-gray-100 text-gray-800',
  layer1: 'bg-slate-100 text-slate-800',
  layer3: 'bg-blue-100 text-blue-800',
  ospf: 'bg-green-100 text-green-800',
  bgp: 'bg-purple-100 text-purple-800',
  vxlan: 'bg-cyan-100 text-cyan-800',
  eigrp: 'bg-orange-100 text-orange-800',
  isis: 'bg-teal-100 text-teal-800',
  ipsec: 'bg-red-100 text-red-800',
}

function DetailField({ label, value, labelClassName, valueClassName }: {
  label: string
  value: ReactNode
  labelClassName: string
  valueClassName: string
}) {
  return (
    <div>
      <span className={`text-xs font-medium block mb-1 ${labelClassName}`}>{label}</span>
      <p className={`text-sm font-mono break-all ${valueClassName}`}>{value}</p>
    </div>
  )
}

export function EdgeDetailsPanel() {
  const { t } = useTranslation()
  const selectedEdgeId = useUIStore((state) => state.selectedEdgeId)
  const { data: networkData, isLoading } = useAllNetworkData()

  const edgeDetails = useMemo<EdgeDetails | null>(() => {
    if (!selectedEdgeId || !networkData) return null
    return resolveEdgeDetails(selectedEdgeId, networkData)
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
      <div className="space-y-4" role="region" aria-label={t('edgeDetails.regionLabel')} aria-busy="true">
        <h2 className="text-lg font-semibold text-gray-900">{t('edgeDetails.title')}</h2>
        <div className="flex items-center justify-center py-8">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600" aria-hidden="true"></div>
          <span className="sr-only">{t('edgeDetails.loading')}</span>
        </div>
      </div>
    )
  }

  if (!edgeDetails) {
    return (
      <div className="space-y-4" role="region" aria-label={t('edgeDetails.regionLabel')}>
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

  const { type, match } = edgeDetails
  const interfaces = match ? getEdgeInterfaces(match) : null
  const notAvailable = t('common.notAvailable')

  return (
    <div className="space-y-4" role="region" aria-label={t('edgeDetails.regionLabel')}>
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
          {EDGE_TYPE_ICONS[type]}
          {t('edgeDetails.title')}
        </h2>
        <span className={`px-2 py-1 rounded-full text-xs font-medium ${EDGE_TYPE_BADGE_COLORS[type]}`}>
          {type.toUpperCase()}
        </span>
      </div>

      <div className="bg-white border border-gray-200 rounded-lg p-4 space-y-3">
        <h3 className="text-sm font-semibold text-gray-900 mb-2">{t('edgeDetails.sections.connection')}</h3>

        <div className="space-y-2">
          <div>
            <span className="text-xs font-medium text-gray-500">{t('edgeDetails.fields.sourceNode')}</span>
            <p className="text-sm text-gray-900 font-mono">{edgeDetails.sourceNode || t('common.unknown')}</p>
          </div>

          <div>
            <span className="text-xs font-medium text-gray-500">{t('edgeDetails.fields.targetNode')}</span>
            <p className="text-sm text-gray-900 font-mono">{edgeDetails.targetNode || t('common.unknown')}</p>
          </div>
        </div>
      </div>

      {!match && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4" role="status">
          <p className="text-sm text-yellow-800">{t('edgeDetails.notFound')}</p>
        </div>
      )}

      {interfaces && (
        <div className="bg-white border border-gray-200 rounded-lg p-4 space-y-3">
          <h3 className="text-sm font-semibold text-gray-900 mb-2">{t('common.interfaces')}</h3>

          <div className="space-y-3">
            <div className="bg-gray-50 rounded p-3">
              <span className="text-xs font-medium text-gray-500 block mb-1">{t('edgeDetails.fields.sourceInterface')}</span>
              <p className="text-sm text-gray-900 font-mono break-all">{interfaces.source || notAvailable}</p>
            </div>

            <div className="bg-gray-50 rounded p-3">
              <span className="text-xs font-medium text-gray-500 block mb-1">{t('edgeDetails.fields.targetInterface')}</span>
              <p className="text-sm text-gray-900 font-mono break-all">{interfaces.target || notAvailable}</p>
            </div>
          </div>
        </div>
      )}

      {match?.type === 'layer3' && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 space-y-3">
          <h3 className="text-sm font-semibold text-blue-900 mb-2">{t('edgeDetails.sections.layer3Info')}</h3>

          <div className="space-y-3">
            <div>
              <span className="text-xs font-medium text-blue-700 block mb-1">{t('edgeDetails.fields.sourceIps')}</span>
              <div className="space-y-1">
                {match.edge.ips?.length > 0 ? (
                  match.edge.ips.map((ip, idx) => (
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
                {match.edge.remote_ips?.length > 0 ? (
                  match.edge.remote_ips.map((ip, idx) => (
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

      {match?.type === 'ospf' && (
        <div className="bg-green-50 border border-green-200 rounded-lg p-4 space-y-3">
          <h3 className="text-sm font-semibold text-green-900 mb-2">{t('edgeDetails.sections.ospfInfo')}</h3>

          <div className="space-y-2">
            <DetailField label={t('edgeDetails.fields.sourceIp')} value={match.edge.ip || notAvailable} labelClassName="text-green-700" valueClassName="text-green-900" />
            <DetailField label={t('edgeDetails.fields.targetIp')} value={match.edge.remote_ip || notAvailable} labelClassName="text-green-700" valueClassName="text-green-900" />
          </div>
        </div>
      )}

      {match?.type === 'eigrp' && (
        <div className="bg-orange-50 border border-orange-200 rounded-lg p-4 space-y-3">
          <h3 className="text-sm font-semibold text-orange-900 mb-2">{t('edgeDetails.sections.eigrpInfo')}</h3>

          <div className="space-y-2">
            <DetailField label={t('edgeDetails.fields.sourceIp')} value={match.edge.ip || notAvailable} labelClassName="text-orange-700" valueClassName="text-orange-900" />
            <DetailField label={t('edgeDetails.fields.targetIp')} value={match.edge.remote_ip || notAvailable} labelClassName="text-orange-700" valueClassName="text-orange-900" />
          </div>
        </div>
      )}

      {match?.type === 'isis' && (
        <div className="bg-teal-50 border border-teal-200 rounded-lg p-4 space-y-3">
          <h3 className="text-sm font-semibold text-teal-900 mb-2">{t('edgeDetails.sections.isisInfo')}</h3>

          <DetailField label={t('edgeDetails.fields.level')} value={match.edge.level || notAvailable} labelClassName="text-teal-700" valueClassName="text-teal-900" />
        </div>
      )}

      {match?.type === 'vxlan' && (
        <div className="bg-cyan-50 border border-cyan-200 rounded-lg p-4 space-y-3">
          <h3 className="text-sm font-semibold text-cyan-900 mb-2">{t('edgeDetails.sections.vxlanInfo')}</h3>

          <div className="space-y-2">
            <DetailField label={t('edgeDetails.fields.vni')} value={match.edge.vni ?? notAvailable} labelClassName="text-cyan-700" valueClassName="text-cyan-900" />
            <DetailField label={t('edgeDetails.fields.vtepAddress')} value={match.edge.vtep_address || notAvailable} labelClassName="text-cyan-700" valueClassName="text-cyan-900" />
            <DetailField label={t('edgeDetails.fields.remoteVtepAddress')} value={match.edge.remote_vtep_address || notAvailable} labelClassName="text-cyan-700" valueClassName="text-cyan-900" />
            <DetailField label={t('edgeDetails.fields.multicastGroup')} value={match.edge.multicast_group || notAvailable} labelClassName="text-cyan-700" valueClassName="text-cyan-900" />
          </div>
        </div>
      )}

      {match?.type === 'ipsec' && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 space-y-3">
          <h3 className="text-sm font-semibold text-red-900 mb-2">{t('edgeDetails.sections.ipsecInfo')}</h3>

          <DetailField
            label={t('edgeDetails.fields.tunnelInterfaces')}
            value={match.edge.tunnel_interfaces?.length ? match.edge.tunnel_interfaces.join(', ') : notAvailable}
            labelClassName="text-red-700"
            valueClassName="text-red-900"
          />
        </div>
      )}

      {match?.type === 'bgp' && (
        <div className="bg-purple-50 border border-purple-200 rounded-lg p-4 space-y-3">
          <h3 className="text-sm font-semibold text-purple-900 mb-2">{t('edgeDetails.sections.bgpInfo')}</h3>

          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <DetailField label={t('edgeDetails.fields.localAsn')} value={match.edge.local_asn || notAvailable} labelClassName="text-purple-700" valueClassName="text-purple-900" />
              <DetailField label={t('edgeDetails.fields.remoteAsn')} value={match.edge.remote_asn || notAvailable} labelClassName="text-purple-700" valueClassName="text-purple-900" />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <DetailField label={t('edgeDetails.fields.localIp')} value={match.edge.local_ip || notAvailable} labelClassName="text-purple-700" valueClassName="text-purple-900" />
              <DetailField label={t('edgeDetails.fields.remoteIp')} value={match.edge.remote_ip || notAvailable} labelClassName="text-purple-700" valueClassName="text-purple-900" />
            </div>

            {match.edge.import_policy && match.edge.import_policy.length > 0 && (
              <div>
                <span className="text-xs font-medium text-purple-700 block mb-1">{t('edgeDetails.fields.importPolicy')}</span>
                <div className="space-y-1">
                  {match.edge.import_policy.map((policy, idx) => (
                    <p key={idx} className="text-sm text-purple-900 font-mono bg-purple-100 px-2 py-1 rounded">
                      {policy}
                    </p>
                  ))}
                </div>
              </div>
            )}

            {match.edge.export_policy && match.edge.export_policy.length > 0 && (
              <div>
                <span className="text-xs font-medium text-purple-700 block mb-1">{t('edgeDetails.fields.exportPolicy')}</span>
                <div className="space-y-1">
                  {match.edge.export_policy.map((policy, idx) => (
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
