/**
 * Comprehensive node details panel with 14 tabs
 * - Displays all Batfish node properties: interfaces, routes, VLANs, ACLs, AAA, OSPF, BGP, HSRP, VRRP, and more
 * - Implements React Rules of Hooks compliance: all hooks before conditional returns (see lines 38, 43, 205)
 * - Uses useMemo extensively for filtering/searching large datasets (routes can exceed 10K entries)
 * - Largest component in codebase (1830 lines) - handles complex nested data structures from network devices
 * - Interactive search and filtering within each tab for efficient navigation
 */
import { useState, memo, useMemo, useCallback, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { useVirtualizer } from '@tanstack/react-virtual'
import { useUIStore } from '../../store'
import { useAllNetworkData } from '../../hooks'
import type {
  NodeProperties,
  InterfaceProperties,
  Route,
} from '../../types/network'
import type {
  OSPFProcessConfig,
  OSPFAreaConfig,
  OSPFInterfaceConfig,
  OSPFSessionCompat,
} from '../../types/ospf'
import type {
  BGPPeerConfiguration,
  BGPProcessConfiguration,
  BGPSessionStatus,
  BGPSessionCompatibility,
  BGPRib,
} from '../../types/bgp'
import type { SwitchedVlanProperties } from '../../types/vlan'
import type { IPOwner } from '../../types/ip'
import type { DefinedStructure, ReferencedStructure, NamedStructure } from '../../types/structures'
import type { FileParseStatus, InitIssue, ParseWarning } from '../../types/validation'
import type { FilterLineReachability, FilterApplication, AddressOwnership, EnrichedFilterEntry, FilterGroup } from '../../types/reachability'
import type { AAAAuthenticationLogin } from '../../types/policy'
import type { BGPEdge, EIGRPEdge, ISISEdge, VXLANEdge } from '../../types/edges'
import type { AllNetworkData } from '../../types/api'
import {
  Server,
  Network,
  Shield,
  Activity,
  Router,
  AlertCircle,
  Globe,
  Cpu,
  Database,
  Lock,
  GitBranch,
  Filter,
  Layers,
  FileText,
  Share2,
  Circle,
  Cloud,
  ChevronDown,
  ChevronRight,
  Search
} from 'lucide-react'

type TabType = 'basic' | 'interfaces' | 'routing' | 'ospf' | 'services' | 'security' | 'validation' | 'bgp' | 'acl' | 'vlan' | 'config' | 'eigrp' | 'isis' | 'vxlan'

// Extended interface type with hostname from backend response
type InterfaceWithHostname = InterfaceProperties & { hostname?: string }

// HSRP group type for interface details
interface HSRPGroup {
  group: number
  ip?: string
  priority?: number
  preempt?: boolean
  track_interface?: string
  track_decrement?: number
}

export const NodeDetailsPanel = memo(function NodeDetailsPanel() {
  const { t } = useTranslation()
  const selectedNodeId = useUIStore((state) => state.selectedNodeId)
  const { data } = useAllNetworkData()
  const [activeTab, setActiveTab] = useState<TabType>('basic')

  // Memoize tab change handler
  const handleTabChange = useCallback((tabId: TabType) => {
    setActiveTab(tabId)
  }, [])

  // Compute node (not a hook - always execute)
  const node = selectedNodeId
    ? data?.node_properties?.find((n) => n.node === selectedNodeId)
    : undefined

  // Memoize expensive filtering operations - ALL hooks BEFORE any returns
  const nodeInterfaces = useMemo(() => {
    if (!selectedNodeId || !data?.interface_properties) return []
    return data.interface_properties.filter((iface) => {
      // Filter by hostname field directly (backend returns {hostname: "r1", interface: "GigabitEthernet0/0"})
      return iface.hostname === selectedNodeId
    })
  }, [data?.interface_properties, selectedNodeId])

  const nodeRoutes = useMemo(() => {
    if (!selectedNodeId || !data?.routes) return []
    return data.routes.filter((route) => route.node === selectedNodeId)
  }, [data?.routes, selectedNodeId])

  const nodeOspfProcess = useMemo(() => {
    if (!selectedNodeId || !data?.ospf_process_configuration) return undefined
    return data.ospf_process_configuration.find(
      (p) => p.node === selectedNodeId
    )
  }, [data?.ospf_process_configuration, selectedNodeId])

  const nodeOspfAreas = useMemo(() => {
    if (!selectedNodeId || !data?.ospf_area_configuration) return []
    return data.ospf_area_configuration.filter(
      (a) => a.node === selectedNodeId
    )
  }, [data?.ospf_area_configuration, selectedNodeId])

  const nodeOspfInterfaces = useMemo(() => {
    if (!selectedNodeId || !data?.ospf_interface_configuration) return []
    return data.ospf_interface_configuration.filter(
      (i) => i.node === selectedNodeId
    )
  }, [data?.ospf_interface_configuration, selectedNodeId])

  const nodeOspfSessions = useMemo(() => {
    if (!selectedNodeId || !data?.ospf_session_compatibility) return []
    return data.ospf_session_compatibility.filter(
      (s) => s.node === selectedNodeId
    )
  }, [data?.ospf_session_compatibility, selectedNodeId])

  const nodeAaaAuth = useMemo(() => {
    if (!selectedNodeId || !data?.aaa_authentication_login) return []
    return data.aaa_authentication_login.filter(
      (a) => a.node === selectedNodeId
    )
  }, [data?.aaa_authentication_login, selectedNodeId])

  const nodeVlans = useMemo(() => {
    if (!selectedNodeId || !data?.switched_vlan_properties) return []
    return data.switched_vlan_properties.filter(
      (v) => v.node === selectedNodeId
    )
  }, [data?.switched_vlan_properties, selectedNodeId])

  const nodeIpOwners = useMemo(() => {
    if (!selectedNodeId || !data?.ip_owners) return []
    return data.ip_owners.filter(
      (ip) => ip.node === selectedNodeId
    )
  }, [data?.ip_owners, selectedNodeId])

  // Memoize BGP data filtering
  const nodeBgpData = useMemo(() => {
    if (!selectedNodeId) {
      return {
        edges: [],
        peerConfig: [],
        processConfig: [],
        sessionStatus: [],
        sessionCompat: [],
        rib: [],
      }
    }
    return {
      edges: data?.bgp_edges?.filter(
        (edge) => edge.node === selectedNodeId
      ) || [],
      peerConfig: data?.bgp_peer_configuration?.filter(
        (peer) => peer.node === selectedNodeId
      ) || [],
      processConfig: data?.bgp_process_configuration?.filter(
        (proc) => proc.node === selectedNodeId
      ) || [],
      sessionStatus: data?.bgp_session_status?.filter(
        (session) => session.node === selectedNodeId
      ) || [],
      sessionCompat: data?.bgp_session_compatibility?.filter(
        (compat) => compat.node === selectedNodeId
      ) || [],
      rib: data?.bgp_rib?.filter(
        (rib) => rib.node === selectedNodeId
      ) || [],
    }
  }, [
    data?.bgp_edges,
    data?.bgp_peer_configuration,
    data?.bgp_process_configuration,
    data?.bgp_session_status,
    data?.bgp_session_compatibility,
    data?.bgp_rib,
    selectedNodeId,
  ])

  // ACL/Filter data
  const allFilterReachability = useMemo(() => {
    return data?.filter_line_reachability || []
  }, [data?.filter_line_reachability])

  // VLAN data for VLAN tab
  const nodeSwitchedVlanProperties = useMemo(() => {
    if (!selectedNodeId || !data?.switched_vlan_properties) return []
    return data.switched_vlan_properties.filter((v) => v.node === selectedNodeId)
  }, [data?.switched_vlan_properties, selectedNodeId])

  // Configuration structures data
  const nodeDefinedStructures = useMemo(() => {
    if (!data?.defined_structures) return []
    return data.defined_structures
  }, [data?.defined_structures])

  const nodeReferencedStructures = useMemo(() => {
    if (!data?.referenced_structures) return []
    return data.referenced_structures
  }, [data?.referenced_structures])

  const nodeNamedStructures = useMemo(() => {
    if (!selectedNodeId || !data?.named_structures) return []
    return data.named_structures.filter((s) => s.node === selectedNodeId)
  }, [data?.named_structures, selectedNodeId])

  // EIGRP data
  const nodeEigrpEdges = useMemo(() => {
    if (!selectedNodeId || !data?.eigrp_edges) return []
    return data.eigrp_edges.filter(
      (edge) => edge.interface?.startsWith(`${selectedNodeId}[`)
    )
  }, [data?.eigrp_edges, selectedNodeId])

  // IS-IS data
  const nodeIsisEdges = useMemo(() => {
    if (!selectedNodeId || !data?.isis_edges) return []
    return data.isis_edges.filter(
      (edge) => edge.interface?.startsWith(`${selectedNodeId}[`)
    )
  }, [data?.isis_edges, selectedNodeId])

  // VXLAN data
  const nodeVxlanEdges = useMemo(() => {
    if (!selectedNodeId || !data?.vxlan_edges) return []
    return data.vxlan_edges.filter((edge) => edge.node === selectedNodeId)
  }, [data?.vxlan_edges, selectedNodeId])

  // Conditional rendering AFTER all hooks (Rules of Hooks compliance)
  if (!selectedNodeId) {
    return (
      <div className="text-center text-gray-700 py-8" role="status">
        <p>{t('nodeDetails.selectNode')}</p>
      </div>
    )
  }

  if (!node) {
    return (
      <div className="text-center text-gray-700 py-8" role="alert">
        <p>{t('nodeDetails.nodeNotFound')}</p>
      </div>
    )
  }

  // Tab configuration
  const tabs = [
    { id: 'basic', label: t('nodeDetails.tabs.basic'), icon: <Cpu className="w-4 h-4" /> },
    { id: 'interfaces', label: t('common.interfaces'), icon: <Network className="w-4 h-4" /> },
    { id: 'routing', label: t('nodeDetails.tabs.routing'), icon: <Router className="w-4 h-4" /> },
    { id: 'ospf', label: t('nodeDetails.tabs.ospf'), icon: <Activity className="w-4 h-4" /> },
    { id: 'services', label: t('nodeDetails.tabs.services'), icon: <Server className="w-4 h-4" /> },
    { id: 'security', label: t('nodeDetails.tabs.security'), icon: <Shield className="w-4 h-4" /> },
    { id: 'validation', label: t('validation.title'), icon: <AlertCircle className="w-4 h-4" /> },
    { id: 'bgp', label: t('nodeDetails.tabs.bgp'), icon: <GitBranch className="w-4 h-4" /> },
    { id: 'acl', label: t('nodeDetails.tabs.acl'), icon: <Filter className="w-4 h-4" /> },
    { id: 'vlan', label: t('nodeDetails.tabs.vlan'), icon: <Layers className="w-4 h-4" /> },
    { id: 'config', label: t('nodeDetails.tabs.configuration'), icon: <FileText className="w-4 h-4" /> },
    { id: 'eigrp', label: t('nodeDetails.tabs.eigrp'), icon: <Share2 className="w-4 h-4" /> },
    { id: 'isis', label: t('nodeDetails.tabs.isis'), icon: <Circle className="w-4 h-4" /> },
    { id: 'vxlan', label: t('nodeDetails.tabs.vxlan'), icon: <Cloud className="w-4 h-4" /> },
  ]

  return (
    <div className="flex flex-col h-full" role="region" aria-label="Node details">
      {/* Header */}
      <div className="border-b pb-4 mb-4">
        <h2 className="text-lg font-semibold text-gray-900">{node.hostname || node.node}</h2>
        <p className="text-sm text-gray-700">{node.node}</p>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-4 flex-wrap" role="tablist" aria-label="Node information tabs">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => handleTabChange(tab.id as TabType)}
            role="tab"
            aria-selected={activeTab === tab.id}
            aria-controls={`node-tabpanel-${tab.id}`}
            id={`node-tab-${tab.id}`}
            tabIndex={activeTab === tab.id ? 0 : -1}
            className={`flex items-center gap-1 px-3 py-1.5 text-xs font-medium rounded-lg transition-colors focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-1 ${
              activeTab === tab.id
                ? 'bg-blue-100 text-blue-800'
                : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
            }`}
          >
            <span aria-hidden="true">{tab.icon}</span>
            <span>{tab.label}</span>
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div
        className="flex-1 overflow-y-auto"
        role="tabpanel"
        id={`node-tabpanel-${activeTab}`}
        aria-labelledby={`node-tab-${activeTab}`}
        tabIndex={0}
      >
        {activeTab === 'basic' && <BasicTab node={node} />}
        {activeTab === 'interfaces' && <InterfacesTab node={node} interfaces={nodeInterfaces} />}
        {activeTab === 'routing' && <RoutingTab routes={nodeRoutes} />}
        {activeTab === 'ospf' && (
          <OspfTab
            process={nodeOspfProcess}
            areas={nodeOspfAreas}
            interfaces={nodeOspfInterfaces}
            sessions={nodeOspfSessions}
          />
        )}
        {activeTab === 'services' && <ServicesTab node={node} aaa={nodeAaaAuth} />}
        {activeTab === 'security' && <SecurityTab node={node} ipOwners={nodeIpOwners} />}
        {activeTab === 'validation' && <ValidationTab node={node} data={data} />}
        {activeTab === 'bgp' && (
          <BgpTab
            node={node}
            edges={nodeBgpData.edges}
            peerConfig={nodeBgpData.peerConfig}
            processConfig={nodeBgpData.processConfig}
            sessionStatus={nodeBgpData.sessionStatus}
            sessionCompat={nodeBgpData.sessionCompat}
            rib={nodeBgpData.rib}
          />
        )}
        {activeTab === 'acl' && (
          <AclTab
            node={node}
            filterReachability={allFilterReachability}
            allInterfaces={data?.interface_properties || []}
            allIpOwners={data?.ip_owners || []}
          />
        )}
        {activeTab === 'vlan' && (
          <VlanTab
            node={node}
            vlans={nodeSwitchedVlanProperties}
          />
        )}
        {activeTab === 'config' && (
          <ConfigurationTab
            node={node}
            definedStructures={nodeDefinedStructures}
            referencedStructures={nodeReferencedStructures}
            namedStructures={nodeNamedStructures}
          />
        )}
        {activeTab === 'eigrp' && (
          <EigrpTab
            node={node}
            edges={nodeEigrpEdges}
          />
        )}
        {activeTab === 'isis' && (
          <IsisTab
            node={node}
            edges={nodeIsisEdges}
          />
        )}
        {activeTab === 'vxlan' && (
          <VxlanTab
            node={node}
            edges={nodeVxlanEdges}
          />
        )}
      </div>
    </div>
  )
})

// Basic Information Tab
function BasicTab({ node }: { node: NodeProperties }) {
  const { t } = useTranslation()
  return (
    <div className="space-y-4">
      <div className="bg-gray-50 rounded-lg p-4">
        <h3 className="font-medium text-gray-900 mb-3">{t('nodeDetails.sections.nodeInfo')}</h3>
        <div className="grid grid-cols-2 gap-2 text-sm">
          <div>
            <span className="text-gray-700">{t('nodeDetails.fields.hostname')}:</span>
            <p className="font-medium">{node.hostname || t('common.notAvailable')}</p>
          </div>
          <div>
            <span className="text-gray-700">{t('nodeDetails.fields.nodeId')}:</span>
            <p className="font-medium">{node.node}</p>
          </div>
          <div>
            <span className="text-gray-700">{t('nodeDetails.fields.vendor')}:</span>
            <p className="font-medium">{node.vendor || t('common.notAvailable')}</p>
          </div>
          <div>
            <span className="text-gray-700">{t('nodeDetails.fields.format')}:</span>
            <p className="font-medium">{node.configuration_format || t('common.notAvailable')}</p>
          </div>
          <div>
            <span className="text-gray-700">{t('nodeDetails.fields.domain')}:</span>
            <p className="font-medium">{node.domain_name || t('common.notAvailable')}</p>
          </div>
          <div>
            <span className="text-gray-700">{t('nodeDetails.fields.interfaces')}:</span>
            <p className="font-medium">{node.interfaces.length}</p>
          </div>
        </div>
      </div>

      {/* VRFs */}
      {node.vrfs && node.vrfs.length > 0 && (
        <div className="bg-gray-50 rounded-lg p-4">
          <h3 className="font-medium text-gray-900 mb-2">{t('nodeDetails.sections.vrfs')} ({node.vrfs.length})</h3>
          <div className="space-y-1">
            {node.vrfs.map((vrf: string, index: number) => (
              <div key={index} className="text-sm text-gray-700 px-2 py-1 bg-white rounded">
                {vrf}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Zones */}
      {node.zones && node.zones.length > 0 && (
        <div className="bg-gray-50 rounded-lg p-4">
          <h3 className="font-medium text-gray-900 mb-2">{t('nodeDetails.sections.securityZones')} ({node.zones.length})</h3>
          <div className="space-y-1">
            {node.zones.map((zone: string, index: number) => (
              <div key={index} className="text-sm text-gray-700 px-2 py-1 bg-white rounded">
                {zone}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* IPsec VPNs */}
      {node.ipsec_vpns && node.ipsec_vpns.length > 0 && (
        <div className="bg-gray-50 rounded-lg p-4">
          <h3 className="font-medium text-gray-900 mb-2">{t('nodeDetails.sections.ipsecVpns')} ({node.ipsec_vpns.length})</h3>
          <div className="space-y-1">
            {node.ipsec_vpns.map((vpn: string, index: number) => (
              <div key={index} className="text-sm text-gray-700 px-2 py-1 bg-white rounded">
                {vpn}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// Interfaces Tab
function InterfacesTab({ node, interfaces }: { node: NodeProperties; interfaces: InterfaceWithHostname[] }) {
  const { t } = useTranslation()
  const [expandedInterface, setExpandedInterface] = useState<string | null>(null)

  return (
    <div className="space-y-4">
      <div className="bg-gray-50 rounded-lg p-4">
        <h3 className="font-medium text-gray-900 mb-3">
          {t('nodeDetails.sections.interfaceDetails')} ({t('nodeDetails.interfaceCount', { count: interfaces.length })})
        </h3>

        {interfaces.length === 0 ? (
          <p className="text-sm text-gray-700">{t('nodeDetails.noInterfaceInfo')}</p>
        ) : (
          <div className="space-y-2">
            {interfaces.map((iface) => {
              const ifaceName = iface.interface  // Already just the interface name (e.g., "GigabitEthernet0/0")
              const isExpanded = expandedInterface === iface.interface

              return (
                <div key={iface.interface} className="bg-white rounded-lg border border-gray-200">
                  <button
                    onClick={() => setExpandedInterface(isExpanded ? null : iface.interface)}
                    className="w-full px-3 py-2 flex items-center justify-between hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-inset rounded-lg"
                    aria-expanded={isExpanded}
                    aria-controls={`interface-details-${iface.interface}`}
                    aria-label={`${ifaceName} interface - ${iface.admin_up ? t('common.status.up') : t('common.status.down')}${iface.primary_address ? ` - ${iface.primary_address}` : ''}`}
                  >
                    <div className="flex items-center gap-3 text-sm">
                      <span className="font-medium text-gray-900">{ifaceName}</span>
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                        iface.admin_up
                          ? 'bg-green-100 text-green-800'
                          : 'bg-red-100 text-red-800'
                      }`} aria-label={`Status: ${iface.admin_up ? t('common.status.up') : t('common.status.down')}`}>
                        {iface.admin_up ? t('common.status.up') : t('common.status.down')}
                      </span>
                      {iface.primary_address && (
                        <span className="text-gray-700">{iface.primary_address}</span>
                      )}
                    </div>
                    <span className="text-gray-500" aria-hidden="true">{isExpanded ? '−' : '+'}</span>
                  </button>

                  {isExpanded && (
                    <div
                      id={`interface-details-${iface.interface}`}
                      className="px-3 py-2 border-t border-gray-200 bg-gray-50 text-xs"
                      role="region"
                      aria-label={`Details for ${ifaceName} interface`}
                    >
                      <div className="grid grid-cols-2 gap-2">
                        {/* Physical Properties */}
                        <div>
                          <p className="font-medium text-gray-900 mb-1">{t('nodeDetails.interface.physical')}</p>
                          <div className="space-y-1 text-gray-700">
                            <div>{t('nodeDetails.fields.type')}: {iface.interface_type || t('common.notAvailable')}</div>
                            <div>{t('nodeDetails.interface.fields.mtu')}: {iface.mtu || t('common.notAvailable')}</div>
                            <div>{t('nodeDetails.interface.fields.speed')}: {iface.speed || t('common.notAvailable')}</div>
                            <div>{t('nodeDetails.interface.fields.bandwidth')}: {iface.bandwidth || t('common.notAvailable')}</div>
                            <div>{t('nodeDetails.fields.description')}: {iface.description || t('common.notAvailable')}</div>
                          </div>
                        </div>

                        {/* Layer 3 Properties */}
                        <div>
                          <p className="font-medium text-gray-900 mb-1">{t('nodeDetails.interface.layer3')}</p>
                          <div className="space-y-1 text-gray-700">
                            <div>{t('nodeDetails.interface.fields.ip')}: {iface.primary_address || t('common.notAvailable')}</div>
                            <div>{t('nodeDetails.interface.fields.network')}: {iface.primary_network || t('common.notAvailable')}</div>
                            <div>{t('nodeDetails.fields.vrf')}: {iface.vrf || t('common.default')}</div>
                            <div>{t('nodeDetails.interface.fields.proxyArp')}: {iface.proxy_arp ? t('common.yes') : t('common.no')}</div>
                          </div>
                        </div>

                        {/* VLAN Properties */}
                        {(iface.switchport || iface.vlan) && (
                          <div>
                            <p className="font-medium text-gray-900 mb-1">{t('nodeDetails.interface.vlan')}</p>
                            <div className="space-y-1 text-gray-700">
                              <div>{t('nodeDetails.interface.fields.switchportMode')}: {iface.switchport_mode || t('common.notAvailable')}</div>
                              <div>{t('nodeDetails.interface.fields.accessVlan')}: {iface.access_vlan || t('common.notAvailable')}</div>
                              <div>{t('nodeDetails.interface.fields.nativeVlan')}: {iface.native_vlan || t('common.notAvailable')}</div>
                              <div>{t('nodeDetails.interface.fields.allowedVlans')}: {iface.allowed_vlans || t('common.notAvailable')}</div>
                            </div>
                          </div>
                        )}

                        {/* OSPF Properties */}
                        {iface.ospf_enabled && (
                          <div>
                            <p className="font-medium text-gray-900 mb-1">{t('nodeDetails.interface.ospf')}</p>
                            <div className="space-y-1 text-gray-700">
                              <div>{t('nodeDetails.interface.fields.ospfArea')}: {iface.ospf_area_name || t('common.notAvailable')}</div>
                              <div>{t('nodeDetails.interface.fields.ospfCost')}: {iface.ospf_cost || t('common.notAvailable')}</div>
                              <div>{t('nodeDetails.interface.fields.ospfNetworkType')}: {iface.ospf_network_type || t('common.notAvailable')}</div>
                              <div>{t('nodeDetails.interface.fields.ospfPassive')}: {iface.ospf_passive ? t('common.yes') : t('common.no')}</div>
                            </div>
                          </div>
                        )}

                        {/* Security */}
                        {(iface.incoming_filter_name || iface.outgoing_filter_name || iface.zone) && (
                          <div>
                            <p className="font-medium text-gray-900 mb-1">{t('nodeDetails.interface.security')}</p>
                            <div className="space-y-1 text-gray-700">
                              <div>{t('nodeDetails.interface.fields.inboundAcl')}: {iface.incoming_filter_name || t('common.notAvailable')}</div>
                              <div>{t('nodeDetails.interface.fields.outboundAcl')}: {iface.outgoing_filter_name || t('common.notAvailable')}</div>
                              <div>{t('nodeDetails.interface.fields.zone')}: {iface.zone || t('common.notAvailable')}</div>
                            </div>
                          </div>
                        )}

                        {/* Additional Properties */}
                        <div>
                          <p className="font-medium text-gray-900 mb-1">{t('nodeDetails.fields.status')}</p>
                          <div className="space-y-1 text-gray-700">
                            <div>{t('nodeDetails.interface.fields.active')}: {iface.active ? t('common.yes') : t('common.no')}</div>
                            <div>{t('nodeDetails.interface.fields.adminStatus')}: {iface.admin_up ? t('common.status.up') : t('common.status.down')}</div>
                            <div>{t('nodeDetails.interface.fields.switchport')}: {iface.switchport ? t('common.yes') : t('common.no')}</div>
                            <div>{t('nodeDetails.interface.fields.channelGroup')}: {iface.channel_group || t('common.notAvailable')}</div>
                          </div>
                        </div>
                      </div>

                      {/* All Prefixes */}
                      {iface.all_prefixes && iface.all_prefixes.length > 0 && (
                        <div className="mt-2">
                          <p className="font-medium text-gray-900 mb-1">{t('nodeDetails.interface.allPrefixes')}</p>
                          <div className="space-y-0.5 text-gray-700">
                            {iface.all_prefixes.map((prefix: string, idx: number) => (
                              <div key={idx}>{prefix}</div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* HSRP Groups */}
                      {iface.hsrp_groups && iface.hsrp_groups.length > 0 && (
                        <div className="mt-2">
                          <p className="font-medium text-gray-900 mb-1">{t('nodeDetails.interface.hsrpGroups')}</p>
                          <div className="space-y-0.5 text-gray-700">
                            {iface.hsrp_groups.map((group: HSRPGroup, idx: number) => (
                              <div key={idx}>{JSON.stringify(group)}</div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* Interface Summary by Name */}
      <div className="bg-gray-50 rounded-lg p-4">
        <h3 className="font-medium text-gray-900 mb-2">
          {t('nodeDetails.sections.interfaceNames')} ({node.interfaces.length})
        </h3>
        <div className="max-h-40 overflow-y-auto space-y-1">
          {node.interfaces.map((iface: string, index: number) => (
            <div key={index} className="text-sm text-gray-700">
              {iface}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// Routing Tab with virtual scrolling for 10K+ routes
function RoutingTab({ routes }: { routes: Route[] }) {
  const { t } = useTranslation()
  const [searchQuery, setSearchQuery] = useState('')
  const parentRef = useRef<HTMLDivElement>(null)

  const filteredRoutes = useMemo(() => {
    if (!searchQuery.trim()) return routes
    const query = searchQuery.toLowerCase()
    return routes.filter((route) =>
      route.network?.toLowerCase().includes(query) ||
      route.next_hop_ip?.toLowerCase().includes(query) ||
      route.next_hop?.toLowerCase().includes(query) ||
      route.next_hop_interface?.toLowerCase().includes(query) ||
      route.protocol?.toLowerCase().includes(query)
    )
  }, [routes, searchQuery])

  const rowVirtualizer = useVirtualizer({
    count: filteredRoutes.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 28,
    overscan: 15,
  })

  return (
    <div className="space-y-4">
      <div className="bg-gray-50 rounded-lg p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="font-medium text-gray-900">
            {t('nodeDetails.sections.routingTable')} ({t('nodeDetails.routeCount', { count: filteredRoutes.length })}
            {searchQuery && ` / ${routes.length}`})
          </h3>
        </div>

        {routes.length > 0 && (
          <div className="mb-3">
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder={t('common.search') + '...'}
              className="w-full px-3 py-1.5 text-sm border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-600 focus:border-transparent"
              aria-label={t('common.search')}
            />
          </div>
        )}

        {filteredRoutes.length === 0 ? (
          <p className="text-sm text-gray-700">
            {routes.length === 0 ? t('nodeDetails.noRoutingInfo') : t('common.noResults')}
          </p>
        ) : (
          <div className="overflow-x-auto">
            <div
              className="grid text-xs font-medium text-gray-700 border-b py-1.5 px-2 bg-gray-100 rounded-t-lg"
              style={{ gridTemplateColumns: 'minmax(120px, 1.5fr) minmax(100px, 1fr) minmax(100px, 1fr) minmax(80px, 0.8fr) minmax(60px, 0.6fr) minmax(60px, 0.6fr)' }}
              role="row"
              aria-label="Table header"
            >
              <div role="columnheader">{t('nodeDetails.fields.prefix')}</div>
              <div role="columnheader">{t('nodeDetails.fields.nextHop')}</div>
              <div role="columnheader">{t('common.interfaces')}</div>
              <div role="columnheader">{t('nodeDetails.fields.protocol')}</div>
              <div role="columnheader">{t('nodeDetails.fields.metric')}</div>
              <div role="columnheader">{t('nodeDetails.fields.adminDistance')}</div>
            </div>

            <div
              ref={parentRef}
              className="h-[400px] overflow-auto"
              role="grid"
              aria-label={t('nodeDetails.sections.routingTable')}
              aria-rowcount={filteredRoutes.length}
            >
              <div
                style={{
                  height: `${rowVirtualizer.getTotalSize()}px`,
                  width: '100%',
                  position: 'relative',
                }}
              >
                {rowVirtualizer.getVirtualItems().map((virtualRow) => {
                  const route = filteredRoutes[virtualRow.index]
                  return (
                    <div
                      key={virtualRow.index}
                      className="grid text-xs border-b border-gray-200 hover:bg-gray-100 py-1.5 px-2 absolute top-0 left-0 w-full items-center"
                      style={{
                        gridTemplateColumns: 'minmax(120px, 1.5fr) minmax(100px, 1fr) minmax(100px, 1fr) minmax(80px, 0.8fr) minmax(60px, 0.6fr) minmax(60px, 0.6fr)',
                        height: `${virtualRow.size}px`,
                        transform: `translateY(${virtualRow.start}px)`,
                      }}
                      role="row"
                      aria-rowindex={virtualRow.index + 1}
                    >
                      <div className="text-gray-900 truncate" title={route.network}>{route.network}</div>
                      <div className="text-gray-700 truncate" title={route.next_hop_ip || route.next_hop || ''}>
                        {route.next_hop_ip || route.next_hop || t('nodeDetails.routing.direct')}
                      </div>
                      <div className="text-gray-700 truncate" title={route.next_hop_interface || ''}>
                        {route.next_hop_interface || t('common.notAvailable')}
                      </div>
                      <div className="text-gray-700 truncate">{route.protocol}</div>
                      <div className="text-gray-700 truncate">{route.metric ?? t('common.notAvailable')}</div>
                      <div className="text-gray-700 truncate">{route.admin_distance ?? t('common.notAvailable')}</div>
                    </div>
                  )
                })}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// OSPF Tab
function OspfTab({ process, areas, interfaces, sessions }: {
  process?: OSPFProcessConfig
  areas: OSPFAreaConfig[]
  interfaces: OSPFInterfaceConfig[]
  sessions: OSPFSessionCompat[]
}) {
  const { t } = useTranslation()
  return (
    <div className="space-y-4">
      {/* OSPF Process */}
      {process && (
        <div className="bg-gray-50 rounded-lg p-4">
          <h3 className="font-medium text-gray-900 mb-2">{t('nodeDetails.sections.ospfProcess')}</h3>
          <div className="grid grid-cols-2 gap-2 text-sm">
            <div>
              <span className="text-gray-700">{t('nodeDetails.ospf.fields.processId')}:</span>
              <p className="font-medium">{process.process_id}</p>
            </div>
            <div>
              <span className="text-gray-700">{t('nodeDetails.fields.routerId')}:</span>
              <p className="font-medium">{process.router_id || t('common.notAvailable')}</p>
            </div>
            <div>
              <span className="text-gray-700">{t('nodeDetails.ospf.fields.referenceBandwidth')}:</span>
              <p className="font-medium">{process.reference_bandwidth || t('common.notAvailable')}</p>
            </div>
            <div>
              <span className="text-gray-700">{t('nodeDetails.ospf.fields.abr')}:</span>
              <p className="font-medium">{process.area_border_router ? t('common.yes') : t('common.no')}</p>
            </div>
          </div>
        </div>
      )}

      {/* OSPF Areas */}
      {areas.length > 0 && (
        <div className="bg-gray-50 rounded-lg p-4">
          <h3 className="font-medium text-gray-900 mb-2">{t('nodeDetails.sections.ospfAreas')} ({areas.length})</h3>
          <div className="space-y-2">
            {areas.map((area, index) => (
              <div key={index} className="bg-white p-2 rounded text-sm">
                <div className="font-medium text-gray-900">{t('nodeDetails.ospf.fields.area')} {area.area}</div>
                <div className="text-gray-700">{t('nodeDetails.fields.type')}: {area.area_type || t('nodeDetails.ospf.defaults.areaType')}</div>
                <div className="text-gray-700">
                  {t('nodeDetails.ospf.fields.activeInterfaces')}: {area.active_interfaces?.join(', ') || t('common.none')}
                </div>
                <div className="text-gray-700">
                  {t('nodeDetails.ospf.fields.passiveInterfaces')}: {area.passive_interfaces?.join(', ') || t('common.none')}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* OSPF Interfaces */}
      {interfaces.length > 0 && (
        <div className="bg-gray-50 rounded-lg p-4">
          <h3 className="font-medium text-gray-900 mb-2">{t('nodeDetails.sections.ospfInterfaces')} ({interfaces.length})</h3>
          <div className="space-y-1">
            {interfaces.map((iface, index) => (
              <div key={index} className="text-sm bg-white p-2 rounded">
                <div className="font-medium text-gray-900">{iface.interface}</div>
                <div className="grid grid-cols-2 gap-2 text-xs text-gray-700">
                  <div>{t('nodeDetails.ospf.fields.area')}: {iface.ospf_area_name || t('common.notAvailable')}</div>
                  <div>{t('nodeDetails.ospf.fields.cost')}: {iface.ospf_cost || t('common.notAvailable')}</div>
                  <div>{t('nodeDetails.ospf.fields.networkType')}: {iface.ospf_network_type || t('common.notAvailable')}</div>
                  <div>{t('nodeDetails.ospf.fields.passive')}: {iface.ospf_passive ? t('common.yes') : t('common.no')}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* OSPF Sessions */}
      {sessions.length > 0 && (
        <div className="bg-gray-50 rounded-lg p-4">
          <h3 className="font-medium text-gray-900 mb-2">{t('nodeDetails.sections.ospfSessions')} ({sessions.length})</h3>
          <div className="space-y-1">
            {sessions.map((session, index) => (
              <div key={index} className="text-sm bg-white p-2 rounded">
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div>
                    <span className="text-gray-700">{t('nodeDetails.ospf.fields.local')}:</span> {session.ip} ({t('nodeDetails.ospf.fields.area')} {session.area})
                  </div>
                  <div>
                    <span className="text-gray-700">{t('nodeDetails.ospf.fields.remote')}:</span> {session.remote_ip} ({t('nodeDetails.ospf.fields.area')} {session.remote_area})
                  </div>
                  <div>
                    <span className="text-gray-700">{t('nodeDetails.fields.status')}:</span> {session.session_status}
                  </div>
                  <div>
                    <span className="text-gray-700">{t('nodeDetails.fields.remoteInterface')}:</span> {session.remote_interface}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {!process && areas.length === 0 && interfaces.length === 0 && sessions.length === 0 && (
        <p className="text-sm text-gray-700">{t('nodeDetails.noOspfConfig')}</p>
      )}
    </div>
  )
}

// Services Tab
function ServicesTab({ node, aaa }: { node: NodeProperties; aaa: AAAAuthenticationLogin[] }) {
  const { t } = useTranslation()
  return (
    <div className="space-y-4">
      {/* DNS Services */}
      <div className="bg-gray-50 rounded-lg p-4">
        <h3 className="font-medium text-gray-900 mb-2">{t('nodeDetails.sections.dnsConfig')}</h3>
        <div className="space-y-2 text-sm">
          {node.dns_servers && node.dns_servers.length > 0 ? (
            <>
              <div>
                <span className="text-gray-700">{t('nodeDetails.services.dnsServers')}</span>
                <div className="ml-4 mt-1 space-y-1">
                  {node.dns_servers.map((server: string, i: number) => (
                    <div key={i} className="text-gray-900">{server}</div>
                  ))}
                </div>
              </div>
              {node.dns_source_interface && (
                <div>
                  <span className="text-gray-700">{t('nodeDetails.services.sourceInterface')}</span>
                  <span className="ml-2 text-gray-900">{node.dns_source_interface}</span>
                </div>
              )}
            </>
          ) : (
            <p className="text-gray-700">{t('nodeDetails.services.noDns')}</p>
          )}
        </div>
      </div>

      {/* NTP Services */}
      <div className="bg-gray-50 rounded-lg p-4">
        <h3 className="font-medium text-gray-900 mb-2">{t('nodeDetails.sections.ntpConfig')}</h3>
        <div className="space-y-2 text-sm">
          {node.ntp_servers && node.ntp_servers.length > 0 ? (
            <>
              <div>
                <span className="text-gray-700">{t('nodeDetails.services.ntpServers')}</span>
                <div className="ml-4 mt-1 space-y-1">
                  {node.ntp_servers.map((server: string, i: number) => (
                    <div key={i} className="text-gray-900">{server}</div>
                  ))}
                </div>
              </div>
              {node.ntp_source_interface && (
                <div>
                  <span className="text-gray-700">{t('nodeDetails.services.sourceInterface')}</span>
                  <span className="ml-2 text-gray-900">{node.ntp_source_interface}</span>
                </div>
              )}
            </>
          ) : (
            <p className="text-gray-700">{t('nodeDetails.services.noNtp')}</p>
          )}
        </div>
      </div>

      {/* Logging Services */}
      <div className="bg-gray-50 rounded-lg p-4">
        <h3 className="font-medium text-gray-900 mb-2">{t('nodeDetails.sections.loggingConfig')}</h3>
        <div className="space-y-2 text-sm">
          {node.logging_servers && node.logging_servers.length > 0 ? (
            <>
              <div>
                <span className="text-gray-700">{t('nodeDetails.services.loggingServers')}</span>
                <div className="ml-4 mt-1 space-y-1">
                  {node.logging_servers.map((server: string, i: number) => (
                    <div key={i} className="text-gray-900">{server}</div>
                  ))}
                </div>
              </div>
              {node.logging_source_interface && (
                <div>
                  <span className="text-gray-700">{t('nodeDetails.services.sourceInterface')}</span>
                  <span className="ml-2 text-gray-900">{node.logging_source_interface}</span>
                </div>
              )}
            </>
          ) : (
            <p className="text-gray-700">{t('nodeDetails.services.noLogging')}</p>
          )}
        </div>
      </div>

      {/* SNMP Services */}
      <div className="bg-gray-50 rounded-lg p-4">
        <h3 className="font-medium text-gray-900 mb-2">{t('nodeDetails.sections.snmpConfig')}</h3>
        <div className="space-y-2 text-sm">
          {node.snmp_trap_servers && node.snmp_trap_servers.length > 0 ? (
            <>
              <div>
                <span className="text-gray-700">{t('nodeDetails.services.snmpServers')}</span>
                <div className="ml-4 mt-1 space-y-1">
                  {node.snmp_trap_servers.map((server: string, i: number) => (
                    <div key={i} className="text-gray-900">{server}</div>
                  ))}
                </div>
              </div>
              {node.snmp_source_interface && (
                <div>
                  <span className="text-gray-700">{t('nodeDetails.services.sourceInterface')}</span>
                  <span className="ml-2 text-gray-900">{node.snmp_source_interface}</span>
                </div>
              )}
            </>
          ) : (
            <p className="text-gray-700">{t('nodeDetails.services.noSnmp')}</p>
          )}
        </div>
      </div>

      {/* TACACS+ Services */}
      <div className="bg-gray-50 rounded-lg p-4">
        <h3 className="font-medium text-gray-900 mb-2">{t('nodeDetails.sections.tacacsConfig')}</h3>
        <div className="space-y-2 text-sm">
          {node.tacacs_servers && node.tacacs_servers.length > 0 ? (
            <>
              <div>
                <span className="text-gray-700">{t('nodeDetails.services.tacacsServers')}</span>
                <div className="ml-4 mt-1 space-y-1">
                  {node.tacacs_servers.map((server: string, i: number) => (
                    <div key={i} className="text-gray-900">{server}</div>
                  ))}
                </div>
              </div>
              {node.tacacs_source_interface && (
                <div>
                  <span className="text-gray-700">{t('nodeDetails.services.sourceInterface')}</span>
                  <span className="ml-2 text-gray-900">{node.tacacs_source_interface}</span>
                </div>
              )}
            </>
          ) : (
            <p className="text-gray-700">{t('nodeDetails.services.noTacacs')}</p>
          )}
        </div>
      </div>

      {/* AAA Authentication */}
      {aaa.length > 0 && (
        <div className="bg-gray-50 rounded-lg p-4">
          <h3 className="font-medium text-gray-900 mb-2">{t('nodeDetails.sections.aaaAuth')}</h3>
          <div className="space-y-2">
            {aaa.map((auth, index) => (
              <div key={index} className="text-sm">
                <div className="text-gray-700">{t('nodeDetails.services.list')}: {auth.list_name || t('common.default')}</div>
                <div className="text-gray-700">{t('nodeDetails.services.methods')}: {auth.methods?.join(', ') || t('common.notAvailable')}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// Security Tab
function SecurityTab({ node, ipOwners }: { node: NodeProperties; ipOwners: IPOwner[] }) {
  const { t } = useTranslation()
  return (
    <div className="space-y-4">
      {/* Security Zones */}
      {node.zones && node.zones.length > 0 && (
        <div className="bg-gray-50 rounded-lg p-4">
          <h3 className="font-medium text-gray-900 mb-2">{t('nodeDetails.sections.securityZones')} ({node.zones.length})</h3>
          <div className="space-y-1">
            {node.zones.map((zone: string, index: number) => (
              <div key={index} className="text-sm text-gray-700 px-2 py-1 bg-white rounded">
                {zone}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* IPsec VPNs */}
      {node.ipsec_vpns && node.ipsec_vpns.length > 0 && (
        <div className="bg-gray-50 rounded-lg p-4">
          <h3 className="font-medium text-gray-900 mb-2">{t('nodeDetails.sections.ipsecVpns')} ({node.ipsec_vpns.length})</h3>
          <div className="space-y-1">
            {node.ipsec_vpns.map((vpn: string, index: number) => (
              <div key={index} className="text-sm text-gray-700 px-2 py-1 bg-white rounded">
                {vpn}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* IP Ownership */}
      {ipOwners.length > 0 && (
        <div className="bg-gray-50 rounded-lg p-4">
          <h3 className="font-medium text-gray-900 mb-2">{t('nodeDetails.sections.ipOwnership')} ({ipOwners.length})</h3>
          <div className="space-y-1">
            {ipOwners.map((ip, index) => (
              <div key={index} className="text-sm bg-white p-2 rounded">
                <div className="grid grid-cols-2 gap-2">
                  <div className="text-gray-700">IP: <span className="text-gray-900">{ip.ip}</span></div>
                  <div className="text-gray-700">Mask: <span className="text-gray-900">{ip.mask}</span></div>
                  <div className="text-gray-700">Interface: <span className="text-gray-900">{ip.interface}</span></div>
                  <div className="text-gray-700">Active: <span className="text-gray-900">{ip.active ? t('common.yes') : t('common.no')}</span></div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {!node.zones?.length && !node.ipsec_vpns?.length && !ipOwners.length && (
        <p className="text-sm text-gray-700">{t('nodeDetails.noSecurityConfig')}</p>
      )}
    </div>
  )
}

// Validation Tab
function ValidationTab({ node, data }: { node: NodeProperties; data: AllNetworkData | undefined }) {
  const { t } = useTranslation()
  // Find validation issues related to this node
  const nodeFileStatus = data?.file_parse_status?.find((f: FileParseStatus) =>
    f.nodes?.includes(node.node)
  )

  const nodeIssues = data?.init_issues?.filter((issue: InitIssue) =>
    issue.nodes?.includes(node.node)
  ) || []

  const nodeWarnings = data?.parse_warnings?.filter((warning: ParseWarning) =>
    warning.filename?.includes(node.node)
  ) || []

  return (
    <div className="space-y-4">
      {/* File Parse Status */}
      {nodeFileStatus && (
        <div className="bg-gray-50 rounded-lg p-4">
          <h3 className="font-medium text-gray-900 mb-2">{t('nodeDetails.sections.configFileStatus')}</h3>
          <div className="text-sm">
            <div className="text-gray-700">File: {nodeFileStatus.file_name}</div>
            <div className="text-gray-700">{t('nodeDetails.fields.format')}: {nodeFileStatus.file_format || t('common.notAvailable')}</div>
            <div className="flex items-center gap-2 mt-2">
              <span className="text-gray-700">{t('nodeDetails.fields.status')}:</span>
              <span className={`px-2 py-1 rounded text-xs font-medium ${
                nodeFileStatus.status === 'PASSED'
                  ? 'bg-green-100 text-green-800'
                  : nodeFileStatus.status === 'PARTIALLY_UNRECOGNIZED'
                  ? 'bg-yellow-100 text-yellow-800'
                  : 'bg-red-100 text-red-800'
              }`}>
                {nodeFileStatus.status}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Initialization Issues */}
      {nodeIssues.length > 0 && (
        <div className="bg-gray-50 rounded-lg p-4">
          <h3 className="font-medium text-gray-900 mb-2">
            {t('validation.sections.initIssues')} ({nodeIssues.length})
          </h3>
          <div className="space-y-2">
            {nodeIssues.map((issue: InitIssue, index: number) => (
              <div key={index} className="text-sm bg-white p-2 rounded border-l-4 border-yellow-400">
                <div className="text-gray-900 font-medium">{issue.type}</div>
                <div className="text-gray-700">{issue.details}</div>
                {issue.line_text && (
                  <div className="text-xs text-gray-600 mt-1 font-mono">{issue.line_text}</div>
                )}
                {issue.source_lines && issue.source_lines.length > 0 && (
                  <div className="text-xs text-gray-600 mt-1">
                    Source: {issue.source_lines.join(', ')}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Parse Warnings */}
      {nodeWarnings.length > 0 && (
        <div className="bg-gray-50 rounded-lg p-4">
          <h3 className="font-medium text-gray-900 mb-2">
            {t('validation.sections.parseWarnings')} ({nodeWarnings.length})
          </h3>
          <div className="space-y-2">
            {nodeWarnings.map((warning: ParseWarning, index: number) => (
              <div key={index} className="text-sm bg-white p-2 rounded border-l-4 border-orange-400">
                <div className="text-gray-700">{warning.comment}</div>
                <div className="text-xs text-gray-600 mt-1">Line {warning.line}: {warning.text}</div>
                {warning.parser_context && (
                  <div className="text-xs text-gray-600">Context: {warning.parser_context}</div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {!nodeFileStatus && nodeIssues.length === 0 && nodeWarnings.length === 0 && (
        <p className="text-sm text-gray-700">{t('nodeDetails.noValidationIssues')}</p>
      )}
    </div>
  )
}

// BGP Tab
function BgpTab({ node, edges, peerConfig, processConfig, sessionStatus, sessionCompat, rib }: {
  node: NodeProperties
  edges: BGPEdge[]
  peerConfig: BGPPeerConfiguration[]
  processConfig: BGPProcessConfiguration[]
  sessionStatus: BGPSessionStatus[]
  sessionCompat: BGPSessionCompatibility[]
  rib: BGPRib[]
}) {
  const { t } = useTranslation()
  const [expandedSection, setExpandedSection] = useState<string | null>(null)

  const toggleSection = (section: string) => {
    setExpandedSection(expandedSection === section ? null : section)
  }

  const hasBgpData = edges.length > 0 || peerConfig.length > 0 || processConfig.length > 0 ||
    sessionStatus.length > 0 || sessionCompat.length > 0 || rib.length > 0

  return (
    <div className="space-y-4">
      {!hasBgpData && (
        <p className="text-sm text-gray-700">{t('nodeDetails.noBgpConfig')}</p>
      )}

      {/* BGP Process Configuration */}
      {processConfig.length > 0 && (
        <div className="bg-gray-50 rounded-lg p-4">
          <button
            onClick={() => toggleSection('process')}
            className="w-full flex items-center justify-between mb-2 focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-1 rounded"
            aria-expanded={expandedSection === 'process'}
            aria-controls="bgp-process-content"
          >
            <h3 className="font-medium text-gray-900">
              {t('nodeDetails.sections.bgpProcess')} ({processConfig.length})
            </h3>
            <span className="text-gray-500" aria-hidden="true">{expandedSection === 'process' ? '−' : '+'}</span>
          </button>

          {expandedSection === 'process' && (
            <div id="bgp-process-content" className="space-y-2" role="region" aria-label="BGP process configuration details">
              {processConfig.map((proc, index) => (
                <div key={index} className="bg-white p-3 rounded text-sm border border-gray-200">
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <span className="text-gray-700">{t('nodeDetails.fields.vrf')}:</span>
                      <p className="font-medium">{proc.vrf || t('common.default')}</p>
                    </div>
                    <div>
                      <span className="text-gray-700">{t('nodeDetails.fields.routerId')}:</span>
                      <p className="font-medium">{proc.router_id || t('common.notAvailable')}</p>
                    </div>
                    {proc.local_as && (
                      <div>
                        <span className="text-gray-700">{t('nodeDetails.fields.localAs')}:</span>
                        <p className="font-medium">{proc.local_as}</p>
                      </div>
                    )}
                    {proc.confederation_id && (
                      <div>
                        <span className="text-gray-700">{t('nodeDetails.fields.confederationId')}:</span>
                        <p className="font-medium">{proc.confederation_id}</p>
                      </div>
                    )}
                  </div>
                  {proc.neighbors && proc.neighbors.length > 0 && (
                    <div className="mt-2">
                      <span className="text-gray-700">{t('nodeDetails.fields.neighbors')}:</span>
                      <div className="ml-2 text-xs text-gray-600">
                        {proc.neighbors.join(', ')}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* BGP Edges (Adjacencies) */}
      {edges.length > 0 && (
        <div className="bg-gray-50 rounded-lg p-4">
          <button
            onClick={() => toggleSection('edges')}
            className="w-full flex items-center justify-between mb-2"
          >
            <h3 className="font-medium text-gray-900">
              {t('nodeDetails.sections.bgpAdjacencies')} ({edges.length})
            </h3>
            <span className="text-gray-500">{expandedSection === 'edges' ? '−' : '+'}</span>
          </button>

          {expandedSection === 'edges' && (
            <div className="space-y-2">
              {edges.map((edge, index) => (
                <div key={index} className="bg-white p-3 rounded text-sm border border-gray-200">
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <span className="text-gray-700">{t('nodeDetails.fields.remoteNode')}:</span>
                      <p className="font-medium">{edge.remote_node || t('common.notAvailable')}</p>
                    </div>
                    <div>
                      <span className="text-gray-700">{t('nodeDetails.fields.remoteAs')}:</span>
                      <p className="font-medium">{edge.remote_as || t('common.notAvailable')}</p>
                    </div>
                    <div>
                      <span className="text-gray-700">{t('nodeDetails.fields.localIp')}:</span>
                      <p className="font-medium">{edge.local_ip || t('common.notAvailable')}</p>
                    </div>
                    <div>
                      <span className="text-gray-700">{t('nodeDetails.fields.remoteIp')}:</span>
                      <p className="font-medium">{edge.remote_ip || t('common.notAvailable')}</p>
                    </div>
                    <div>
                      <span className="text-gray-700">{t('nodeDetails.fields.localInterface')}:</span>
                      <p className="font-medium">{edge.local_interface || t('common.notAvailable')}</p>
                    </div>
                    <div>
                      <span className="text-gray-700">{t('nodeDetails.fields.vrf')}:</span>
                      <p className="font-medium">{edge.vrf || t('common.default')}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* BGP Peer Configuration */}
      {peerConfig.length > 0 && (
        <div className="bg-gray-50 rounded-lg p-4">
          <button
            onClick={() => toggleSection('peers')}
            className="w-full flex items-center justify-between mb-2"
          >
            <h3 className="font-medium text-gray-900">
              {t('nodeDetails.sections.bgpPeerConfig')} ({peerConfig.length})
            </h3>
            <span className="text-gray-500">{expandedSection === 'peers' ? '−' : '+'}</span>
          </button>

          {expandedSection === 'peers' && (
            <div className="space-y-2">
              {peerConfig.map((peer, index) => (
                <div key={index} className="bg-white p-3 rounded text-sm border border-gray-200">
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <span className="text-gray-700">{t('nodeDetails.fields.peerAddress')}:</span>
                      <p className="font-medium">{peer.peer_address || t('common.notAvailable')}</p>
                    </div>
                    <div>
                      <span className="text-gray-700">{t('nodeDetails.fields.remoteAs')}:</span>
                      <p className="font-medium">{peer.remote_as || t('common.notAvailable')}</p>
                    </div>
                    <div>
                      <span className="text-gray-700">{t('nodeDetails.fields.localAs')}:</span>
                      <p className="font-medium">{peer.local_as || t('common.notAvailable')}</p>
                    </div>
                    <div>
                      <span className="text-gray-700">{t('nodeDetails.fields.vrf')}:</span>
                      <p className="font-medium">{peer.vrf || t('common.default')}</p>
                    </div>
                    {peer.peer_group && (
                      <div>
                        <span className="text-gray-700">{t('nodeDetails.fields.peerGroup')}:</span>
                        <p className="font-medium">{peer.peer_group}</p>
                      </div>
                    )}
                    {peer.description && (
                      <div className="col-span-2">
                        <span className="text-gray-700">{t('nodeDetails.fields.description')}:</span>
                        <p className="font-medium">{peer.description}</p>
                      </div>
                    )}
                  </div>
                  {peer.import_policy && (
                    <div className="mt-2">
                      <span className="text-gray-700">{t('nodeDetails.fields.importPolicy')}:</span>
                      <p className="text-xs text-gray-600">{peer.import_policy}</p>
                    </div>
                  )}
                  {peer.export_policy && (
                    <div className="mt-1">
                      <span className="text-gray-700">{t('nodeDetails.fields.exportPolicy')}:</span>
                      <p className="text-xs text-gray-600">{peer.export_policy}</p>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* BGP Session Status */}
      {sessionStatus.length > 0 && (
        <div className="bg-gray-50 rounded-lg p-4">
          <button
            onClick={() => toggleSection('status')}
            className="w-full flex items-center justify-between mb-2"
          >
            <h3 className="font-medium text-gray-900">
              {t('nodeDetails.sections.bgpSessionStatus')} ({sessionStatus.length})
            </h3>
            <span className="text-gray-500">{expandedSection === 'status' ? '−' : '+'}</span>
          </button>

          {expandedSection === 'status' && (
            <div className="space-y-2">
              {sessionStatus.map((session, index) => (
                <div key={index} className="bg-white p-3 rounded text-sm border border-gray-200">
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-medium text-gray-900">
                      {session.remote_ip || session.remote_node || t('common.unknown')}
                    </span>
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                      session.established
                        ? 'bg-green-100 text-green-800'
                        : 'bg-red-100 text-red-800'
                    }`}>
                      {session.established ? t('common.status.established') : t('common.status.down')}
                    </span>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div className="text-gray-700">{t('nodeDetails.fields.localIp')}: {session.local_ip || t('common.notAvailable')}</div>
                    <div className="text-gray-700">{t('nodeDetails.fields.remoteIp')}: {session.remote_ip || t('common.notAvailable')}</div>
                    <div className="text-gray-700">{t('nodeDetails.fields.localAs')}: {session.local_as || t('common.notAvailable')}</div>
                    <div className="text-gray-700">{t('nodeDetails.fields.remoteAs')}: {session.remote_as || t('common.notAvailable')}</div>
                    <div className="text-gray-700">{t('nodeDetails.fields.vrf')}: {session.vrf || t('common.default')}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* BGP Session Compatibility */}
      {sessionCompat.length > 0 && (
        <div className="bg-gray-50 rounded-lg p-4">
          <button
            onClick={() => toggleSection('compat')}
            className="w-full flex items-center justify-between mb-2"
          >
            <h3 className="font-medium text-gray-900">
              {t('nodeDetails.sections.bgpSessionValidation')} ({sessionCompat.length})
            </h3>
            <span className="text-gray-500">{expandedSection === 'compat' ? '−' : '+'}</span>
          </button>

          {expandedSection === 'compat' && (
            <div className="space-y-2">
              {sessionCompat.map((compat, index) => (
                <div key={index} className="bg-white p-3 rounded text-sm border border-gray-200">
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-medium text-gray-900">
                      {compat.remote_node || compat.remote_ip || t('common.unknown')}
                    </span>
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                      compat.compatible || compat.configured_status === 'UNIQUE_MATCH'
                        ? 'bg-green-100 text-green-800'
                        : 'bg-yellow-100 text-yellow-800'
                    }`}>
                      {compat.configured_status || (compat.compatible ? t('nodeDetails.bgp.status.compatible') : t('nodeDetails.bgp.status.checkConfig'))}
                    </span>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-xs text-gray-700">
                    <div>{t('nodeDetails.fields.localIp')}: {compat.local_ip || t('common.notAvailable')}</div>
                    <div>{t('nodeDetails.fields.remoteIp')}: {compat.remote_ip || t('common.notAvailable')}</div>
                    <div>{t('nodeDetails.fields.vrf')}: {compat.vrf || t('common.default')}</div>
                    {compat.remote_interface && (
                      <div>{t('nodeDetails.fields.remoteInterface')}: {compat.remote_interface}</div>
                    )}
                  </div>
                  {compat.issues && compat.issues.length > 0 && (
                    <div className="mt-2 text-xs">
                      <span className="text-red-600 font-medium">{t('nodeDetails.fields.issues')}:</span>
                      <ul className="ml-4 list-disc text-red-600">
                        {compat.issues.map((issue: string, i: number) => (
                          <li key={i}>{issue}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* BGP RIB (Routing Information Base) */}
      {rib.length > 0 && (
        <div className="bg-gray-50 rounded-lg p-4">
          <button
            onClick={() => toggleSection('rib')}
            className="w-full flex items-center justify-between mb-2"
          >
            <h3 className="font-medium text-gray-900">
              {t('nodeDetails.sections.bgpRoutingTable')} ({t('nodeDetails.routeCount', { count: rib.length })})
            </h3>
            <span className="text-gray-500">{expandedSection === 'rib' ? '−' : '+'}</span>
          </button>

          {expandedSection === 'rib' && (
            <div className="overflow-x-auto">
              <table className="min-w-full text-xs">
                <thead>
                  <tr className="border-b">
                    <th className="text-left py-1 px-2 text-gray-700">{t('nodeDetails.fields.prefix')}</th>
                    <th className="text-left py-1 px-2 text-gray-700">{t('nodeDetails.fields.nextHop')}</th>
                    <th className="text-left py-1 px-2 text-gray-700">{t('nodeDetails.fields.protocol')}</th>
                    <th className="text-left py-1 px-2 text-gray-700">{t('nodeDetails.fields.origin')}</th>
                    <th className="text-left py-1 px-2 text-gray-700">{t('nodeDetails.fields.best')}</th>
                  </tr>
                </thead>
                <tbody>
                  {rib.map((route, index) => (
                    <tr key={index} className="border-b hover:bg-gray-100">
                      <td className="py-1 px-2 text-gray-900">{route.network || t('common.notAvailable')}</td>
                      <td className="py-1 px-2 text-gray-700">{route.next_hop_ip || t('common.notAvailable')}</td>
                      <td className="py-1 px-2 text-gray-700">{route.protocol || t('common.protocol.bgp')}</td>
                      <td className="py-1 px-2 text-gray-700">{route.origin_type || t('common.notAvailable')}</td>
                      <td className="py-1 px-2">
                        {route.best_path && (
                          <span className="text-xs bg-blue-100 text-blue-800 px-1 rounded">{t('nodeDetails.fields.best')}</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ACL/Filters Tab — Helper functions

const IPV4_REGEX = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d{1,2})?)\b/g

function ipToInt(ip: string): number | null {
  const parts = ip.split('.')
  if (parts.length !== 4) return null
  let result = 0
  for (const part of parts) {
    const num = parseInt(part, 10)
    if (isNaN(num) || num < 0 || num > 255) return null
    result = (result << 8) | num
  }
  return result >>> 0
}

function prefixToMaskInt(prefix: number): number {
  if (prefix <= 0) return 0
  if (prefix >= 32) return 0xFFFFFFFF
  return (~0 << (32 - prefix)) >>> 0
}

function extractAddresses(unreachableLine: string, blockingLines: string[]): string[] {
  const allText = [unreachableLine || '', ...(blockingLines || [])].join(' ')
  if (!allText.trim()) return []
  const matches = allText.match(IPV4_REGEX) || []
  return [...new Set(matches)]
}

interface IPOwnerEntry {
  owner: IPOwner
  ipInt: number
  maskInt: number
}

function findAddressOwners(
  addresses: string[],
  index: { exactMap: Map<string, IPOwner[]>; cidrEntries: IPOwnerEntry[] }
): AddressOwnership[] {
  const results: AddressOwnership[] = []

  for (const addr of addresses) {
    const [ipPart, maskPart] = addr.split('/')
    const hasPrefix = maskPart !== undefined

    const exactOwners = index.exactMap.get(ipPart) || []
    for (const owner of exactOwners) {
      results.push({
        address: addr,
        match_type: 'exact',
        owner_node: owner.node,
        owner_interface: owner.interface,
        owner_vrf: owner.vrf,
      })
    }

    if (hasPrefix) {
      // Forward: referenced CIDR → find owners whose IP falls within this subnet
      const prefixLen = parseInt(maskPart, 10)
      if (prefixLen < 0 || prefixLen > 32 || isNaN(prefixLen)) continue
      const addrInt = ipToInt(ipPart)
      const addrMask = prefixToMaskInt(prefixLen)
      if (addrInt !== null) {
        const addrNetwork = (addrInt & addrMask) >>> 0
        for (const entry of index.cidrEntries) {
          const ownerNetwork = (entry.ipInt & addrMask) >>> 0
          if (ownerNetwork === addrNetwork) {
            results.push({
              address: addr,
              match_type: 'cidr_contains',
              owner_node: entry.owner.node,
              owner_interface: entry.owner.interface,
              owner_vrf: entry.owner.vrf,
            })
          }
        }
      }
    } else if (exactOwners.length === 0) {
      // Inverse: bare host IP with no exact match → check if it falls within any owner's subnet
      const addrInt = ipToInt(ipPart)
      if (addrInt !== null) {
        for (const entry of index.cidrEntries) {
          const ownerNetwork = (entry.ipInt & entry.maskInt) >>> 0
          const addrNetwork = (addrInt & entry.maskInt) >>> 0
          if (ownerNetwork === addrNetwork) {
            results.push({
              address: addr,
              match_type: 'cidr_contains',
              owner_node: entry.owner.node,
              owner_interface: entry.owner.interface,
              owner_vrf: entry.owner.vrf,
            })
          }
        }
      }
    }
  }

  const seen = new Set<string>()
  return results.filter((r) => {
    const key = `${r.address}|${r.owner_node}|${r.owner_interface}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

function parseNodeFilter(filter: FilterLineReachability): { node: string; filterName: string } {
  if (filter.node && filter.filter) {
    return { node: filter.node, filterName: filter.filter }
  }
  // Try to extract "node: filter" or "node:filter" from sources field
  const parseSrc = (s: string): { node: string; filterName: string } | null => {
    // Prefer ": " (colon+space), fall back to ":" (colon only)
    const sepIdx = s.indexOf(': ')
    if (sepIdx > 0) {
      return { node: s.slice(0, sepIdx).trim(), filterName: s.slice(sepIdx + 2).trim() }
    }
    const colonIdx = s.indexOf(':')
    if (colonIdx > 0) {
      return { node: s.slice(0, colonIdx).trim(), filterName: s.slice(colonIdx + 1).trim() }
    }
    return null
  }
  const sources = filter.sources
  if (typeof sources === 'string') {
    const parsed = parseSrc(sources)
    if (parsed) return parsed
  }
  if (Array.isArray(sources) && sources.length > 0) {
    const parsed = parseSrc(String(sources[0]))
    if (parsed) return parsed
  }
  return { node: filter.node || '', filterName: filter.filter || '' }
}

function toSafeId(str: string): string {
  return str.replace(/[^a-zA-Z0-9-]/g, '-').replace(/-+/g, '-').toLowerCase()
}

function aclGroupId(node: string, filterName: string, index: number): string {
  return `acl-group-${toSafeId(node)}-${toSafeId(filterName)}-${index}`
}

// ACL/Filters Tab
function AclTab({ node, filterReachability, allInterfaces, allIpOwners }: {
  node: NodeProperties
  filterReachability: FilterLineReachability[]
  allInterfaces: InterfaceProperties[]
  allIpOwners: IPOwner[]
}) {
  const { t } = useTranslation()
  const setSelectedNodeId = useUIStore((s) => s.setSelectedNodeId)
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set())
  const [searchQuery, setSearchQuery] = useState('')

  const toggleGroup = useCallback((gid: string) => {
    setExpandedGroups((prev) => {
      const next = new Set(prev)
      if (next.has(gid)) next.delete(gid)
      else next.add(gid)
      return next
    })
  }, [])

  // Step 0: Pre-indexed lookup structures
  const interfacesByHost = useMemo(() => {
    const map = new Map<string, InterfaceProperties[]>()
    for (const iface of allInterfaces) {
      const list = map.get(iface.hostname) || []
      list.push(iface)
      map.set(iface.hostname, list)
    }
    return map
  }, [allInterfaces])

  const ipOwnerIndex = useMemo(() => {
    const exactMap = new Map<string, IPOwner[]>()
    const cidrEntries: IPOwnerEntry[] = []
    for (const owner of allIpOwners) {
      if (!owner.active || !owner.ip) continue
      const list = exactMap.get(owner.ip) || []
      list.push(owner)
      exactMap.set(owner.ip, list)
      const ipInt = ipToInt(owner.ip)
      const maskInt = owner.mask != null ? prefixToMaskInt(parseInt(String(owner.mask), 10)) : 0xFFFFFFFF
      if (ipInt !== null) {
        cidrEntries.push({ owner, ipInt, maskInt })
      }
    }
    return { exactMap, cidrEntries }
  }, [allIpOwners])

  // Step 1-3: Enrichment
  const enrichedFilters = useMemo((): EnrichedFilterEntry[] => {
    if (!filterReachability.length) return []
    return filterReachability.map((filter) => {
      const { node: nodeName, filterName } = parseNodeFilter(filter)
      const appliedTo: FilterApplication[] = []
      const hostInterfaces = interfacesByHost.get(nodeName) || []
      for (const iface of hostInterfaces) {
        if (iface.incoming_filter_name === filterName) {
          appliedTo.push({
            interface_name: iface.interface,
            direction: 'inbound',
            zone: iface.zone || null,
            primary_address: iface.primary_address || null,
          })
        }
        if (iface.outgoing_filter_name === filterName) {
          appliedTo.push({
            interface_name: iface.interface,
            direction: 'outbound',
            zone: iface.zone || null,
            primary_address: iface.primary_address || null,
          })
        }
      }
      const referencedAddresses = extractAddresses(filter.unreachable_line, filter.blocking_lines)
      const addressOwners = findAddressOwners(referencedAddresses, ipOwnerIndex)
      return {
        ...filter,
        node: nodeName,
        filter: filterName,
        applied_to: appliedTo,
        referenced_addresses: referencedAddresses,
        address_owners: addressOwners,
      }
    })
  }, [filterReachability, interfacesByHost, ipOwnerIndex])

  // Grouping
  const { currentNodeGroups, otherNodeGroups, totalNodes } = useMemo(() => {
    const currentGroups: FilterGroup[] = []
    const otherGroups: FilterGroup[] = []
    const groupMap = new Map<string, EnrichedFilterEntry[]>()
    const nodeSet = new Set<string>()

    let unknownIdx = 0
    for (const entry of enrichedFilters) {
      let key: string
      if (!entry.node && !entry.filter) {
        // Each unknown-source entry gets its own group to prevent merging unrelated entries
        key = `__unknown_${unknownIdx++}|||`
      } else {
        key = `${entry.node}|||${entry.filter}`
      }
      const list = groupMap.get(key) || []
      list.push(entry)
      groupMap.set(key, list)
      if (entry.node) nodeSet.add(entry.node)
    }

    for (const [, entries] of groupMap) {
      // Use actual entry values (not the grouping key, which may be synthetic for unknown entries)
      const nodeName = entries[0]?.node || ''
      const filterName = entries[0]?.filter || ''
      const deny = entries.filter((e) => e.action?.toUpperCase() === 'DENY').length
      const permit = entries.filter((e) => e.action?.toUpperCase() === 'PERMIT').length
      const other = entries.length - deny - permit
      const group: FilterGroup = {
        filter_name: filterName || t('nodeDetails.acl.defaults.unnamedFilter'),
        node: nodeName,
        applied_to: entries[0]?.applied_to || [],
        severity: entries.length >= 3 ? 'high' : 'low',
        action_breakdown: { deny, permit, other },
        entries,
      }
      if (nodeName === node.node) {
        currentGroups.push(group)
      } else {
        otherGroups.push(group)
      }
    }

    return { currentNodeGroups: currentGroups, otherNodeGroups: otherGroups, totalNodes: nodeSet.size }
  }, [enrichedFilters, node.node, t])

  // Search filter for other nodes
  const filteredOtherGroups = useMemo(() => {
    if (!searchQuery.trim()) return otherNodeGroups
    const q = searchQuery.toLowerCase()
    return otherNodeGroups.filter(
      (g) => g.node.toLowerCase().includes(q) || g.filter_name.toLowerCase().includes(q)
    )
  }, [otherNodeGroups, searchQuery])

  // Group other node groups by node name
  const otherNodeGroupsByNode = useMemo(() => {
    const map = new Map<string, FilterGroup[]>()
    for (const g of filteredOtherGroups) {
      const list = map.get(g.node) || []
      list.push(g)
      map.set(g.node, list)
    }
    return map
  }, [filteredOtherGroups])

  const totalCurrentLines = currentNodeGroups.reduce((sum, g) => sum + g.entries.length, 0)
  const totalOtherLines = otherNodeGroups.reduce((sum, g) => sum + g.entries.length, 0)

  // Render helpers
  const renderActionBadge = (action: string) => {
    const upper = action?.toUpperCase() || ''
    if (upper === 'DENY') return <span className="text-red-600 font-semibold">{upper}</span>
    if (upper === 'PERMIT') return <span className="text-emerald-600 font-semibold">{upper}</span>
    return <span className="text-gray-600 font-medium">{action || t('common.notAvailable')}</span>
  }

  const renderAppliedTo = (appliedTo: FilterApplication[]) => {
    if (appliedTo.length === 0) {
      return <p className="text-xs text-gray-400 italic">{t('nodeDetails.acl.notApplied')}</p>
    }
    return (
      <div className="space-y-1.5">
        {appliedTo.map((app, i) => (
          <div key={`${app.interface_name}-${app.direction}-${i}`} className="flex items-center gap-2 text-xs">
            <span className="font-mono text-gray-900">{app.interface_name}</span>
            <span
              className={`px-2.5 py-1 rounded-md font-medium text-sm ${
                app.direction === 'inbound'
                  ? 'bg-blue-100 text-blue-700'
                  : 'bg-green-100 text-green-700'
              }`}
              aria-label={`${t(`nodeDetails.acl.direction.${app.direction}`)} - ${app.interface_name}`}
            >
              {app.direction === 'inbound' ? '← ' : '→ '}{t(`nodeDetails.acl.direction.${app.direction}`)}
            </span>
            {app.zone && (
              <span className="text-gray-500">{t('nodeDetails.acl.fields.zone')}: {app.zone}</span>
            )}
            {app.primary_address && (
              <span className="font-mono text-gray-500">{app.primary_address}</span>
            )}
          </div>
        ))}
      </div>
    )
  }

  const renderAddressOwners = (entry: EnrichedFilterEntry) => {
    if (entry.referenced_addresses.length === 0) {
      return <p className="text-xs text-gray-400 italic">{t('nodeDetails.acl.noAddresses')}</p>
    }
    return (
      <table className="text-xs w-full">
        <thead>
          <tr className="text-xs font-semibold text-gray-500 uppercase tracking-wide border-b border-gray-200">
            <th className="text-left py-1 pr-2">{t('nodeDetails.acl.fields.address')}</th>
            <th className="text-left py-1 pr-2">{t('nodeDetails.acl.fields.owner')}</th>
            <th className="text-left py-1 pr-2">{t('nodeDetails.acl.fields.interface')}</th>
            <th className="text-left py-1">{t('nodeDetails.acl.fields.vrf')}</th>
          </tr>
        </thead>
        <tbody>
          {entry.referenced_addresses.map((addr) => {
            const owners = entry.address_owners.filter((o) => o.address === addr)
            if (owners.length === 0) {
              return (
                <tr key={addr} className="border-b border-gray-50">
                  <td className="font-mono py-1 pr-2">{addr}</td>
                  <td className="text-gray-400 italic py-1 pr-2" colSpan={3}>{t('nodeDetails.acl.unknownOwner')}</td>
                </tr>
              )
            }
            return owners.map((owner, oi) => (
              <tr key={`${addr}-${owner.owner_node}-${owner.owner_interface}-${oi}`} className="border-b border-gray-50">
                {oi === 0 && <td className="font-mono py-1 pr-2" rowSpan={owners.length}>{addr}</td>}
                <td className="py-1 pr-2">
                  <button
                    onClick={() => setSelectedNodeId(owner.owner_node)}
                    className="text-primary-600 hover:underline text-xs focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-1 rounded"
                    aria-label={t('nodeDetails.acl.navigateToNode', { node: owner.owner_node })}
                  >
                    {owner.match_type === 'cidr_contains' && (
                      <span title={t('nodeDetails.acl.cidrMatch')}>~</span>
                    )}
                    {owner.owner_node}
                  </button>
                </td>
                <td className="font-mono py-1 pr-2">{owner.owner_interface}</td>
                <td className="py-1">{owner.owner_vrf}</td>
              </tr>
            ))
          })}
        </tbody>
      </table>
    )
  }

  const renderEntryCard = (entry: EnrichedFilterEntry, idx: number, borderColor: string) => (
    <div key={idx} className={`bg-white p-4 rounded-lg text-sm border-l-4 ${borderColor} shadow-sm border border-gray-200`}>
      <div className="flex items-center gap-2 mb-2">
        {entry.line != null && (
          <>
            <span className="text-xs font-semibold text-gray-500 uppercase tracking-wide">
              {t('nodeDetails.acl.fields.line')} {entry.line}
            </span>
            <span className="text-xs" aria-hidden="true">·</span>
          </>
        )}
        {renderActionBadge(entry.action)}
      </div>

      {entry.unreachable_line && (
        <div className="bg-gray-800 text-gray-100 rounded-md p-3 font-mono text-xs mb-3">
          <code role="code">{entry.unreachable_line}</code>
        </div>
      )}

      <div className="mt-3 pt-3 border-t border-gray-100">
        <h5 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1">
          {t('nodeDetails.acl.referencedAddresses')}
        </h5>
        {renderAddressOwners(entry)}
      </div>

      {entry.blocking_lines && entry.blocking_lines.length > 0 && (
        <div className="mt-3 pt-3 border-t border-gray-100">
          <h5 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1">
            {t('nodeDetails.acl.blockedBy')}
          </h5>
          <div className="text-xs text-gray-700 space-y-1">
            {entry.blocking_lines.map((bl, bi) => (
              <div key={bi} className="bg-gray-800 text-gray-100 rounded-md p-2 font-mono"><code role="code">{bl}</code></div>
            ))}
          </div>
        </div>
      )}

      {entry.reason && (
        <div className="mt-3 pt-3 border-t border-gray-100">
          <h5 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1">
            {t('nodeDetails.acl.fields.reason')}
          </h5>
          <p className="text-xs text-gray-600">{entry.reason}</p>
        </div>
      )}
    </div>
  )

  const renderFilterGroup = (group: FilterGroup, idx: number, borderColor: string) => {
    const gid = aclGroupId(group.node, group.filter_name, idx)
    return (
      <div key={gid}>
        <button
          id={`${gid}-button`}
          onClick={() => toggleGroup(gid)}
          aria-expanded={expandedGroups.has(gid)}
          aria-controls={`${gid}-content`}
          className="w-full flex items-center justify-between p-3 hover:bg-gray-50 transition-colors
                     focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-inset rounded-lg"
        >
          <div className="flex items-center gap-2">
            {expandedGroups.has(gid)
              ? <ChevronDown className="w-4 h-4 text-gray-500" aria-hidden="true" />
              : <ChevronRight className="w-4 h-4 text-gray-500" aria-hidden="true" />}
            <span className="font-medium text-gray-900">{group.filter_name}</span>
            <span className="text-xs text-gray-500">
              — {t('nodeDetails.acl.collapsePreview', {
                count: group.entries.length,
                deny: group.action_breakdown.deny,
                permit: group.action_breakdown.permit,
              })}
            </span>
          </div>
          <span
            className={`w-2.5 h-2.5 rounded-full ${
              group.severity === 'high' ? 'bg-red-500' : 'bg-yellow-400'
            }`}
            aria-label={t(`nodeDetails.acl.severity.${group.severity}`)}
          />
        </button>

        {expandedGroups.has(gid) && (
          <div
            id={`${gid}-content`}
            role="region"
            aria-labelledby={`${gid}-button`}
            className="px-4 pb-4"
          >
            {!group.node && !group.entries[0]?.filter && group.entries[0]?.sources && (
              <div className="mb-3 text-xs text-gray-400 italic">
                {t('nodeDetails.acl.unknownSource')}: {
                  Array.isArray(group.entries[0].sources)
                    ? group.entries[0].sources.join(', ')
                    : String(group.entries[0].sources)
                }
              </div>
            )}

            <div className="mb-3">
              <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1.5">
                {t('nodeDetails.acl.appliedTo')}
              </h4>
              {renderAppliedTo(group.applied_to)}
            </div>

            <div className="space-y-3">
              {group.entries.map((entry, ei) => renderEntryCard(entry, ei, borderColor))}
            </div>
          </div>
        )}
      </div>
    )
  }

  if (filterReachability.length === 0) {
    return (
      <div className="space-y-4">
        <p className="text-sm text-gray-700">{t('nodeDetails.acl.noData')}</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Summary Bar */}
      <div className="bg-gray-100 rounded-lg px-4 py-3 text-sm text-gray-700" role="status">
        {t('nodeDetails.acl.summary', { count: filterReachability.length, nodeCount: totalNodes })}
      </div>

      {/* Current Node Filters */}
      {currentNodeGroups.length > 0 && (
        <div className="bg-white rounded-lg">
          <h3 className="font-medium text-gray-900 px-4 pt-4 pb-2">
            {t('nodeDetails.acl.currentNodeFilters')} ({t('nodeDetails.acl.filterCount', {
              filterCount: currentNodeGroups.length,
              lineCount: totalCurrentLines,
            })})
          </h3>
          <div className="space-y-1">
            {currentNodeGroups.map((group, idx) => renderFilterGroup(group, idx, 'border-red-400'))}
          </div>
        </div>
      )}

      {/* Other Nodes' Filters */}
      {otherNodeGroups.length > 0 && (
        <div className="bg-gray-50 rounded-lg">
          <h3 className="font-medium text-gray-900 px-4 pt-4 pb-2">
            {t('nodeDetails.acl.otherNodeFilters')} ({t('nodeDetails.acl.filterCount', {
              filterCount: otherNodeGroups.length,
              lineCount: totalOtherLines,
            })})
          </h3>

          <div className="px-4 pb-3">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" aria-hidden="true" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder={t('nodeDetails.acl.searchPlaceholder')}
                aria-label={t('nodeDetails.acl.searchPlaceholder')}
                className="w-full pl-9 pr-3 py-2 text-sm border border-gray-300 rounded-md
                           focus:outline-none focus:ring-2 focus:ring-primary-600"
              />
            </div>
          </div>

          {filteredOtherGroups.length === 0 && searchQuery.trim() && (
            <p className="text-xs text-gray-400 italic px-4 pb-4">{t('nodeDetails.acl.noSearchResults')}</p>
          )}

          <div className="space-y-1 max-h-[600px] overflow-y-auto">
            {Array.from(otherNodeGroupsByNode.entries()).map(([nodeName, groups], nodeIdx) => {
              const nodeGid = `acl-node-${nodeName ? toSafeId(nodeName) : `unknown-${nodeIdx}`}`
              const displayName = nodeName || t('nodeDetails.acl.unknownSource')
              return (
                <div key={nodeGid}>
                  <button
                    id={`${nodeGid}-button`}
                    onClick={() => toggleGroup(nodeGid)}
                    aria-expanded={expandedGroups.has(nodeGid)}
                    aria-controls={`${nodeGid}-content`}
                    className="w-full flex items-center gap-2 p-3 hover:bg-gray-100 transition-colors
                               focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-inset rounded-lg font-medium text-gray-900"
                  >
                    {expandedGroups.has(nodeGid)
                      ? <ChevronDown className="w-4 h-4 text-gray-500" aria-hidden="true" />
                      : <ChevronRight className="w-4 h-4 text-gray-500" aria-hidden="true" />}
                    <span className={!nodeName ? 'text-gray-400 italic' : ''}>{displayName}</span>
                    <span className="text-xs text-gray-500 font-normal">
                      ({t('nodeDetails.acl.filterCount', {
                        filterCount: groups.length,
                        lineCount: groups.reduce((s, g) => s + g.entries.length, 0),
                      })})
                    </span>
                  </button>

                  {expandedGroups.has(nodeGid) && (
                    <div
                      id={`${nodeGid}-content`}
                      role="region"
                      aria-labelledby={`${nodeGid}-button`}
                      className="pl-4"
                    >
                      {groups.map((group, idx) => renderFilterGroup(group, idx, 'border-yellow-400'))}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}

// VLAN Tab
function VlanTab({ node, vlans }: { node: NodeProperties; vlans: SwitchedVlanProperties[] }) {
  const { t } = useTranslation()
  return (
    <div className="space-y-4">
      {/* VLAN Properties */}
      {vlans.length > 0 && (
        <div className="bg-gray-50 rounded-lg p-4">
          <h3 className="font-medium text-gray-900 mb-3">
            {t('nodeDetails.sections.vlanProperties')} ({vlans.length})
          </h3>
          <div className="space-y-2">
            {vlans.map((vlan, index) => (
              <div key={index} className="bg-white p-3 rounded text-sm border border-gray-200">
                <div className="flex items-center justify-between mb-2">
                  <span className="font-medium text-gray-900">{t('nodeDetails.vlan.fields.vlanPrefix')} {vlan.vlan_id}</span>
                  {vlan.vxlan_vni && (
                    <span className="px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-800">
                      {t('nodeDetails.vlan.fields.vni')}: {vlan.vxlan_vni}
                    </span>
                  )}
                </div>
                <div className="grid grid-cols-1 gap-2 text-xs">
                  <div className="text-gray-700">
                    {t('nodeDetails.vlan.fields.interfaces')}: {vlan.interfaces?.join(', ') || t('common.none')}
                  </div>
                  {vlan.interface_vlans && vlan.interface_vlans.length > 0 && (
                    <div className="text-gray-700">
                      {t('nodeDetails.vlan.fields.interfaceVlans')}: {vlan.interface_vlans.join(', ')}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {vlans.length === 0 && (
        <p className="text-sm text-gray-700">{t('nodeDetails.noVlanData')}</p>
      )}
    </div>
  )
}

// Configuration Structures Tab
function ConfigurationTab({ node, definedStructures, referencedStructures, namedStructures }: {
  node: NodeProperties
  definedStructures: DefinedStructure[]
  referencedStructures: ReferencedStructure[]
  namedStructures: NamedStructure[]
}) {
  const { t } = useTranslation()
  const [expandedSection, setExpandedSection] = useState<string | null>(null)

  const toggleSection = (section: string) => {
    setExpandedSection(expandedSection === section ? null : section)
  }

  return (
    <div className="space-y-4">
      {/* Named Structures */}
      {namedStructures.length > 0 && (
        <div className="bg-gray-50 rounded-lg p-4">
          <button
            onClick={() => toggleSection('named')}
            className="w-full flex items-center justify-between mb-2 focus:outline-none"
            aria-expanded={expandedSection === 'named'}
          >
            <h3 className="font-medium text-gray-900">
              {t('nodeDetails.sections.namedStructures')} ({namedStructures.length})
            </h3>
            <span className="text-gray-500">{expandedSection === 'named' ? '−' : '+'}</span>
          </button>

          {expandedSection === 'named' && (
            <div className="space-y-2">
              {namedStructures.map((struct, index) => (
                <div key={index} className="bg-white p-3 rounded text-sm border border-gray-200">
                  <div className="font-medium text-gray-900">{struct.structure_name}</div>
                  <div className="text-xs text-gray-700">{t('nodeDetails.fields.type')}: {struct.structure_type}</div>
                  {struct.structure_definition && (
                    <div className="mt-2 p-2 bg-gray-100 rounded text-xs font-mono overflow-auto max-h-40">
                      {JSON.stringify(struct.structure_definition, null, 2)}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Defined Structures */}
      {definedStructures.length > 0 && (
        <div className="bg-gray-50 rounded-lg p-4">
          <button
            onClick={() => toggleSection('defined')}
            className="w-full flex items-center justify-between mb-2 focus:outline-none"
            aria-expanded={expandedSection === 'defined'}
          >
            <h3 className="font-medium text-gray-900">
              {t('nodeDetails.sections.definedStructures')} ({definedStructures.length})
            </h3>
            <span className="text-gray-500">{expandedSection === 'defined' ? '−' : '+'}</span>
          </button>

          {expandedSection === 'defined' && (
            <div className="space-y-1 max-h-96 overflow-y-auto">
              {definedStructures.map((struct, index) => (
                <div key={index} className="bg-white p-2 rounded text-xs border border-gray-200">
                  <div className="grid grid-cols-2 gap-2">
                    <div className="text-gray-700">{t('nodeDetails.fields.name')}: {struct.structure_name}</div>
                    <div className="text-gray-700">{t('nodeDetails.fields.type')}: {struct.structure_type}</div>
                  </div>
                  {struct.source_lines && struct.source_lines.length > 0 && (
                    <div className="text-gray-600 text-xs mt-1">
                      {t('nodeDetails.config.fields.lines')}: {struct.source_lines.join(', ')}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Referenced Structures */}
      {referencedStructures.length > 0 && (
        <div className="bg-gray-50 rounded-lg p-4">
          <button
            onClick={() => toggleSection('referenced')}
            className="w-full flex items-center justify-between mb-2 focus:outline-none"
            aria-expanded={expandedSection === 'referenced'}
          >
            <h3 className="font-medium text-gray-900">
              {t('nodeDetails.sections.referencedStructures')} ({referencedStructures.length})
            </h3>
            <span className="text-gray-500">{expandedSection === 'referenced' ? '−' : '+'}</span>
          </button>

          {expandedSection === 'referenced' && (
            <div className="space-y-1 max-h-96 overflow-y-auto">
              {referencedStructures.map((struct, index) => (
                <div key={index} className="bg-white p-2 rounded text-xs border border-gray-200">
                  <div className="grid grid-cols-2 gap-2">
                    <div className="text-gray-700">{t('nodeDetails.fields.name')}: {struct.structure_name}</div>
                    <div className="text-gray-700">{t('nodeDetails.fields.type')}: {struct.structure_type}</div>
                  </div>
                  <div className="text-gray-600 text-xs mt-1">{t('nodeDetails.config.fields.context')}: {struct.context}</div>
                  {struct.source_lines && struct.source_lines.length > 0 && (
                    <div className="text-gray-600 text-xs">
                      {t('nodeDetails.config.fields.lines')}: {struct.source_lines.join(', ')}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {namedStructures.length === 0 && definedStructures.length === 0 && referencedStructures.length === 0 && (
        <p className="text-sm text-gray-700">{t('nodeDetails.noConfigData')}</p>
      )}
    </div>
  )
}

// EIGRP Tab
function EigrpTab({ node, edges }: { node: NodeProperties; edges: EIGRPEdge[] }) {
  const { t } = useTranslation()
  return (
    <div className="space-y-4">
      {/* EIGRP Edges */}
      {edges.length > 0 && (
        <div className="bg-gray-50 rounded-lg p-4">
          <h3 className="font-medium text-gray-900 mb-3">
            {t('nodeDetails.sections.eigrpEdges')} ({edges.length})
          </h3>
          <div className="space-y-2">
            {edges.map((edge, index) => (
              <div key={index} className="bg-white p-3 rounded text-sm border border-gray-200">
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="text-gray-700">{t('nodeDetails.eigrp.fields.interface')}: {edge.interface}</div>
                  <div className="text-gray-700">{t('nodeDetails.eigrp.fields.remote')}: {edge.remote_interface}</div>
                  <div className="text-gray-700">{t('nodeDetails.eigrp.fields.ip')}: {edge.ip}</div>
                  <div className="text-gray-700">{t('nodeDetails.eigrp.fields.remoteIp')}: {edge.remote_ip}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {edges.length === 0 && (
        <p className="text-sm text-gray-700">{t('nodeDetails.noEigrpData')}</p>
      )}
    </div>
  )
}

// IS-IS Tab
function IsisTab({ node, edges }: { node: NodeProperties; edges: ISISEdge[] }) {
  const { t } = useTranslation()
  return (
    <div className="space-y-4">
      {/* IS-IS Edges */}
      {edges.length > 0 && (
        <div className="bg-gray-50 rounded-lg p-4">
          <h3 className="font-medium text-gray-900 mb-3">
            {t('nodeDetails.sections.isisEdges')} ({edges.length})
          </h3>
          <div className="space-y-2">
            {edges.map((edge, index) => (
              <div key={index} className="bg-white p-3 rounded text-sm border border-gray-200">
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="text-gray-700">{t('nodeDetails.isis.fields.interface')}: {edge.interface}</div>
                  <div className="text-gray-700">{t('nodeDetails.isis.fields.remote')}: {edge.remote_interface}</div>
                  <div className="text-gray-700">{t('nodeDetails.isis.fields.level')}: {edge.level}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {edges.length === 0 && (
        <p className="text-sm text-gray-700">{t('nodeDetails.noIsisData')}</p>
      )}
    </div>
  )
}

// VXLAN Tab
function VxlanTab({ node, edges }: { node: NodeProperties; edges: VXLANEdge[] }) {
  const { t } = useTranslation()
  return (
    <div className="space-y-4">
      {/* VXLAN Edges */}
      {edges.length > 0 && (
        <div className="bg-gray-50 rounded-lg p-4">
          <h3 className="font-medium text-gray-900 mb-3">
            {t('nodeDetails.sections.vxlanEdges')} ({edges.length})
          </h3>
          <div className="space-y-2">
            {edges.map((edge, index) => (
              <div key={index} className="bg-white p-3 rounded text-sm border border-gray-200">
                <div className="flex items-center justify-between mb-2">
                  <span className="font-medium text-gray-900">{t('nodeDetails.vxlan.fields.vni')}: {edge.vni}</span>
                  <span className="text-xs text-gray-700">{edge.remote_node}</span>
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="text-gray-700">{t('nodeDetails.vxlan.fields.localVtep')}: {edge.vtep_address}</div>
                  <div className="text-gray-700">{t('nodeDetails.vxlan.fields.remoteVtep')}: {edge.remote_vtep_address}</div>
                  {edge.multicast_group && (
                    <div className="col-span-2 text-gray-700">
                      {t('nodeDetails.vxlan.fields.multicastGroup')}: {edge.multicast_group}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {edges.length === 0 && (
        <p className="text-sm text-gray-700">{t('nodeDetails.noVxlanData')}</p>
      )}
    </div>
  )
}

export default NodeDetailsPanel