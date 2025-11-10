/**
 * Comprehensive network data explorer with 40+ collapsible sections
 * - Imports ~50 React Query hooks for all Batfish data types
 * - Protocol sections: OSPF, BGP, EIGRP, IS-IS, BFD, EVPN, VXLAN, IPSec
 * - HA sections: VRRP, HSRP, MLAG properties
 * - Topology sections: Layer1, Layer2, physical/layer3 edges, VLAN edges
 * - Config sections: routes, VLANs, interfaces, structures, AAA auth
 * - Advanced: F5 VIPs, vendor-independent model, route policies
 * - Each section shows data count badge and JSON-formatted results
 * - Used for deep dive analysis and debugging network configurations
 */
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  useVRRPProperties,
  useHSRPProperties,
  useMLAGProperties,
  useDuplicateRouterIDs,
  useSwitchingProperties,
  useBGPEdges,
  useBGPProcessConfiguration,
  useBGPPeerConfiguration,
  useBGPSessionStatus,
  useBGPSessionCompatibility,
  useBGPRib,
  useEIGRPEdges,
  useEIGRPInterfaces,
  useISISEdges,
  useISISInterfaces,
  useISISLoopbackInterfaces,
  useBFDSessionStatus,
  useEVPNRib,
  useOSPFProcesses,
  useOSPFAreas,
  useOSPFInterfaces,
  useOSPFSessions,
  useOSPFEdges,
  useNodes,
  useInterfaces,
  useRoutes,
  useVlans,
  useIPOwners,
  usePhysicalEdges,
  useLayer3Edges,
  useLayer1Topology,
  useLayer2Topology,
  useVXLANVNIProperties,
  useVXLANEdges,
  useIPSecSessionStatus,
  useIPSecEdges,
  useIPSecPeerConfiguration,
  useInterfaceMTU,
  useIPSpaceAssignment,
  useF5VIPs,
  useVIModel,
  useDefinedStructures,
  useReferencedStructures,
  useNamedStructures,
  useAAAAuthentication,
  useRoutePolicies,
} from '../../hooks'

import {
  Shield,
  Activity,
  Layers,
  Network,
  GitBranch,
  Server,
  Lock,
  ChevronDown,
  ChevronRight,
  CheckCircle,
  Info,
  FileText,
} from 'lucide-react'

interface SectionProps {
  title: string
  icon: React.ReactNode
  isLoading: boolean
  data: any
  defaultOpen?: boolean
}

/**
 * Reusable collapsible section component for displaying Batfish query results
 * - Accordion-style: click header to expand/collapse content
 * - Badge: shows item count when data is available (array length or object keys)
 * - JSON display: renders data as formatted JSON in scrollable pre block
 * - Loading/empty states: handles loading spinner and "no data" message
 * - Accessibility: ARIA expanded/controls attributes for screen readers
 */
function Section({ title, icon, isLoading, data, defaultOpen = false }: SectionProps) {
  const { t } = useTranslation()
  const [isOpen, setIsOpen] = useState(defaultOpen)
  const sectionId = `section-${title.toLowerCase().replace(/\s+/g, '-')}`

  const hasData = data && (Array.isArray(data) ? data.length > 0 : Object.keys(data).length > 0)

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full px-4 py-3 flex items-center justify-between hover:bg-gray-50 transition-colors focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-inset rounded-lg"
        aria-expanded={isOpen}
        aria-controls={`${sectionId}-content`}
        id={`${sectionId}-button`}
      >
        <div className="flex items-center gap-3">
          <span aria-hidden="true">{icon}</span>
          <h3 className="font-semibold text-gray-900">{title}</h3>
          {hasData && (
            <span className="px-2 py-0.5 bg-blue-100 text-blue-700 text-xs font-medium rounded-full" aria-label={`${Array.isArray(data) ? data.length : Object.keys(data).length} items`}>
              {Array.isArray(data) ? data.length : Object.keys(data).length}
            </span>
          )}
        </div>
        <span aria-hidden="true">
          {isOpen ? (
            <ChevronDown className="w-4 h-4 text-gray-500" />
          ) : (
            <ChevronRight className="w-4 h-4 text-gray-500" />
          )}
        </span>
      </button>

      {isOpen && (
        <div
          id={`${sectionId}-content`}
          role="region"
          aria-labelledby={`${sectionId}-button`}
          className="px-4 pb-4 border-t border-gray-100"
        >
          {isLoading ? (
            <p className="text-sm text-gray-700 py-2" role="status" aria-live="polite">
              <span className="sr-only">Loading {title}...</span>
              {t('common.loading')}
            </p>
          ) : !hasData ? (
            <p className="text-sm text-gray-700 py-2">{t('common.noData')}</p>
          ) : (
            <div className="max-h-96 overflow-y-auto mt-3">
              <pre className="text-xs bg-gray-50 p-3 rounded overflow-x-auto" aria-label={`${title} data in JSON format`}>
                {JSON.stringify(data, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export function NetworkAnalysisPanel() {
  const { t } = useTranslation()
  const [activeTab, setActiveTab] = useState<'protocols' | 'ha' | 'network' | 'topology' | 'advanced'>('protocols')

  // OSPF queries
  const ospfProcesses = useOSPFProcesses()
  const ospfAreas = useOSPFAreas()
  const ospfInterfaces = useOSPFInterfaces()
  const ospfSessions = useOSPFSessions()
  const ospfEdges = useOSPFEdges()

  // Network queries
  const nodes = useNodes()
  const interfaces = useInterfaces()
  const routes = useRoutes()
  const vlans = useVlans()
  const ipOwners = useIPOwners()

  // Edge queries
  const physicalEdges = usePhysicalEdges()
  const layer3Edges = useLayer3Edges()

  // High Availability queries
  const vrrpProperties = useVRRPProperties()
  const hsrpProperties = useHSRPProperties()
  const mlagProperties = useMLAGProperties()
  const duplicateRouterIds = useDuplicateRouterIDs()
  const switchingProperties = useSwitchingProperties()

  // Protocols queries
  const bgpEdges = useBGPEdges()
  const bgpProcessConfig = useBGPProcessConfiguration()
  const bgpPeerConfig = useBGPPeerConfiguration()
  const bgpSessionStatus = useBGPSessionStatus()
  const bgpSessionCompat = useBGPSessionCompatibility()
  const bgpRib = useBGPRib()
  const eigrpEdges = useEIGRPEdges()
  const eigrpInterfaces = useEIGRPInterfaces()
  const isisEdges = useISISEdges()
  const isisInterfaces = useISISInterfaces()
  const isisLoopbackInterfaces = useISISLoopbackInterfaces()
  const bfdSessionStatus = useBFDSessionStatus()

  // Topology queries
  const layer1Topology = useLayer1Topology()
  const layer2Topology = useLayer2Topology()
  const vxlanVNI = useVXLANVNIProperties()
  const vxlanEdges = useVXLANEdges()
  const ipsecSessionStatus = useIPSecSessionStatus()
  const ipsecEdges = useIPSecEdges()
  const ipsecPeerConfig = useIPSecPeerConfiguration()

  // Advanced queries
  const f5VIPs = useF5VIPs()
  const viModel = useVIModel()
  const evpnRib = useEVPNRib()
  const interfaceMTU = useInterfaceMTU()
  const ipSpaceAssignment = useIPSpaceAssignment()
  const definedStructures = useDefinedStructures()
  const referencedStructures = useReferencedStructures()
  const namedStructures = useNamedStructures()
  const aaaAuthentication = useAAAAuthentication()
  const routePolicies = useRoutePolicies({})

  /**
   * Tab navigation configuration for analysis categories
   * Five tabs: Protocols (BGP/OSPF/etc), HA (VRRP/HSRP), Network (nodes/routes), Topology (layers/edges), Advanced (F5/structures)
   */
  const tabs = [
    { id: 'protocols' as const, label: t('analysis.tabs.protocols'), icon: Activity },
    { id: 'ha' as const, label: t('analysis.tabs.highAvailability'), icon: Shield },
    { id: 'network' as const, label: t('analysis.tabs.network'), icon: Network },
    { id: 'topology' as const, label: t('analysis.tabs.topology'), icon: Layers },
    { id: 'advanced' as const, label: t('analysis.tabs.advanced'), icon: Server },
  ]

  return (
    <div className="space-y-4" role="region" aria-label="Network analysis">
      <h2 className="text-lg font-semibold text-gray-900">{t('analysis.title')}</h2>

      {/* Tab Navigation */}
      <div className="flex space-x-1 bg-gray-100 p-1 rounded-lg" role="tablist" aria-label="Analysis categories">
        {tabs.map((tab) => {
          const Icon = tab.icon
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              role="tab"
              aria-selected={activeTab === tab.id}
              aria-controls={`analysis-tabpanel-${tab.id}`}
              id={`analysis-tab-${tab.id}`}
              tabIndex={activeTab === tab.id ? 0 : -1}
              className={`flex-1 flex items-center justify-center gap-2 px-3 py-2 rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-inset ${
                activeTab === tab.id
                  ? 'bg-white text-gray-900 font-medium shadow-sm'
                  : 'text-gray-600 hover:text-gray-900'
              }`}
            >
              <Icon className="w-4 h-4" aria-hidden="true" />
              <span className="text-sm">{tab.label}</span>
            </button>
          )
        })}
      </div>

      {/* Tab Content */}
      <div
        className="space-y-3"
        role="tabpanel"
        id={`analysis-tabpanel-${activeTab}`}
        aria-labelledby={`analysis-tab-${activeTab}`}
        tabIndex={0}
      >
        {activeTab === 'ha' && (
          <>
            <Section
              title={t('analysis.sections.vrrpProperties')}
              icon={<Shield className="w-5 h-5 text-blue-600" />}
              isLoading={vrrpProperties.isLoading}
              data={vrrpProperties.data}
              defaultOpen={true}
            />
            <Section
              title={t('analysis.sections.hsrpProperties')}
              icon={<Shield className="w-5 h-5 text-green-600" />}
              isLoading={hsrpProperties.isLoading}
              data={hsrpProperties.data}
            />
            <Section
              title={t('analysis.sections.mlagProperties')}
              icon={<Network className="w-5 h-5 text-purple-600" />}
              isLoading={mlagProperties.isLoading}
              data={mlagProperties.data}
            />
            <Section
              title={t('analysis.sections.duplicateRouterIds')}
              icon={<Shield className="w-5 h-5 text-yellow-600" />}
              isLoading={duplicateRouterIds.isLoading}
              data={duplicateRouterIds.data}
            />
            <Section
              title={t('analysis.sections.switchingProperties')}
              icon={<Network className="w-5 h-5 text-indigo-600" />}
              isLoading={switchingProperties.isLoading}
              data={switchingProperties.data}
            />
          </>
        )}

        {activeTab === 'network' && (
          <>
            <Section
              title={t('analysis.sections.nodes')}
              icon={<Server className="w-5 h-5 text-blue-600" />}
              isLoading={nodes.isLoading}
              data={nodes.data}
              defaultOpen={true}
            />
            <Section
              title={t('analysis.sections.interfaces')}
              icon={<Network className="w-5 h-5 text-green-600" />}
              isLoading={interfaces.isLoading}
              data={interfaces.data}
            />
            <Section
              title={t('analysis.sections.interfaceMTU')}
              icon={<Network className="w-5 h-5 text-blue-500" />}
              isLoading={interfaceMTU.isLoading}
              data={interfaceMTU.data}
            />
            <Section
              title={t('analysis.sections.routes')}
              icon={<GitBranch className="w-5 h-5 text-purple-600" />}
              isLoading={routes.isLoading}
              data={routes.data}
            />
            <Section
              title={t('analysis.sections.vlans')}
              icon={<Network className="w-5 h-5 text-indigo-600" />}
              isLoading={vlans.isLoading}
              data={vlans.data}
            />
            <Section
              title={t('analysis.sections.ipOwners')}
              icon={<Info className="w-5 h-5 text-gray-600" />}
              isLoading={ipOwners.isLoading}
              data={ipOwners.data}
            />
            <Section
              title={t('analysis.sections.ipSpaceAssignment')}
              icon={<Network className="w-5 h-5 text-indigo-500" />}
              isLoading={ipSpaceAssignment.isLoading}
              data={ipSpaceAssignment.data}
            />
          </>
        )}

        {activeTab === 'protocols' && (
          <>
            <Section
              title={t('analysis.sections.bgpEdges')}
              icon={<GitBranch className="w-5 h-5 text-purple-600" />}
              isLoading={bgpEdges.isLoading}
              data={bgpEdges.data}
              defaultOpen={true}
            />
            <Section
              title={t('analysis.sections.bgpProcess')}
              icon={<Server className="w-5 h-5 text-purple-500" />}
              isLoading={bgpProcessConfig.isLoading}
              data={bgpProcessConfig.data}
            />
            <Section
              title={t('analysis.sections.bgpPeerConfiguration')}
              icon={<Network className="w-5 h-5 text-purple-400" />}
              isLoading={bgpPeerConfig.isLoading}
              data={bgpPeerConfig.data}
            />
            <Section
              title={t('analysis.sections.bgpSessionStatus')}
              icon={<Activity className="w-5 h-5 text-purple-600" />}
              isLoading={bgpSessionStatus.isLoading}
              data={bgpSessionStatus.data}
            />
            <Section
              title={t('analysis.sections.bgpSessionCompatibility')}
              icon={<CheckCircle className="w-5 h-5 text-purple-500" />}
              isLoading={bgpSessionCompat.isLoading}
              data={bgpSessionCompat.data}
            />
            <Section
              title={t('analysis.sections.bgpRib')}
              icon={<Info className="w-5 h-5 text-purple-400" />}
              isLoading={bgpRib.isLoading}
              data={bgpRib.data}
            />
            <Section
              title={t('analysis.sections.ospfEdges')}
              icon={<GitBranch className="w-5 h-5 text-green-600" />}
              isLoading={ospfEdges.isLoading}
              data={ospfEdges.data}
            />
            <Section
              title={t('analysis.sections.ospfProcess')}
              icon={<Server className="w-5 h-5 text-green-500" />}
              isLoading={ospfProcesses.isLoading}
              data={ospfProcesses.data}
            />
            <Section
              title={t('analysis.sections.ospfArea')}
              icon={<Network className="w-5 h-5 text-green-400" />}
              isLoading={ospfAreas.isLoading}
              data={ospfAreas.data}
            />
            <Section
              title={t('analysis.sections.ospfInterfaces')}
              icon={<Network className="w-5 h-5 text-green-500" />}
              isLoading={ospfInterfaces.isLoading}
              data={ospfInterfaces.data}
            />
            <Section
              title={t('analysis.sections.ospfSessions')}
              icon={<Activity className="w-5 h-5 text-green-600" />}
              isLoading={ospfSessions.isLoading}
              data={ospfSessions.data}
            />
            <Section
              title={t('analysis.sections.eigrpEdges')}
              icon={<GitBranch className="w-5 h-5 text-orange-600" />}
              isLoading={eigrpEdges.isLoading}
              data={eigrpEdges.data}
            />
            <Section
              title={t('analysis.sections.eigrpInterfaces')}
              icon={<Network className="w-5 h-5 text-orange-500" />}
              isLoading={eigrpInterfaces.isLoading}
              data={eigrpInterfaces.data}
            />
            <Section
              title={t('analysis.sections.isisEdges')}
              icon={<GitBranch className="w-5 h-5 text-teal-600" />}
              isLoading={isisEdges.isLoading}
              data={isisEdges.data}
            />
            <Section
              title={t('analysis.sections.isisInterfaces')}
              icon={<Network className="w-5 h-5 text-teal-500" />}
              isLoading={isisInterfaces.isLoading}
              data={isisInterfaces.data}
            />
            <Section
              title={t('analysis.sections.isisLoopbackInterfaces')}
              icon={<Network className="w-5 h-5 text-teal-400" />}
              isLoading={isisLoopbackInterfaces.isLoading}
              data={isisLoopbackInterfaces.data}
            />
            <Section
              title={t('analysis.sections.bfdSessionStatus')}
              icon={<Activity className="w-5 h-5 text-blue-600" />}
              isLoading={bfdSessionStatus.isLoading}
              data={bfdSessionStatus.data}
            />
            <Section
              title={t('analysis.sections.evpnRib')}
              icon={<Info className="w-5 h-5 text-cyan-600" />}
              isLoading={evpnRib.isLoading}
              data={evpnRib.data}
            />
          </>
        )}

        {activeTab === 'topology' && (
          <>
            <Section
              title={t('analysis.sections.layer1Topology')}
              icon={<Layers className="w-5 h-5 text-gray-600" />}
              isLoading={layer1Topology.isLoading}
              data={layer1Topology.data}
              defaultOpen={true}
            />
            <Section
              title={t('analysis.sections.layer2Topology')}
              icon={<Layers className="w-5 h-5 text-blue-600" />}
              isLoading={layer2Topology.isLoading}
              data={layer2Topology.data}
            />
            <Section
              title={t('analysis.sections.physicalEdges')}
              icon={<GitBranch className="w-5 h-5 text-gray-500" />}
              isLoading={physicalEdges.isLoading}
              data={physicalEdges.data}
            />
            <Section
              title={t('analysis.sections.layer3Edges')}
              icon={<GitBranch className="w-5 h-5 text-blue-500" />}
              isLoading={layer3Edges.isLoading}
              data={layer3Edges.data}
            />
            <Section
              title={t('analysis.sections.vxlanVniProperties')}
              icon={<Network className="w-5 h-5 text-purple-600" />}
              isLoading={vxlanVNI.isLoading}
              data={vxlanVNI.data}
            />
            <Section
              title={t('analysis.sections.vxlanEdges')}
              icon={<GitBranch className="w-5 h-5 text-purple-500" />}
              isLoading={vxlanEdges.isLoading}
              data={vxlanEdges.data}
            />
            <Section
              title={t('analysis.sections.ipsecSessionStatus')}
              icon={<Lock className="w-5 h-5 text-green-600" />}
              isLoading={ipsecSessionStatus.isLoading}
              data={ipsecSessionStatus.data}
            />
            <Section
              title={t('analysis.sections.ipsecEdges')}
              icon={<Lock className="w-5 h-5 text-green-500" />}
              isLoading={ipsecEdges.isLoading}
              data={ipsecEdges.data}
            />
            <Section
              title={t('analysis.sections.ipsecPeerConfiguration')}
              icon={<Lock className="w-5 h-5 text-green-700" />}
              isLoading={ipsecPeerConfig.isLoading}
              data={ipsecPeerConfig.data}
            />
          </>
        )}

        {activeTab === 'advanced' && (
          <>
            <Section
              title={t('analysis.sections.f5Vips')}
              icon={<Server className="w-5 h-5 text-blue-600" />}
              isLoading={f5VIPs.isLoading}
              data={f5VIPs.data}
              defaultOpen={true}
            />
            <Section
              title={t('analysis.sections.viModel')}
              icon={<Info className="w-5 h-5 text-gray-600" />}
              isLoading={viModel.isLoading}
              data={viModel.data}
            />
            <Section
              title={t('analysis.sections.definedStructures')}
              icon={<FileText className="w-5 h-5 text-blue-600" />}
              isLoading={definedStructures.isLoading}
              data={definedStructures.data}
            />
            <Section
              title={t('analysis.sections.referencedStructures')}
              icon={<FileText className="w-5 h-5 text-green-600" />}
              isLoading={referencedStructures.isLoading}
              data={referencedStructures.data}
            />
            <Section
              title={t('analysis.sections.namedStructures')}
              icon={<FileText className="w-5 h-5 text-purple-600" />}
              isLoading={namedStructures.isLoading}
              data={namedStructures.data}
            />
            <Section
              title={t('analysis.sections.aaaAuthentication')}
              icon={<Lock className="w-5 h-5 text-yellow-600" />}
              isLoading={aaaAuthentication.isLoading}
              data={aaaAuthentication.data}
            />
            <Section
              title={t('analysis.sections.routePolicies')}
              icon={<GitBranch className="w-5 h-5 text-indigo-600" />}
              isLoading={routePolicies.isLoading}
              data={routePolicies.data}
            />
          </>
        )}
      </div>
    </div>
  )
}

export default NetworkAnalysisPanel