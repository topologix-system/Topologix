/**
 * Network overview dashboard with key statistics and summaries
 * - Statistics cards: node count, interface count, route count, issue count
 * - OSPF summary: processes, areas, interfaces, sessions
 * - BGP summary: peers, processes, sessions, RIB entries
 * - Validation warnings: init issues, parse warnings, unused/undefined structures, forwarding loops
 * - Quick health check view for snapshot assessment
 */
import { useTranslation } from 'react-i18next'
import { useAllNetworkData, useUnusedStructures, useUndefinedReferences, useForwardingLoops } from '../../hooks'
import { Server, Link, GitBranch, AlertTriangle } from 'lucide-react'
import { ParseResultSummaryCard } from '../validation/ParseResultDetails'
import { buildFileParseStatusView, buildParseResultSummary } from '../../lib/validation/parseResult'

export function OverviewPanel() {
  const { t } = useTranslation()
  const { data, isLoading } = useAllNetworkData()
  const { data: unusedStructures } = useUnusedStructures()
  const { data: undefinedRefs } = useUndefinedReferences()
  const { data: forwardingLoops } = useForwardingLoops()

  if (isLoading) {
    return (
      <div role="status" aria-live="polite">
        <span className="sr-only">{t('overview.loading')}</span>
        {t('common.loading')}
      </div>
    )
  }

  if (!data) {
    return (
      <div role="status">
        <p className="text-gray-700">{t('overview.noData')}</p>
      </div>
    )
  }

  /**
   * Calculate total issue count across all validation categories
   * Includes: init issues, parse warnings, unused structures, undefined references, forwarding loops
   */
  const issueCount =
    data.init_issues.length +
    data.parse_warnings.length +
    (unusedStructures?.length || 0) +
    (undefinedRefs?.length || 0) +
    (forwardingLoops?.length || 0)
  const parseResultSummary = buildParseResultSummary(
    data.file_parse_status,
    data.init_issues,
    data.parse_warnings
  )
  const abnormalParseFiles = buildFileParseStatusView(
    data.file_parse_status,
    data.init_issues,
    data.parse_warnings
  )
    .filter((file) => file.statusBucket !== 'passed' || file.relatedIssueCount > 0 || file.relatedWarningCount > 0)
    .slice(0, 5)

  /**
   * Statistics card configuration for overview dashboard
   * Four key metrics: node count, interface count, route count, total issues
   */
  const stats = [
    {
      label: t('overview.stats.nodes'),
      value: data.node_properties.length,
      icon: <Server className="w-5 h-5 text-primary-600" />,
    },
    {
      label: t('overview.stats.interfaces'),
      value: data.interface_properties.length,
      icon: <Link className="w-5 h-5 text-green-600" />,
    },
    {
      label: t('overview.stats.routes'),
      value: data.routes.length,
      icon: <GitBranch className="w-5 h-5 text-blue-600" />,
    },
    {
      label: t('overview.stats.issues'),
      value: issueCount,
      icon: <AlertTriangle className="w-5 h-5 text-yellow-600" />,
    },
  ]

  return (
    <div className="space-y-4" role="region" aria-label={t('overview.title')}>
      <h2 className="text-lg font-semibold text-gray-900">{t('overview.title')}</h2>

      {/* Statistics Cards */}
      <div className="grid grid-cols-2 gap-4" role="list" aria-label="Network statistics">
        {stats.map((stat) => (
          <div key={stat.label} className="bg-gray-50 rounded-lg p-4" role="listitem">
            <div className="flex items-center gap-2 mb-2" aria-hidden="true">{stat.icon}</div>
            <div className="text-2xl font-bold text-gray-900" aria-label={`${stat.value} ${stat.label}`}>
              {stat.value}
            </div>
            <div className="text-sm text-gray-700">{stat.label}</div>
          </div>
        ))}
      </div>

      {/* OSPF Summary */}
      <div className="bg-gray-50 rounded-lg p-4">
        <h3 className="font-medium text-gray-900 mb-2">{t('overview.ospf.title')}</h3>
        <div className="space-y-1 text-sm">
          <div className="flex justify-between">
            <span className="text-gray-700">{t('overview.ospf.processes')}:</span>
            <span className="font-medium">{data.ospf_process_configuration.length}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-700">{t('overview.ospf.areas')}:</span>
            <span className="font-medium">{data.ospf_area_configuration.length}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-700">{t('overview.ospf.sessions')}:</span>
            <span className="font-medium">{data.ospf_session_compatibility.length}</span>
          </div>
        </div>
      </div>

      {/* BGP Summary */}
      <div className="bg-gray-50 rounded-lg p-4">
        <h3 className="font-medium text-gray-900 mb-2">{t('overview.bgp.title')}</h3>
        <div className="space-y-1 text-sm">
          <div className="flex justify-between">
            <span className="text-gray-700">{t('overview.bgp.processes')}:</span>
            <span className="font-medium">{data.bgp_process_configuration.length}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-700">{t('overview.bgp.peers')}:</span>
            <span className="font-medium">{data.bgp_peer_configuration.length}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-700">{t('overview.bgp.sessions')}:</span>
            <span className="font-medium">{data.bgp_session_status.length}</span>
          </div>
        </div>
      </div>

      {/* IPsec Summary */}
      {data.ipsec_edges && data.ipsec_edges.length > 0 && (
        <div className="bg-gray-50 rounded-lg p-4">
          <h3 className="font-medium text-gray-900 mb-2">{t('overview.ipsec.title')}</h3>
          <div className="space-y-1 text-sm">
            <div className="flex justify-between">
              <span className="text-gray-700">{t('overview.ipsec.edges')}:</span>
              <span className="font-medium">{data.ipsec_edges.length}</span>
            </div>
          </div>
        </div>
      )}

      {/* EIGRP Summary - Only show if data exists */}
      {data.eigrp_edges && data.eigrp_edges.length > 0 && (
        <div className="bg-gray-50 rounded-lg p-4">
          <h3 className="font-medium text-gray-900 mb-2">{t('overview.eigrp.title')}</h3>
          <div className="space-y-1 text-sm">
            <div className="flex justify-between">
              <span className="text-gray-700">{t('overview.eigrp.edges')}:</span>
              <span className="font-medium">{data.eigrp_edges.length}</span>
            </div>
          </div>
        </div>
      )}

      {/* IS-IS Summary - Only show if data exists */}
      {data.isis_edges && data.isis_edges.length > 0 && (
        <div className="bg-gray-50 rounded-lg p-4">
          <h3 className="font-medium text-gray-900 mb-2">{t('overview.isis.title')}</h3>
          <div className="space-y-1 text-sm">
            <div className="flex justify-between">
              <span className="text-gray-700">{t('overview.isis.edges')}:</span>
              <span className="font-medium">{data.isis_edges.length}</span>
            </div>
          </div>
        </div>
      )}

      {/* Configuration parsing summary */}
      <div className="space-y-3">
        <ParseResultSummaryCard
          title={t('overview.configFiles.title')}
          subtitle={t('overview.configFiles.summaryHelp')}
          summary={parseResultSummary}
          compact
        />
        {abnormalParseFiles.length > 0 && (
          <div className="rounded-lg bg-gray-50 p-4">
            <h3 className="font-medium text-gray-900 mb-2">{t('overview.configFiles.abnormalTitle')}</h3>
            <div className="space-y-2">
              {abnormalParseFiles.map((file) => (
                <div key={file.file_name} className="flex items-center justify-between gap-3 text-sm">
                  <span className="min-w-0 flex-1 truncate text-gray-700">{file.file_name}</span>
                  <span className="rounded bg-white px-2 py-1 text-xs font-medium text-gray-700">
                    {file.status || t('common.unknown')}
                  </span>
                  <span className="whitespace-nowrap text-xs text-gray-600">
                    {t('overview.configFiles.relatedCounts', {
                      warnings: file.relatedWarningCount,
                      issues: file.relatedIssueCount,
                    })}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default OverviewPanel
