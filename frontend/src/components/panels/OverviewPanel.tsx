/**
 * Network overview dashboard with key statistics and summaries
 */
import { useTranslation } from 'react-i18next'
import { useQueryClient } from '@tanstack/react-query'
import {
  useActivateSnapshot,
  useAllNetworkData,
  useUnusedStructures,
  useUndefinedReferences,
  useForwardingLoops,
  useSnapshotVersionState,
  resolveNetworkKey,
  getVersioningUnavailableReason,
} from '../../hooks'
import { Server, Link, GitBranch, AlertTriangle, RefreshCw } from 'lucide-react'
import { ParseResultSummaryCard } from '../validation/ParseResultDetails'
import { buildFileParseStatusView, buildParseResultSummary } from '../../lib/validation/parseResult'
import { useSnapshotStore } from '../../store'
import type { AllNetworkData, SnapshotVersionState } from '../../types'
import {
  hashKeyedErrorText,
  joinLabels,
  shortContentHash,
  versionAuthorLabel,
  versionKindBadgeClass,
  versionKindLabel,
  versionMessageLabel,
  versionRefLabel,
  versioningReasonLabel,
} from '../snapshotVersionLabels'

interface SnapshotVersionSummaryProps {
  snapshotName: string
  networkData: AllNetworkData | undefined
  networkUpdating: boolean
  mismatchText: string | null
}

function SnapshotVersionLine({
  snapshotName,
  state,
  lastKnown,
}: {
  snapshotName: string
  state: SnapshotVersionState
  lastKnown: boolean
}) {
  const { t } = useTranslation()
  const head = state.head
  const workingStates = [
    state.uncommitted ? t('overview.version.uncommitted') : null,
    state.pending_external ? t('overview.version.pendingExternal') : null,
    state.external_settling ? t('overview.version.settling') : null,
    state.restored_from
      ? t('overview.version.workingRestoredFrom', { version: versionRefLabel(t, state.restored_from) })
      : null,
  ].filter((label): label is string => label !== null)

  return (
    <div className="rounded-lg border border-gray-200 bg-gray-50 p-3 text-sm" aria-label={t('overview.version.title')}>
      {lastKnown && (
        <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-gray-600">
          {t('overview.version.lastKnown')}
        </p>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-semibold text-gray-900">{snapshotName}</span>
        {head ? (
          <span className="font-mono font-medium text-gray-900">
            {t('overview.version.versionLabel', { seq: head.seq })}
          </span>
        ) : (
          <span className="text-gray-700">{t('overview.version.noVersions')}</span>
        )}
        {state.content_hash && (
          <span className="font-mono text-xs text-gray-600" title={state.content_hash}>
            {t('overview.version.shortHash', { hash: shortContentHash(state.content_hash) })}
          </span>
        )}
        {head && (
          <span className={`rounded border px-1.5 py-0.5 text-xs font-medium ${versionKindBadgeClass[head.kind]}`}>
            {versionKindLabel(t, head.kind)}
          </span>
        )}
      </div>
      {head && (
        <>
          <p className="mt-1 break-words font-medium text-gray-900">{versionMessageLabel(t, head)}</p>
          <p className="text-xs text-gray-600">
            {t('overview.version.headMeta', {
              author: versionAuthorLabel(t, head),
              time: new Date(head.created_at).toLocaleString(),
            })}
          </p>
        </>
      )}
      {head && (head.parent || (head.kind === 'restore' && head.restored_from)) && (
        <p className="mt-1 text-xs text-gray-600">
          {joinLabels(t, [
            head.parent && t('overview.version.basedOn', { version: versionRefLabel(t, head.parent) }),
            head.kind === 'restore' && head.restored_from &&
              t('overview.version.headRestoredFrom', { version: versionRefLabel(t, head.restored_from) }),
          ])}
        </p>
      )}
      {workingStates.length > 0 && (
        <ul className="mt-2 flex flex-wrap gap-2" aria-label={t('overview.version.workingStateLabel')}>
          {workingStates.map((label) => (
            <li key={label} className="rounded bg-yellow-100 px-2 py-0.5 text-xs font-medium text-yellow-900">
              {label}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function SnapshotVersionSummary({ snapshotName, networkData, networkUpdating, mismatchText }: SnapshotVersionSummaryProps) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const versionState = useSnapshotVersionState(snapshotName)
  const activateMutation = useActivateSnapshot()
  const isSnapshotActivationInProgress = useSnapshotStore((state) => state.isSnapshotActivationInProgress)
  const reloadPending = isSnapshotActivationInProgress || activateMutation.isPending
  const noData = resolveNetworkKey(queryClient, snapshotName, versionState).status === 'no-data'
  const state = versionState.data
  const reloadSnapshot = () => {
    if (reloadPending) return
    activateMutation.mutate(snapshotName)
  }

  const effectiveHash = networkData
    ? networkData.snapshot_version?.content_hash ?? networkData.snapshot_version?.live_hash ?? null
    : undefined
  const showStaleWarning =
    versionState.isSuccess &&
    !!state &&
    networkData !== undefined &&
    !networkUpdating &&
    (effectiveHash === null || effectiveHash !== state.content_hash)
  const showStagingNotice = versionState.isSuccess && !!state?.loaded_live
  const unavailableReason = versionState.isError ? getVersioningUnavailableReason(versionState.error) : null

  const reloadButton = (
    <button
      type="button"
      onClick={reloadSnapshot}
      disabled={reloadPending}
      className="mt-2 inline-flex items-center gap-2 rounded-md border border-yellow-300 bg-white px-3 py-1.5 text-xs font-semibold text-yellow-900 transition-colors hover:bg-yellow-100 focus:outline-none focus:ring-2 focus:ring-yellow-600 focus:ring-offset-1 disabled:cursor-not-allowed disabled:opacity-50"
    >
      <RefreshCw className={`h-3.5 w-3.5 ${reloadPending ? 'animate-spin' : ''}`} aria-hidden="true" />
      {t('overview.version.reload')}
    </button>
  )

  return (
    <div className="space-y-2">
      {versionState.isError && (
        <div className="rounded-lg border border-yellow-200 bg-yellow-50 p-3 text-sm text-yellow-900" role="status">
          {unavailableReason
            ? t('overview.version.unavailableWithReason', { reason: versioningReasonLabel(t, unavailableReason) })
            : t('overview.version.unavailable')}
        </div>
      )}
      {state && !noData && (versionState.isSuccess || versionState.isError) && (
        <SnapshotVersionLine snapshotName={snapshotName} state={state} lastKnown={versionState.isError} />
      )}
      {networkUpdating && (
        <p className="text-xs font-medium text-blue-700" role="status" aria-live="polite">
          {t('overview.version.updating')}
        </p>
      )}
      {showStagingNotice && (
        <div className="rounded-lg border border-yellow-200 bg-yellow-50 p-3 text-sm text-yellow-900" role="status">
          {t('overview.version.stagingUnavailable')}
        </div>
      )}
      {showStaleWarning && (
        <div className="rounded-lg border border-yellow-200 bg-yellow-50 p-3 text-sm text-yellow-900" role="alert">
          <p>{t('overview.version.staleTopology')}</p>
          {reloadButton}
        </div>
      )}
      {mismatchText && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-800" role="alert">
          <p>{mismatchText}</p>
          {reloadButton}
        </div>
      )}
    </div>
  )
}

export function OverviewPanel() {
  const { t } = useTranslation()
  const currentSnapshotName = useSnapshotStore((state) => state.currentSnapshotName)
  const hasActiveSnapshot = Boolean(currentSnapshotName)
  const { data, isLoading, isFetching, isPlaceholderData, error } = useAllNetworkData(hasActiveSnapshot)
  const { data: unusedStructures } = useUnusedStructures(hasActiveSnapshot)
  const { data: undefinedRefs } = useUndefinedReferences(hasActiveSnapshot)
  const { data: forwardingLoops } = useForwardingLoops(hasActiveSnapshot)

  if (!hasActiveSnapshot || !currentSnapshotName) {
    return (
      <div className="space-y-3" role="status" aria-live="polite">
        <h2 className="text-lg font-semibold text-gray-900">{t('overview.title')}</h2>
        <p className="text-sm text-gray-700">{t('overview.noActiveSnapshot')}</p>
      </div>
    )
  }

  const versionSummary = (
    <SnapshotVersionSummary
      snapshotName={currentSnapshotName}
      networkData={data}
      networkUpdating={isFetching || isPlaceholderData}
      mismatchText={hashKeyedErrorText(t, error)}
    />
  )

  if (isLoading) {
    return (
      <div className="space-y-4" role="region" aria-label={t('overview.title')}>
        <h2 className="text-lg font-semibold text-gray-900">{t('overview.title')}</h2>
        {versionSummary}
        <div role="status" aria-live="polite">
          <span className="sr-only">{t('overview.loading')}</span>
          {t('common.loading')}
        </div>
      </div>
    )
  }

  if (!data) {
    return (
      <div className="space-y-4" role="region" aria-label={t('overview.title')}>
        <h2 className="text-lg font-semibold text-gray-900">{t('overview.title')}</h2>
        {versionSummary}
        <div role="status">
          <p className="text-gray-700">{t('overview.noData')}</p>
        </div>
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
  const aggregateQueryErrors = data.query_errors ?? []
  const bgpQueryErrors = aggregateQueryErrors.filter((queryError) =>
    queryError.data_key === 'search_route_policies' || queryError.data_key.startsWith('bgp_')
  )

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

      {versionSummary}

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

      {bgpQueryErrors.length > 0 && (
        <div className="rounded-lg border border-yellow-200 bg-yellow-50 p-4 text-sm text-yellow-900" role="status">
          <h3 className="font-medium">{t('overview.partialData.title')}</h3>
          <p className="mt-1">{t('overview.partialData.description', { count: bgpQueryErrors.length })}</p>
          <ul className="mt-2 list-disc space-y-1 pl-5 text-xs">
            {bgpQueryErrors.slice(0, 3).map((queryError) => (
              <li key={`${queryError.data_key}-${queryError.code}`}>
                {queryError.data_key}: {queryError.code}
              </li>
            ))}
          </ul>
        </div>
      )}

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
