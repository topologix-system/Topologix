/**
 * Snapshot Comparison Page
 * Displays differential analysis between two network snapshots
 * Shows changes in nodes, topology (edges), routing tables, and reachability
 */
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { ArrowLeft, GitCompare, Loader2 } from 'lucide-react'

import { useSnapshots, useCompareSnapshots } from '../hooks'
import type { ComparisonResult } from '../types'
import { extractErrorMessage } from '../types/errors'

/**
 * Display text for a modified route's next hops: every ECMP next hop when the list is present
 */
function formatNextHops(nextHops: string[] | undefined, nextHop: string | undefined) {
  return nextHops && nextHops.length > 0 ? nextHops.join(', ') : (nextHop ?? '')
}

export function SnapshotComparison() {
  const { t } = useTranslation()
  const [baseSnapshot, setBaseSnapshot] = useState<string>('')
  const [comparisonSnapshot, setComparisonSnapshot] = useState<string>('')
  const [activeTab, setActiveTab] = useState<'nodes' | 'topology' | 'routes' | 'reachability'>('nodes')
  const [comparisonResult, setComparisonResult] = useState<ComparisonResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  /**
   * Fetch available snapshots for selection dropdowns
   */
  const { data: snapshots, isLoading: loadingSnapshots } = useSnapshots()

  /**
   * React Query mutation for snapshot comparison
   */
  const compareMutation = useCompareSnapshots()

  /**
   * Handle comparison execution
   * Validates snapshot selection and triggers comparison API call
   */
  const handleCompare = () => {
    setComparisonResult(null)

    if (!baseSnapshot || !comparisonSnapshot) {
      setError(t('comparison.errors.selectBoth'))
      return
    }

    if (baseSnapshot === comparisonSnapshot) {
      setError(t('comparison.errors.selectDifferent'))
      return
    }

    setError(null)
    compareMutation.mutate(
      {
        base_snapshot: baseSnapshot,
        comparison_snapshot: comparisonSnapshot,
      },
      {
        onSuccess: (data) => {
          setComparisonResult(data)
        },
        onError: (err: unknown) => {
          setComparisonResult(null)
          setError(
            t('comparison.errors.comparisonFailed', {
              message: extractErrorMessage(err, t('comparison.errors.unknown')),
            })
          )
        },
      }
    )
  }

  /**
   * Calculate summary statistics from comparison result
   */
  const getSummary = () => {
    if (!comparisonResult) return null

    return {
      nodes_added: comparisonResult.nodes.added.length,
      nodes_removed: comparisonResult.nodes.removed.length,
      edges_added: comparisonResult.edges.added.length,
      edges_removed: comparisonResult.edges.removed.length,
      routes_added: comparisonResult.routes.added.length,
      routes_removed: comparisonResult.routes.removed.length,
      routes_modified: comparisonResult.routes.modified.length,
      reachability_changes: comparisonResult.reachability.length,
    }
  }

  const summary = getSummary()
  const reachabilityError = comparisonResult?.reachability_error ?? null

  return (
    <div className="flex flex-col h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b border-gray-200 px-6 py-4" role="banner">
        <div className="flex items-center gap-4">
          <Link
            to="/"
            className="p-2 hover:bg-gray-100 rounded-lg transition-colors focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-2"
            aria-label={t('comparison.backToTopologyAria')}
          >
            <ArrowLeft className="w-5 h-5" aria-hidden="true" />
            <span className="sr-only">{t('snapshots.backToTopology')}</span>
          </Link>
          <h1 className="text-2xl font-bold text-gray-900">{t('comparison.title')}</h1>
        </div>
      </header>

      {/* Main content */}
      <div className="flex-1 overflow-y-auto p-6">
        {/* Snapshot selection */}
        <div className="bg-white rounded-lg shadow p-6 mb-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">{t('comparison.selectSnapshots')}</h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            {/* Base snapshot selector */}
            <div>
              <label htmlFor="base-snapshot" className="block text-sm font-medium text-gray-800 mb-2">
                {t('comparison.baseSnapshot')}
              </label>
              <select
                id="base-snapshot"
                value={baseSnapshot}
                onChange={(e) => setBaseSnapshot(e.target.value)}
                disabled={loadingSnapshots || compareMutation.isPending}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-600 disabled:opacity-50 disabled:cursor-not-allowed"
                aria-label={t('comparison.selectBaseAria')}
              >
                <option value="">{t('comparison.selectBase')}</option>
                {snapshots?.map((snapshot) => (
                  <option key={snapshot.name} value={snapshot.name}>
                    {snapshot.folder_name ? `${snapshot.folder_name} / ` : ''}{snapshot.name}
                  </option>
                ))}
              </select>
            </div>

            {/* Comparison snapshot selector */}
            <div>
              <label htmlFor="comparison-snapshot" className="block text-sm font-medium text-gray-800 mb-2">
                {t('comparison.comparisonSnapshot')}
              </label>
              <select
                id="comparison-snapshot"
                value={comparisonSnapshot}
                onChange={(e) => setComparisonSnapshot(e.target.value)}
                disabled={loadingSnapshots || compareMutation.isPending}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-600 disabled:opacity-50 disabled:cursor-not-allowed"
                aria-label={t('comparison.selectComparisonAria')}
              >
                <option value="">{t('comparison.selectComparison')}</option>
                {snapshots?.map((snapshot) => (
                  <option key={snapshot.name} value={snapshot.name}>
                    {snapshot.folder_name ? `${snapshot.folder_name} / ` : ''}{snapshot.name}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Compare button */}
          <button
            onClick={handleCompare}
            disabled={!baseSnapshot || !comparisonSnapshot || compareMutation.isPending}
            className="flex items-center gap-2 px-6 py-2.5 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors font-medium shadow-sm hover:shadow-md focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-2"
            aria-label={t('comparison.compareAria')}
            aria-busy={compareMutation.isPending}
          >
            {compareMutation.isPending ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" />
                {t('comparison.comparing')}
              </>
            ) : (
              <>
                <GitCompare className="w-4 h-4" aria-hidden="true" />
                {t('comparison.compareButton')}
              </>
            )}
          </button>
        </div>

        {error && (
          <div className="text-red-600 text-sm mt-2" role="alert">{error}</div>
        )}

        {/* Comparison results */}
        {comparisonResult && summary && (
          <div className="space-y-6">
            {/* Summary cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="bg-white rounded-lg shadow p-4">
                <h3 className="text-sm font-medium text-gray-700 mb-2">{t('comparison.summary.nodeChanges')}</h3>
                <div className="space-y-1">
                  <p className="text-sm">
                    <span className="text-green-600 font-semibold">+{summary.nodes_added}</span> {t('comparison.summary.added')}
                  </p>
                  <p className="text-sm">
                    <span className="text-red-600 font-semibold">-{summary.nodes_removed}</span> {t('comparison.summary.removed')}
                  </p>
                </div>
              </div>

              <div className="bg-white rounded-lg shadow p-4">
                <h3 className="text-sm font-medium text-gray-700 mb-2">{t('comparison.summary.topologyChanges')}</h3>
                <div className="space-y-1">
                  <p className="text-sm">
                    <span className="text-green-600 font-semibold">+{summary.edges_added}</span> {t('comparison.summary.added')}
                  </p>
                  <p className="text-sm">
                    <span className="text-red-600 font-semibold">-{summary.edges_removed}</span> {t('comparison.summary.removed')}
                  </p>
                </div>
              </div>

              <div className="bg-white rounded-lg shadow p-4">
                <h3 className="text-sm font-medium text-gray-700 mb-2">{t('comparison.summary.routeChanges')}</h3>
                <div className="space-y-1">
                  <p className="text-sm">
                    <span className="text-green-600 font-semibold">+{summary.routes_added}</span> {t('comparison.summary.added')}
                  </p>
                  <p className="text-sm">
                    <span className="text-red-600 font-semibold">-{summary.routes_removed}</span> {t('comparison.summary.removed')}
                  </p>
                  <p className="text-sm">
                    <span className="text-yellow-600 font-semibold">~{summary.routes_modified}</span> {t('comparison.summary.modified')}
                  </p>
                </div>
              </div>

              <div className="bg-white rounded-lg shadow p-4">
                <h3 className="text-sm font-medium text-gray-700 mb-2">{t('comparison.summary.reachability')}</h3>
                {reachabilityError ? (
                  <>
                    <p className="text-2xl font-bold text-gray-900">{t('common.notAvailable')}</p>
                    <p className="text-xs text-gray-600 mt-1">{t('comparison.summary.notComputed')}</p>
                  </>
                ) : (
                  <>
                    <p className="text-2xl font-bold text-gray-900">{summary.reachability_changes}</p>
                    <p className="text-xs text-gray-600 mt-1">{t('comparison.summary.changesDetected')}</p>
                  </>
                )}
              </div>
            </div>

            {/* Tabs */}
            <div className="bg-white rounded-lg shadow">
              <div className="border-b border-gray-200">
                <nav className="flex -mb-px" aria-label={t('comparison.tabsAria')}>
                  {[
                    { id: 'nodes', label: t('comparison.tabs.nodes') },
                    { id: 'topology', label: t('comparison.tabs.topology') },
                    { id: 'routes', label: t('comparison.tabs.routes') },
                    { id: 'reachability', label: t('comparison.tabs.reachability') },
                  ].map((tab) => (
                    <button
                      key={tab.id}
                      onClick={() => setActiveTab(tab.id as typeof activeTab)}
                      className={`px-6 py-3 text-sm font-medium border-b-2 transition-colors focus:outline-none focus:ring-2 focus:ring-inset focus:ring-primary-600 ${
                        activeTab === tab.id
                          ? 'border-blue-600 text-blue-600'
                          : 'border-transparent text-gray-700 hover:text-gray-900 hover:border-gray-300'
                      }`}
                      aria-current={activeTab === tab.id ? 'page' : undefined}
                    >
                      {tab.label}
                    </button>
                  ))}
                </nav>
              </div>

              {/* Tab content */}
              <div className="p-6">
                {activeTab === 'nodes' && (
                  <div className="space-y-4">
                    <h3 className="text-lg font-semibold text-gray-900">{t('comparison.nodes.title')}</h3>

                    {summary.nodes_added > 0 && (
                      <div>
                        <h4 className="text-sm font-medium text-green-700 mb-2">{t('comparison.nodes.addedNodes', { count: summary.nodes_added })}</h4>
                        <div className="bg-green-50 border border-green-200 rounded-lg p-3">
                          <ul className="space-y-1">
                            {comparisonResult.nodes.added.map((node) => (
                              <li key={node} className="text-sm text-gray-900 font-mono">
                                + {node}
                              </li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    )}

                    {summary.nodes_removed > 0 && (
                      <div>
                        <h4 className="text-sm font-medium text-red-700 mb-2">{t('comparison.nodes.removedNodes', { count: summary.nodes_removed })}</h4>
                        <div className="bg-red-50 border border-red-200 rounded-lg p-3">
                          <ul className="space-y-1">
                            {comparisonResult.nodes.removed.map((node) => (
                              <li key={node} className="text-sm text-gray-900 font-mono">
                                - {node}
                              </li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    )}

                    {summary.nodes_added === 0 && summary.nodes_removed === 0 && (
                      <p className="text-gray-700">{t('comparison.nodes.noChanges')}</p>
                    )}
                  </div>
                )}

                {activeTab === 'topology' && (
                  <div className="space-y-4">
                    <h3 className="text-lg font-semibold text-gray-900">{t('comparison.topology.title')}</h3>

                    {summary.edges_added > 0 && (
                      <div>
                        <h4 className="text-sm font-medium text-green-700 mb-2">{t('comparison.topology.addedEdges', { count: summary.edges_added })}</h4>
                        <div className="bg-green-50 border border-green-200 rounded-lg p-3">
                          <ul className="space-y-2">
                            {comparisonResult.edges.added.map((edge, idx) => (
                              <li key={idx} className="text-sm text-gray-900">
                                + <span className="font-mono">{edge.source}</span>
                                {edge.source_interface && <span className="text-gray-700"> ({edge.source_interface})</span>}
                                {' → '}
                                <span className="font-mono">{edge.target}</span>
                                {edge.target_interface && <span className="text-gray-700"> ({edge.target_interface})</span>}
                              </li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    )}

                    {summary.edges_removed > 0 && (
                      <div>
                        <h4 className="text-sm font-medium text-red-700 mb-2">{t('comparison.topology.removedEdges', { count: summary.edges_removed })}</h4>
                        <div className="bg-red-50 border border-red-200 rounded-lg p-3">
                          <ul className="space-y-2">
                            {comparisonResult.edges.removed.map((edge, idx) => (
                              <li key={idx} className="text-sm text-gray-900">
                                - <span className="font-mono">{edge.source}</span>
                                {edge.source_interface && <span className="text-gray-700"> ({edge.source_interface})</span>}
                                {' → '}
                                <span className="font-mono">{edge.target}</span>
                                {edge.target_interface && <span className="text-gray-700"> ({edge.target_interface})</span>}
                              </li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    )}

                    {summary.edges_added === 0 && summary.edges_removed === 0 && (
                      <p className="text-gray-700">{t('comparison.topology.noChanges')}</p>
                    )}
                  </div>
                )}

                {activeTab === 'routes' && (
                  <div className="space-y-4">
                    <h3 className="text-lg font-semibold text-gray-900">{t('comparison.routes.title')}</h3>

                    {summary.routes_added > 0 && (
                      <div>
                        <h4 className="text-sm font-medium text-green-700 mb-2">{t('comparison.routes.addedRoutes', { count: summary.routes_added })}</h4>
                        <div className="bg-green-50 border border-green-200 rounded-lg p-3 overflow-x-auto">
                          <table className="min-w-full text-sm">
                            <thead>
                              <tr className="border-b border-green-300">
                                <th className="text-left py-2 px-2 font-semibold text-gray-900">{t('comparison.routes.fields.node')}</th>
                                <th className="text-left py-2 px-2 font-semibold text-gray-900">{t('comparison.routes.fields.vrf')}</th>
                                <th className="text-left py-2 px-2 font-semibold text-gray-900">{t('comparison.routes.fields.network')}</th>
                                <th className="text-left py-2 px-2 font-semibold text-gray-900">{t('comparison.routes.fields.nextHop')}</th>
                                <th className="text-left py-2 px-2 font-semibold text-gray-900">{t('comparison.routes.fields.protocol')}</th>
                              </tr>
                            </thead>
                            <tbody>
                              {comparisonResult.routes.added.map((route, idx) => (
                                <tr key={idx} className="border-b border-green-200 last:border-0">
                                  <td className="py-2 px-2 font-mono text-gray-900">{route.node}</td>
                                  <td className="py-2 px-2 text-gray-900">{route.vrf}</td>
                                  <td className="py-2 px-2 font-mono text-gray-900">{route.network}</td>
                                  <td className="py-2 px-2 font-mono text-gray-800">{route.next_hop || '-'}</td>
                                  <td className="py-2 px-2 text-gray-800">{route.protocol || '-'}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}

                    {summary.routes_removed > 0 && (
                      <div>
                        <h4 className="text-sm font-medium text-red-700 mb-2">{t('comparison.routes.removedRoutes', { count: summary.routes_removed })}</h4>
                        <div className="bg-red-50 border border-red-200 rounded-lg p-3 overflow-x-auto">
                          <table className="min-w-full text-sm">
                            <thead>
                              <tr className="border-b border-red-300">
                                <th className="text-left py-2 px-2 font-semibold text-gray-900">{t('comparison.routes.fields.node')}</th>
                                <th className="text-left py-2 px-2 font-semibold text-gray-900">{t('comparison.routes.fields.vrf')}</th>
                                <th className="text-left py-2 px-2 font-semibold text-gray-900">{t('comparison.routes.fields.network')}</th>
                                <th className="text-left py-2 px-2 font-semibold text-gray-900">{t('comparison.routes.fields.nextHop')}</th>
                                <th className="text-left py-2 px-2 font-semibold text-gray-900">{t('comparison.routes.fields.protocol')}</th>
                              </tr>
                            </thead>
                            <tbody>
                              {comparisonResult.routes.removed.map((route, idx) => (
                                <tr key={idx} className="border-b border-red-200 last:border-0">
                                  <td className="py-2 px-2 font-mono text-gray-900">{route.node}</td>
                                  <td className="py-2 px-2 text-gray-900">{route.vrf}</td>
                                  <td className="py-2 px-2 font-mono text-gray-900">{route.network}</td>
                                  <td className="py-2 px-2 font-mono text-gray-800">{route.next_hop || '-'}</td>
                                  <td className="py-2 px-2 text-gray-800">{route.protocol || '-'}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}

                    {summary.routes_modified > 0 && (
                      <div>
                        <h4 className="text-sm font-medium text-yellow-700 mb-2">{t('comparison.routes.modifiedRoutes', { count: summary.routes_modified })}</h4>
                        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-3 overflow-x-auto">
                          <table className="min-w-full text-sm">
                            <thead>
                              <tr className="border-b border-yellow-300">
                                <th className="text-left py-2 px-2 font-semibold text-gray-900">{t('comparison.routes.fields.node')}</th>
                                <th className="text-left py-2 px-2 font-semibold text-gray-900">{t('comparison.routes.fields.vrf')}</th>
                                <th className="text-left py-2 px-2 font-semibold text-gray-900">{t('comparison.routes.fields.network')}</th>
                                <th className="text-left py-2 px-2 font-semibold text-gray-900">{t('comparison.routes.fields.change')}</th>
                              </tr>
                            </thead>
                            <tbody>
                              {comparisonResult.routes.modified.map((route, idx) => {
                                const baseNextHops = formatNextHops(route.base_next_hops, route.base_next_hop)
                                const comparisonNextHops = formatNextHops(route.comparison_next_hops, route.comparison_next_hop)
                                return (
                                  <tr key={idx} className="border-b border-yellow-200 last:border-0">
                                    <td className="py-2 px-2 font-mono text-gray-900">{route.node}</td>
                                    <td className="py-2 px-2 text-gray-900">{route.vrf}</td>
                                    <td className="py-2 px-2 font-mono text-gray-900">{route.network}</td>
                                    <td className="py-2 px-2">
                                      {baseNextHops !== comparisonNextHops && (
                                        <div className="text-xs">
                                          {t('comparison.routes.nextHopAbbr')}: <span className="font-mono text-red-700">{baseNextHops}</span>
                                          {' → '}
                                          <span className="font-mono text-green-700">{comparisonNextHops}</span>
                                        </div>
                                      )}
                                      {route.base_protocol !== route.comparison_protocol && (
                                        <div className="text-xs">
                                          {t('comparison.routes.protocolAbbr')}: <span className="text-red-700">{route.base_protocol}</span>
                                          {' → '}
                                          <span className="text-green-700">{route.comparison_protocol}</span>
                                        </div>
                                      )}
                                    </td>
                                  </tr>
                                )
                              })}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}

                    {summary.routes_added === 0 && summary.routes_removed === 0 && summary.routes_modified === 0 && (
                      <p className="text-gray-700">{t('comparison.routes.noChanges')}</p>
                    )}
                  </div>
                )}

                {activeTab === 'reachability' && (
                  <div className="space-y-4">
                    <h3 className="text-lg font-semibold text-gray-900">{t('comparison.reachability.title')}</h3>

                    {reachabilityError ? (
                      <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4" role="status">
                        <p className="text-sm font-medium text-yellow-900">
                          {t('comparison.reachability.unavailable')}
                        </p>
                        {reachabilityError.reason && reachabilityError.reason !== reachabilityError.message && (
                          <p className="text-xs text-yellow-800 mt-1 font-mono break-words">
                            {t('comparison.reachability.reason', { reason: reachabilityError.reason })}
                          </p>
                        )}
                      </div>
                    ) : summary.reachability_changes > 0 ? (
                      <div className="space-y-3">
                        {comparisonResult.reachability.map((diff, idx) => (
                          <div key={idx} className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                            <div className="mb-2">
                              <span className="text-sm font-medium text-blue-900">{t('comparison.reachability.changeType')}: </span>
                              <span className="text-sm font-semibold text-blue-700">{diff.change}</span>
                            </div>
                            <div className="text-xs font-mono bg-white p-2 rounded border border-blue-200">
                              <pre className="overflow-x-auto">{JSON.stringify(diff.flow, null, 2)}</pre>
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-gray-700">{t('comparison.reachability.noChanges')}</p>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* No results placeholder */}
        {!comparisonResult && !compareMutation.isPending && (
          <div className="text-center py-12 text-gray-700">
            <GitCompare className="w-16 h-16 mx-auto mb-4 text-gray-500" aria-hidden="true" />
            <p className="text-lg font-semibold">{t('comparison.noResults')}</p>
            <p className="text-sm mt-2 text-gray-700">{t('comparison.selectToCompare')}</p>
          </div>
        )}
      </div>
    </div>
  )
}
