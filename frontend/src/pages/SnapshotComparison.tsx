/**
 * Snapshot Comparison Page
 * Displays differential analysis between two network snapshots
 * Shows changes in nodes, topology (edges), routing tables, and reachability
 */
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ArrowLeft, GitCompare, Loader2 } from 'lucide-react'

import { useSnapshots, useCompareSnapshots } from '../hooks'
import type { ComparisonResult } from '../types'

export function SnapshotComparison() {
  const [baseSnapshot, setBaseSnapshot] = useState<string>('')
  const [comparisonSnapshot, setComparisonSnapshot] = useState<string>('')
  const [activeTab, setActiveTab] = useState<'nodes' | 'topology' | 'routes' | 'reachability'>('nodes')
  const [comparisonResult, setComparisonResult] = useState<ComparisonResult | null>(null)

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
    if (!baseSnapshot || !comparisonSnapshot) {
      alert('Please select both base and comparison snapshots')
      return
    }

    if (baseSnapshot === comparisonSnapshot) {
      alert('Please select different snapshots to compare')
      return
    }

    compareMutation.mutate(
      {
        base_snapshot: baseSnapshot,
        comparison_snapshot: comparisonSnapshot,
      },
      {
        onSuccess: (data) => {
          setComparisonResult(data)
        },
        onError: (error: any) => {
          alert(`Comparison failed: ${error.message || 'Unknown error'}`)
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

  return (
    <div className="flex flex-col h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b border-gray-200 px-6 py-4" role="banner">
        <div className="flex items-center gap-4">
          <Link
            to="/"
            className="p-2 hover:bg-gray-100 rounded-lg transition-colors focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-2"
            aria-label="Back to topology view"
          >
            <ArrowLeft className="w-5 h-5" aria-hidden="true" />
            <span className="sr-only">Back to Topology</span>
          </Link>
          <h1 className="text-2xl font-bold text-gray-900">Snapshot Comparison</h1>
        </div>
      </header>

      {/* Main content */}
      <div className="flex-1 overflow-y-auto p-6">
        {/* Snapshot selection */}
        <div className="bg-white rounded-lg shadow p-6 mb-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Select Snapshots to Compare</h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            {/* Base snapshot selector */}
            <div>
              <label htmlFor="base-snapshot" className="block text-sm font-medium text-gray-800 mb-2">
                Base Snapshot (Before)
              </label>
              <select
                id="base-snapshot"
                value={baseSnapshot}
                onChange={(e) => setBaseSnapshot(e.target.value)}
                disabled={loadingSnapshots || compareMutation.isPending}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-600 disabled:opacity-50 disabled:cursor-not-allowed"
                aria-label="Select base snapshot"
              >
                <option value="">-- Select Base Snapshot --</option>
                {snapshots?.map((snapshot) => (
                  <option key={snapshot.name} value={snapshot.name}>
                    {snapshot.name}
                  </option>
                ))}
              </select>
            </div>

            {/* Comparison snapshot selector */}
            <div>
              <label htmlFor="comparison-snapshot" className="block text-sm font-medium text-gray-800 mb-2">
                Comparison Snapshot (After)
              </label>
              <select
                id="comparison-snapshot"
                value={comparisonSnapshot}
                onChange={(e) => setComparisonSnapshot(e.target.value)}
                disabled={loadingSnapshots || compareMutation.isPending}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-600 disabled:opacity-50 disabled:cursor-not-allowed"
                aria-label="Select comparison snapshot"
              >
                <option value="">-- Select Comparison Snapshot --</option>
                {snapshots?.map((snapshot) => (
                  <option key={snapshot.name} value={snapshot.name}>
                    {snapshot.name}
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
            aria-label="Compare selected snapshots"
            aria-busy={compareMutation.isPending}
          >
            {compareMutation.isPending ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" />
                Comparing...
              </>
            ) : (
              <>
                <GitCompare className="w-4 h-4" aria-hidden="true" />
                Compare Snapshots
              </>
            )}
          </button>
        </div>

        {/* Comparison results */}
        {comparisonResult && summary && (
          <div className="space-y-6">
            {/* Summary cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="bg-white rounded-lg shadow p-4">
                <h3 className="text-sm font-medium text-gray-700 mb-2">Node Changes</h3>
                <div className="space-y-1">
                  <p className="text-sm">
                    <span className="text-green-600 font-semibold">+{summary.nodes_added}</span> added
                  </p>
                  <p className="text-sm">
                    <span className="text-red-600 font-semibold">-{summary.nodes_removed}</span> removed
                  </p>
                </div>
              </div>

              <div className="bg-white rounded-lg shadow p-4">
                <h3 className="text-sm font-medium text-gray-700 mb-2">Topology Changes</h3>
                <div className="space-y-1">
                  <p className="text-sm">
                    <span className="text-green-600 font-semibold">+{summary.edges_added}</span> added
                  </p>
                  <p className="text-sm">
                    <span className="text-red-600 font-semibold">-{summary.edges_removed}</span> removed
                  </p>
                </div>
              </div>

              <div className="bg-white rounded-lg shadow p-4">
                <h3 className="text-sm font-medium text-gray-700 mb-2">Route Changes</h3>
                <div className="space-y-1">
                  <p className="text-sm">
                    <span className="text-green-600 font-semibold">+{summary.routes_added}</span> added
                  </p>
                  <p className="text-sm">
                    <span className="text-red-600 font-semibold">-{summary.routes_removed}</span> removed
                  </p>
                  <p className="text-sm">
                    <span className="text-yellow-600 font-semibold">~{summary.routes_modified}</span> modified
                  </p>
                </div>
              </div>

              <div className="bg-white rounded-lg shadow p-4">
                <h3 className="text-sm font-medium text-gray-700 mb-2">Reachability</h3>
                <p className="text-2xl font-bold text-gray-900">{summary.reachability_changes}</p>
                <p className="text-xs text-gray-600 mt-1">changes detected</p>
              </div>
            </div>

            {/* Tabs */}
            <div className="bg-white rounded-lg shadow">
              <div className="border-b border-gray-200">
                <nav className="flex -mb-px" aria-label="Comparison tabs">
                  {[
                    { id: 'nodes', label: 'Nodes' },
                    { id: 'topology', label: 'Topology' },
                    { id: 'routes', label: 'Routes' },
                    { id: 'reachability', label: 'Reachability' },
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
                    <h3 className="text-lg font-semibold text-gray-900">Node Changes</h3>

                    {summary.nodes_added > 0 && (
                      <div>
                        <h4 className="text-sm font-medium text-green-700 mb-2">Added Nodes ({summary.nodes_added})</h4>
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
                        <h4 className="text-sm font-medium text-red-700 mb-2">Removed Nodes ({summary.nodes_removed})</h4>
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
                      <p className="text-gray-700">No node changes detected</p>
                    )}
                  </div>
                )}

                {activeTab === 'topology' && (
                  <div className="space-y-4">
                    <h3 className="text-lg font-semibold text-gray-900">Topology Changes (Edges)</h3>

                    {summary.edges_added > 0 && (
                      <div>
                        <h4 className="text-sm font-medium text-green-700 mb-2">Added Edges ({summary.edges_added})</h4>
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
                        <h4 className="text-sm font-medium text-red-700 mb-2">Removed Edges ({summary.edges_removed})</h4>
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
                      <p className="text-gray-700">No topology changes detected</p>
                    )}
                  </div>
                )}

                {activeTab === 'routes' && (
                  <div className="space-y-4">
                    <h3 className="text-lg font-semibold text-gray-900">Routing Table Changes</h3>

                    {summary.routes_added > 0 && (
                      <div>
                        <h4 className="text-sm font-medium text-green-700 mb-2">Added Routes ({summary.routes_added})</h4>
                        <div className="bg-green-50 border border-green-200 rounded-lg p-3 overflow-x-auto">
                          <table className="min-w-full text-sm">
                            <thead>
                              <tr className="border-b border-green-300">
                                <th className="text-left py-2 px-2 font-semibold text-gray-900">Node</th>
                                <th className="text-left py-2 px-2 font-semibold text-gray-900">VRF</th>
                                <th className="text-left py-2 px-2 font-semibold text-gray-900">Network</th>
                                <th className="text-left py-2 px-2 font-semibold text-gray-900">Next Hop</th>
                                <th className="text-left py-2 px-2 font-semibold text-gray-900">Protocol</th>
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
                        <h4 className="text-sm font-medium text-red-700 mb-2">Removed Routes ({summary.routes_removed})</h4>
                        <div className="bg-red-50 border border-red-200 rounded-lg p-3 overflow-x-auto">
                          <table className="min-w-full text-sm">
                            <thead>
                              <tr className="border-b border-red-300">
                                <th className="text-left py-2 px-2 font-semibold text-gray-900">Node</th>
                                <th className="text-left py-2 px-2 font-semibold text-gray-900">VRF</th>
                                <th className="text-left py-2 px-2 font-semibold text-gray-900">Network</th>
                                <th className="text-left py-2 px-2 font-semibold text-gray-900">Next Hop</th>
                                <th className="text-left py-2 px-2 font-semibold text-gray-900">Protocol</th>
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
                        <h4 className="text-sm font-medium text-yellow-700 mb-2">Modified Routes ({summary.routes_modified})</h4>
                        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-3 overflow-x-auto">
                          <table className="min-w-full text-sm">
                            <thead>
                              <tr className="border-b border-yellow-300">
                                <th className="text-left py-2 px-2 font-semibold text-gray-900">Node</th>
                                <th className="text-left py-2 px-2 font-semibold text-gray-900">VRF</th>
                                <th className="text-left py-2 px-2 font-semibold text-gray-900">Network</th>
                                <th className="text-left py-2 px-2 font-semibold text-gray-900">Change</th>
                              </tr>
                            </thead>
                            <tbody>
                              {comparisonResult.routes.modified.map((route, idx) => (
                                <tr key={idx} className="border-b border-yellow-200 last:border-0">
                                  <td className="py-2 px-2 font-mono text-gray-900">{route.node}</td>
                                  <td className="py-2 px-2 text-gray-900">{route.vrf}</td>
                                  <td className="py-2 px-2 font-mono text-gray-900">{route.network}</td>
                                  <td className="py-2 px-2">
                                    {route.base_next_hop !== route.comparison_next_hop && (
                                      <div className="text-xs">
                                        NH: <span className="font-mono text-red-700">{route.base_next_hop}</span>
                                        {' → '}
                                        <span className="font-mono text-green-700">{route.comparison_next_hop}</span>
                                      </div>
                                    )}
                                    {route.base_protocol !== route.comparison_protocol && (
                                      <div className="text-xs">
                                        Proto: <span className="text-red-700">{route.base_protocol}</span>
                                        {' → '}
                                        <span className="text-green-700">{route.comparison_protocol}</span>
                                      </div>
                                    )}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}

                    {summary.routes_added === 0 && summary.routes_removed === 0 && summary.routes_modified === 0 && (
                      <p className="text-gray-700">No routing table changes detected</p>
                    )}
                  </div>
                )}

                {activeTab === 'reachability' && (
                  <div className="space-y-4">
                    <h3 className="text-lg font-semibold text-gray-900">Reachability Changes</h3>

                    {summary.reachability_changes > 0 ? (
                      <div className="space-y-3">
                        {comparisonResult.reachability.map((diff, idx) => (
                          <div key={idx} className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                            <div className="mb-2">
                              <span className="text-sm font-medium text-blue-900">Change Type: </span>
                              <span className="text-sm font-semibold text-blue-700">{diff.change}</span>
                            </div>
                            <div className="text-xs font-mono bg-white p-2 rounded border border-blue-200">
                              <pre className="overflow-x-auto">{JSON.stringify(diff.flow, null, 2)}</pre>
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-gray-700">No reachability changes detected</p>
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
            <p className="text-lg font-semibold">No comparison results yet</p>
            <p className="text-sm mt-2 text-gray-700">Select two snapshots and click Compare to see differences</p>
          </div>
        )}
      </div>
    </div>
  )
}
