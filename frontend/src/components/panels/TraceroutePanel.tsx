/**
 * Network path analysis tool with traceroute simulation
 * - Supports unidirectional and bidirectional traceroute modes
 * - Detailed packet specification: src/dst IP, ports, protocols, DSCP, ECN, fragment offset
 * - Path constraints: ingress/egress nodes, transit nodes, forbidden nodes for "what-if" scenarios
 * - Advanced options: maxTraces, ignoreFilters, ignorePBR for analysis control
 * - Results visualization: hop-by-hop trace with flow dispositions (accepted/denied/loop/etc)
 * - Collapsible trace sections with success/fail indicators per flow
 * - Largest panel component (675 lines) with extensive form handling
 */
import { useState } from 'react'
import { useTraceroute, useBidirectionalTraceroute } from '../../hooks/useAnalysis'
import type {
  TracerouteRequest,
  TracerouteResponse,
  BidirectionalTracerouteResponse,
  Trace,
  TraceHop,
} from '../../types'
import {
  Network,
  Activity,
  ArrowRight,
  ArrowLeftRight,
  ChevronDown,
  ChevronRight,
  CheckCircle,
  XCircle,
  AlertCircle,
  Info,
} from 'lucide-react'

export function TraceroutePanel() {
  const [tracerouteMode, setTracerouteMode] = useState<'unidirectional' | 'bidirectional'>(
    'unidirectional'
  )

  const [formData, setFormData] = useState<TracerouteRequest>({
    headers: {},
  })

  const [showAdvanced, setShowAdvanced] = useState(false)

  const traceroute = useTraceroute()
  const bidirectionalTraceroute = useBidirectionalTraceroute()

  /**
   * Handle form submission for traceroute analysis
   * Routes to bidirectional or unidirectional mutation based on selected mode
   */
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    if (tracerouteMode === 'bidirectional') {
      bidirectionalTraceroute.mutate(formData)
    } else {
      traceroute.mutate(formData)
    }
  }

  /**
   * Reset form and clear all traceroute results
   * Clears form data, unidirectional results, and bidirectional results
   */
  const handleReset = () => {
    setFormData({ headers: {} })
    traceroute.reset()
    bidirectionalTraceroute.reset()
  }

  /**
   * Update packet header fields in form data
   * Merges new field value into existing headers object
   */
  const updateHeaders = (field: string, value: any) => {
    setFormData((prev) => ({
      ...prev,
      headers: {
        ...prev.headers,
        [field]: value,
      },
    }))
  }

  /**
   * Update path constraint fields in form data
   * Used for ingress/egress nodes, transit nodes, forbidden nodes
   */
  const updatePathConstraints = (field: string, value: any) => {
    setFormData((prev) => ({
      ...prev,
      pathConstraints: {
        ...prev.pathConstraints,
        [field]: value,
      },
    }))
  }

  const isLoading = traceroute.isPending || bidirectionalTraceroute.isPending
  const hasResults = traceroute.data || bidirectionalTraceroute.data
  const error = traceroute.error || bidirectionalTraceroute.error

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex items-center gap-3 mb-4">
          <Network className="w-6 h-6 text-primary-600" aria-hidden="true" />
          <h2 className="text-xl font-semibold text-gray-900">Network Traceroute</h2>
        </div>
        <p className="text-sm text-gray-600">
          Analyze network paths with detailed packet specifications and path constraints
        </p>
      </div>

      {/* Configuration Form */}
      <form onSubmit={handleSubmit} className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Configuration</h3>

        {/* Mode Selection */}
        <div className="mb-6">
          <label className="block text-sm font-medium text-gray-700 mb-2">Trace Mode</label>
          <div className="flex gap-4">
            <button
              type="button"
              onClick={() => setTracerouteMode('unidirectional')}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg border-2 transition-colors ${
                tracerouteMode === 'unidirectional'
                  ? 'border-primary-600 bg-primary-50 text-primary-700'
                  : 'border-gray-300 bg-white text-gray-700 hover:bg-gray-50'
              }`}
            >
              <ArrowRight className="w-4 h-4" aria-hidden="true" />
              Unidirectional
            </button>
            <button
              type="button"
              onClick={() => setTracerouteMode('bidirectional')}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg border-2 transition-colors ${
                tracerouteMode === 'bidirectional'
                  ? 'border-primary-600 bg-primary-50 text-primary-700'
                  : 'border-gray-300 bg-white text-gray-700 hover:bg-gray-50'
              }`}
            >
              <ArrowLeftRight className="w-4 h-4" aria-hidden="true" />
              Bidirectional
            </button>
          </div>
        </div>

        {/* Basic Configuration */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
          <div>
            <label htmlFor="srcIps" className="block text-sm font-medium text-gray-700 mb-1">
              Source IP/Range
            </label>
            <input
              type="text"
              id="srcIps"
              value={formData.headers?.srcIps || ''}
              onChange={(e) => updateHeaders('srcIps', e.target.value)}
              placeholder="e.g., 192.0.2.1 or 192.0.2.0/24"
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-600 focus:border-transparent"
            />
          </div>

          <div>
            <label htmlFor="dstIps" className="block text-sm font-medium text-gray-700 mb-1">
              Destination IP/Range *
            </label>
            <input
              type="text"
              id="dstIps"
              value={formData.headers?.dstIps || ''}
              onChange={(e) => updateHeaders('dstIps', e.target.value)}
              placeholder="e.g., 198.51.100.1"
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-600 focus:border-transparent"
              required
            />
          </div>

          <div>
            <label htmlFor="startLocation" className="block text-sm font-medium text-gray-700 mb-1">
              Start Location
            </label>
            <input
              type="text"
              id="startLocation"
              value={formData.startLocation || ''}
              onChange={(e) => setFormData({ ...formData, startLocation: e.target.value || undefined })}
              placeholder="e.g., router1 or router1[GigabitEthernet0/1]"
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-600 focus:border-transparent"
            />
          </div>

          <div>
            <label htmlFor="maxTraces" className="block text-sm font-medium text-gray-700 mb-1">
              Max Traces
            </label>
            <input
              type="number"
              id="maxTraces"
              value={formData.maxTraces || ''}
              onChange={(e) => setFormData({ ...formData, maxTraces: e.target.value ? Number(e.target.value) : undefined })}
              placeholder="e.g., 10"
              min="1"
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-600 focus:border-transparent"
            />
          </div>
        </div>

        {/* Advanced Configuration */}
        <div className="mb-6">
          <button
            type="button"
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="flex items-center gap-2 text-sm font-medium text-primary-600 hover:text-primary-700"
          >
            {showAdvanced ? (
              <ChevronDown className="w-4 h-4" aria-hidden="true" />
            ) : (
              <ChevronRight className="w-4 h-4" aria-hidden="true" />
            )}
            Advanced Options
          </button>

          {showAdvanced && (
            <div className="mt-4 space-y-4 p-4 bg-gray-50 rounded-lg">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Protocol Options */}
                <div>
                  <label htmlFor="ipProtocols" className="block text-sm font-medium text-gray-700 mb-1">
                    IP Protocols
                  </label>
                  <input
                    type="text"
                    id="ipProtocols"
                    value={formData.headers?.ipProtocols?.join(',') || ''}
                    onChange={(e) => updateHeaders('ipProtocols', e.target.value ? e.target.value.split(',').map(p => p.trim()).filter(p => p) : undefined)}
                    placeholder="e.g., TCP,UDP,ICMP"
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-600 focus:border-transparent"
                  />
                </div>

                <div>
                  <label htmlFor="applications" className="block text-sm font-medium text-gray-700 mb-1">
                    Applications
                  </label>
                  <input
                    type="text"
                    id="applications"
                    value={formData.headers?.applications?.join(',') || ''}
                    onChange={(e) => updateHeaders('applications', e.target.value ? e.target.value.split(',').map(a => a.trim()).filter(a => a) : undefined)}
                    placeholder="e.g., DNS,SSH,HTTP"
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-600 focus:border-transparent"
                  />
                </div>

                {/* Port Options */}
                <div>
                  <label htmlFor="srcPorts" className="block text-sm font-medium text-gray-700 mb-1">
                    Source Ports
                  </label>
                  <input
                    type="text"
                    id="srcPorts"
                    value={formData.headers?.srcPorts || ''}
                    onChange={(e) => updateHeaders('srcPorts', e.target.value)}
                    placeholder="e.g., 80 or 1000-2000"
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-600 focus:border-transparent"
                  />
                </div>

                <div>
                  <label htmlFor="dstPorts" className="block text-sm font-medium text-gray-700 mb-1">
                    Destination Ports
                  </label>
                  <input
                    type="text"
                    id="dstPorts"
                    value={formData.headers?.dstPorts || ''}
                    onChange={(e) => updateHeaders('dstPorts', e.target.value)}
                    placeholder="e.g., 443"
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-600 focus:border-transparent"
                  />
                </div>

                {/* ICMP Options */}
                <div>
                  <label htmlFor="icmpTypes" className="block text-sm font-medium text-gray-700 mb-1">
                    ICMP Types
                  </label>
                  <input
                    type="text"
                    id="icmpTypes"
                    value={formData.headers?.icmpTypes?.join(',') || ''}
                    onChange={(e) => updateHeaders('icmpTypes', e.target.value ? e.target.value.split(',').map(t => Number(t.trim())).filter(t => !isNaN(t)) : undefined)}
                    placeholder="e.g., 8,0"
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-600 focus:border-transparent"
                  />
                </div>

                <div>
                  <label htmlFor="icmpCodes" className="block text-sm font-medium text-gray-700 mb-1">
                    ICMP Codes
                  </label>
                  <input
                    type="text"
                    id="icmpCodes"
                    value={formData.headers?.icmpCodes?.join(',') || ''}
                    onChange={(e) => updateHeaders('icmpCodes', e.target.value ? e.target.value.split(',').map(c => Number(c.trim())).filter(c => !isNaN(c)) : undefined)}
                    placeholder="e.g., 0"
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-600 focus:border-transparent"
                  />
                </div>

                {/* QoS Options */}
                <div>
                  <label htmlFor="dscps" className="block text-sm font-medium text-gray-700 mb-1">
                    DSCP Values
                  </label>
                  <input
                    type="text"
                    id="dscps"
                    value={formData.headers?.dscps?.join(',') || ''}
                    onChange={(e) => updateHeaders('dscps', e.target.value ? e.target.value.split(',').map(d => Number(d.trim())).filter(d => !isNaN(d)) : undefined)}
                    placeholder="e.g., 46"
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-600 focus:border-transparent"
                  />
                </div>

                <div>
                  <label htmlFor="ecns" className="block text-sm font-medium text-gray-700 mb-1">
                    ECN Values
                  </label>
                  <input
                    type="text"
                    id="ecns"
                    value={formData.headers?.ecns?.join(',') || ''}
                    onChange={(e) => updateHeaders('ecns', e.target.value ? e.target.value.split(',').map(n => Number(n.trim())).filter(n => !isNaN(n)) : undefined)}
                    placeholder="e.g., 0,1,2,3"
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-600 focus:border-transparent"
                  />
                </div>

                <div>
                  <label htmlFor="packetLengths" className="block text-sm font-medium text-gray-700 mb-1">
                    Packet Length
                  </label>
                  <input
                    type="text"
                    id="packetLengths"
                    value={formData.headers?.packetLengths || ''}
                    onChange={(e) => updateHeaders('packetLengths', e.target.value)}
                    placeholder="e.g., 64-1500"
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-600 focus:border-transparent"
                  />
                </div>
              </div>

              {/* Path Constraints */}
              <div className="pt-4 border-t border-gray-200">
                <h4 className="text-sm font-semibold text-gray-900 mb-3">Path Constraints</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label htmlFor="endLocation" className="block text-sm font-medium text-gray-700 mb-1">
                      End Location
                    </label>
                    <input
                      type="text"
                      id="endLocation"
                      value={formData.pathConstraints?.endLocation || ''}
                      onChange={(e) => updatePathConstraints('endLocation', e.target.value)}
                      placeholder="e.g., router2"
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-600 focus:border-transparent"
                    />
                  </div>

                  <div>
                    <label htmlFor="transitLocations" className="block text-sm font-medium text-gray-700 mb-1">
                      Transit Locations (required)
                    </label>
                    <input
                      type="text"
                      id="transitLocations"
                      value={formData.pathConstraints?.transitLocations || ''}
                      onChange={(e) => updatePathConstraints('transitLocations', e.target.value)}
                      placeholder="e.g., core-switch"
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-600 focus:border-transparent"
                    />
                  </div>

                  <div>
                    <label htmlFor="forbiddenLocations" className="block text-sm font-medium text-gray-700 mb-1">
                      Forbidden Locations
                    </label>
                    <input
                      type="text"
                      id="forbiddenLocations"
                      value={formData.pathConstraints?.forbiddenLocations || ''}
                      onChange={(e) => updatePathConstraints('forbiddenLocations', e.target.value)}
                      placeholder="e.g., firewall1"
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-600 focus:border-transparent"
                    />
                  </div>
                </div>
              </div>

              {/* Other Options */}
              <div className="pt-4 border-t border-gray-200">
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={formData.ignoreFilters || false}
                    onChange={(e) => setFormData({ ...formData, ignoreFilters: e.target.checked })}
                    className="rounded border-gray-300 text-primary-600 focus:ring-primary-600"
                  />
                  <span className="text-sm font-medium text-gray-700">Ignore ACLs/Filters</span>
                </label>
              </div>
            </div>
          )}
        </div>

        {/* Submit Buttons */}
        <div className="flex gap-3">
          <button
            type="submit"
            disabled={isLoading}
            className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
          >
            {isLoading ? 'Running...' : 'Run Traceroute'}
          </button>
          <button
            type="button"
            onClick={handleReset}
            disabled={isLoading}
            className="px-4 py-2 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300 disabled:bg-gray-100 disabled:cursor-not-allowed transition-colors"
          >
            Reset
          </button>
        </div>
      </form>

      {/* Error Display */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <div className="flex items-start gap-3">
            <XCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" aria-hidden="true" />
            <div>
              <h4 className="text-sm font-semibold text-red-900">Error</h4>
              <p className="text-sm text-red-700 mt-1">{error.message || 'Failed to run traceroute'}</p>
            </div>
          </div>
        </div>
      )}

      {/* Results Display */}
      {hasResults && (
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Results</h3>

          {tracerouteMode === 'bidirectional' && bidirectionalTraceroute.data ? (
            <BidirectionalResults data={bidirectionalTraceroute.data} />
          ) : traceroute.data ? (
            <UnidirectionalResults data={traceroute.data} />
          ) : null}
        </div>
      )}
    </div>
  )
}

/**
 * Display results for unidirectional traceroute
 * Shows flow details and traces for each result with hop-by-hop visualization
 */
function UnidirectionalResults({ data }: { data: TracerouteResponse[] }) {
  return (
    <div className="space-y-6">
      {data.map((result, idx) => (
        <div key={idx} className="border border-gray-200 rounded-lg p-4">
          <h4 className="text-sm font-semibold text-gray-900 mb-3">Flow {idx + 1}</h4>

          {/* Flow Information */}
          <div className="mb-4 p-3 bg-gray-50 rounded-lg">
            <h5 className="text-xs font-semibold text-gray-700 mb-2">Flow Details</h5>
            <pre className="text-xs text-gray-600 whitespace-pre-wrap font-mono">
              {typeof result.flow === 'string' ? result.flow : JSON.stringify(result.flow, null, 2)}
            </pre>
          </div>

          {/* Traces */}
          {Array.isArray(result.traces) && result.traces.length > 0 ? (
            <div className="space-y-3">
              {result.traces.map((trace, traceIdx) => (
                <TraceDisplay key={traceIdx} trace={trace} index={traceIdx} />
              ))}
            </div>
          ) : (
            <p className="text-sm text-gray-500">No traces available</p>
          )}
        </div>
      ))}
    </div>
  )
}

/**
 * Display results for bidirectional traceroute
 * Shows both forward and reverse direction flows with separate trace displays
 */
function BidirectionalResults({ data }: { data: BidirectionalTracerouteResponse[] }) {
  return (
    <div className="space-y-6">
      {data.map((result, idx) => (
        <div key={idx} className="border border-gray-200 rounded-lg p-4">
          <h4 className="text-sm font-semibold text-gray-900 mb-3">Flow Pair {idx + 1}</h4>

          {/* Forward Direction */}
          <div className="mb-6">
            <div className="flex items-center gap-2 mb-3">
              <ArrowRight className="w-4 h-4 text-primary-600" aria-hidden="true" />
              <h5 className="text-sm font-semibold text-gray-900">Forward Direction</h5>
            </div>

            <div className="mb-4 p-3 bg-gray-50 rounded-lg">
              <h6 className="text-xs font-semibold text-gray-700 mb-2">Flow Details</h6>
              <pre className="text-xs text-gray-600 whitespace-pre-wrap font-mono">
                {typeof result.flow === 'string' ? result.flow : JSON.stringify(result.flow, null, 2)}
              </pre>
            </div>

            {Array.isArray(result.forward_traces) && result.forward_traces.length > 0 ? (
              <div className="space-y-3">
                {result.forward_traces.map((trace, traceIdx) => (
                  <TraceDisplay key={traceIdx} trace={trace} index={traceIdx} />
                ))}
              </div>
            ) : (
              <p className="text-sm text-gray-500">No forward traces available</p>
            )}
          </div>

          {/* Reverse Direction */}
          <div>
            <div className="flex items-center gap-2 mb-3">
              <ArrowLeftRight className="w-4 h-4 text-secondary-600" aria-hidden="true" />
              <h5 className="text-sm font-semibold text-gray-900">Reverse Direction</h5>
            </div>

            <div className="mb-4 p-3 bg-gray-50 rounded-lg">
              <h6 className="text-xs font-semibold text-gray-700 mb-2">Reverse Flow Details</h6>
              <pre className="text-xs text-gray-600 whitespace-pre-wrap font-mono">
                {typeof result.reverse_flow === 'string'
                  ? result.reverse_flow
                  : JSON.stringify(result.reverse_flow, null, 2)}
              </pre>
            </div>

            {Array.isArray(result.reverse_traces) && result.reverse_traces.length > 0 ? (
              <div className="space-y-3">
                {result.reverse_traces.map((trace, traceIdx) => (
                  <TraceDisplay key={traceIdx} trace={trace} index={traceIdx} />
                ))}
              </div>
            ) : (
              <p className="text-sm text-gray-500">No reverse traces available</p>
            )}
          </div>
        </div>
      ))}
    </div>
  )
}

/**
 * Collapsible trace display component
 * Shows disposition status with color-coded badge and hop details
 * Handles both structured Trace objects and string traces
 */
function TraceDisplay({ trace, index }: { trace: Trace | string; index: number }) {
  const [isExpanded, setIsExpanded] = useState(true)

  if (typeof trace === 'string') {
    return (
      <div className="p-3 bg-gray-50 rounded-lg">
        <pre className="text-xs text-gray-600 whitespace-pre-wrap font-mono">{trace}</pre>
      </div>
    )
  }

  const dispositionIcon = getDispositionIcon(trace.disposition)
  const dispositionColor = getDispositionColor(trace.disposition)

  return (
    <div className="border border-gray-200 rounded-lg">
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full px-4 py-3 flex items-center justify-between hover:bg-gray-50 transition-colors"
      >
        <div className="flex items-center gap-3">
          <span aria-hidden="true">{isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}</span>
          <span className="text-sm font-medium text-gray-900">Trace {index + 1}</span>
          <span className={`flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${dispositionColor}`}>
            {dispositionIcon}
            {trace.disposition}
          </span>
          {trace.hops && (
            <span className="text-xs text-gray-500">{trace.hops.length} hops</span>
          )}
        </div>
      </button>

      {isExpanded && (
        <div className="px-4 pb-4 border-t border-gray-100">
          {trace.hops && trace.hops.length > 0 ? (
            <div className="space-y-2 mt-3">
              {trace.hops.map((hop, hopIdx) => (
                <HopDisplay key={hopIdx} hop={hop} index={hopIdx} />
              ))}
            </div>
          ) : (
            <p className="text-sm text-gray-500 mt-3">No hops available</p>
          )}
        </div>
      )}
    </div>
  )
}

/**
 * Individual hop display component with expandable step details
 * Shows node name and processing steps for each network hop
 * Handles both structured TraceHop objects and string hops
 */
function HopDisplay({ hop, index }: { hop: TraceHop | string; index: number }) {
  const [isExpanded, setIsExpanded] = useState(false)

  if (typeof hop === 'string') {
    return (
      <div className="p-2 bg-gray-50 rounded text-xs text-gray-600 font-mono">
        {hop}
      </div>
    )
  }

  return (
    <div className="border border-gray-100 rounded">
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full px-3 py-2 flex items-center justify-between hover:bg-gray-50 transition-colors"
      >
        <div className="flex items-center gap-2">
          <Activity className="w-3 h-3 text-gray-400" aria-hidden="true" />
          <span className="text-xs font-medium text-gray-900">Hop {index + 1}: {hop.node}</span>
          {hop.steps && (
            <span className="text-xs text-gray-500">({hop.steps.length} steps)</span>
          )}
        </div>
        <span aria-hidden="true">{isExpanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}</span>
      </button>

      {isExpanded && hop.steps && hop.steps.length > 0 && (
        <div className="px-3 pb-2 space-y-1 border-t border-gray-100">
          {hop.steps.map((step, stepIdx) => (
            <div key={stepIdx} className="py-1 text-xs">
              <div className="flex items-start gap-2">
                <span className="text-gray-400 font-mono">{stepIdx + 1}.</span>
                <div className="flex-1">
                  <div className="text-gray-900 font-medium">{step.action}</div>
                  {step.detail && (
                    <div className="text-gray-600 mt-0.5">{step.detail}</div>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

/**
 * Map flow disposition to appropriate icon
 * Returns icon component for disposition status: ACCEPTED/SUCCESS, DENIED/DROPPED, NO_ROUTE, etc.
 */
function getDispositionIcon(disposition: string) {
  switch (disposition?.toUpperCase()) {
    case 'ACCEPTED':
    case 'SUCCESS':
      return <CheckCircle className="w-3 h-3" aria-hidden="true" />
    case 'DENIED':
    case 'DROPPED':
    case 'FAILURE':
      return <XCircle className="w-3 h-3" aria-hidden="true" />
    case 'NO_ROUTE':
    case 'NEIGHBOR_UNREACHABLE':
      return <AlertCircle className="w-3 h-3" aria-hidden="true" />
    default:
      return <Info className="w-3 h-3" aria-hidden="true" />
  }
}

/**
 * Map flow disposition to color class for badge styling
 * Returns Tailwind CSS classes for disposition colors: green (success), red (failure), yellow (warnings)
 */
function getDispositionColor(disposition: string): string {
  switch (disposition?.toUpperCase()) {
    case 'ACCEPTED':
    case 'SUCCESS':
      return 'bg-green-100 text-green-700'
    case 'DENIED':
    case 'DROPPED':
    case 'FAILURE':
      return 'bg-red-100 text-red-700'
    case 'NO_ROUTE':
    case 'NEIGHBOR_UNREACHABLE':
      return 'bg-yellow-100 text-yellow-700'
    default:
      return 'bg-gray-100 text-gray-700'
  }
}

export default TraceroutePanel
