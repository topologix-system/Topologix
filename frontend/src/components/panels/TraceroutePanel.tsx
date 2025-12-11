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
import { useTranslation } from 'react-i18next'
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
  const { t } = useTranslation()
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
          <h2 className="text-xl font-semibold text-gray-900">{t('traceroute.title')}</h2>
        </div>
        <p className="text-sm text-gray-600">
          {t('traceroute.description')}
        </p>
      </div>

      {/* Configuration Form */}
      <form onSubmit={handleSubmit} className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">{t('traceroute.sections.configuration')}</h3>

        {/* Mode Selection */}
        <div className="mb-6">
          <label className="block text-sm font-medium text-gray-700 mb-2">{t('traceroute.fields.traceMode')}</label>
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
              {t('traceroute.modes.unidirectional')}
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
              {t('traceroute.modes.bidirectional')}
            </button>
          </div>
        </div>

        {/* Basic Configuration */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
          <div>
            <label htmlFor="srcIps" className="block text-sm font-medium text-gray-700 mb-1">
              {t('traceroute.fields.sourceIp')}
            </label>
            <input
              type="text"
              id="srcIps"
              value={formData.headers?.srcIps || ''}
              onChange={(e) => updateHeaders('srcIps', e.target.value)}
              placeholder={t('traceroute.placeholders.sourceIp')}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-600 focus:border-transparent"
            />
          </div>

          <div>
            <label htmlFor="dstIps" className="block text-sm font-medium text-gray-700 mb-1">
              {t('traceroute.fields.destinationIp')} *
            </label>
            <input
              type="text"
              id="dstIps"
              value={formData.headers?.dstIps || ''}
              onChange={(e) => updateHeaders('dstIps', e.target.value)}
              placeholder={t('traceroute.placeholders.destinationIp')}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-600 focus:border-transparent"
              required
            />
          </div>

          <div>
            <label htmlFor="startLocation" className="block text-sm font-medium text-gray-700 mb-1">
              {t('traceroute.fields.startLocation')}
            </label>
            <input
              type="text"
              id="startLocation"
              value={formData.startLocation || ''}
              onChange={(e) => setFormData({ ...formData, startLocation: e.target.value || undefined })}
              placeholder={t('traceroute.placeholders.startLocation')}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-600 focus:border-transparent"
            />
          </div>

          <div>
            <label htmlFor="maxTraces" className="block text-sm font-medium text-gray-700 mb-1">
              {t('traceroute.fields.maxTraces')}
            </label>
            <input
              type="number"
              id="maxTraces"
              value={formData.maxTraces || ''}
              onChange={(e) => setFormData({ ...formData, maxTraces: e.target.value ? Number(e.target.value) : undefined })}
              placeholder={t('traceroute.placeholders.maxTraces')}
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
            {t('traceroute.sections.advanced')}
          </button>

          {showAdvanced && (
            <div className="mt-4 space-y-4 p-4 bg-gray-50 rounded-lg">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Protocol Options */}
                <div>
                  <label htmlFor="ipProtocols" className="block text-sm font-medium text-gray-700 mb-1">
                    {t('traceroute.fields.ipProtocols')}
                  </label>
                  <input
                    type="text"
                    id="ipProtocols"
                    value={formData.headers?.ipProtocols?.join(',') || ''}
                    onChange={(e) => updateHeaders('ipProtocols', e.target.value ? e.target.value.split(',').map(p => p.trim()).filter(p => p) : undefined)}
                    placeholder={t('traceroute.placeholders.ipProtocols')}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-600 focus:border-transparent"
                  />
                </div>

                <div>
                  <label htmlFor="applications" className="block text-sm font-medium text-gray-700 mb-1">
                    {t('traceroute.fields.applications')}
                  </label>
                  <input
                    type="text"
                    id="applications"
                    value={formData.headers?.applications?.join(',') || ''}
                    onChange={(e) => updateHeaders('applications', e.target.value ? e.target.value.split(',').map(a => a.trim()).filter(a => a) : undefined)}
                    placeholder={t('traceroute.placeholders.applications')}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-600 focus:border-transparent"
                  />
                </div>

                {/* Port Options */}
                <div>
                  <label htmlFor="srcPorts" className="block text-sm font-medium text-gray-700 mb-1">
                    {t('traceroute.fields.sourcePorts')}
                  </label>
                  <input
                    type="text"
                    id="srcPorts"
                    value={formData.headers?.srcPorts || ''}
                    onChange={(e) => updateHeaders('srcPorts', e.target.value)}
                    placeholder={t('traceroute.placeholders.sourcePorts')}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-600 focus:border-transparent"
                  />
                </div>

                <div>
                  <label htmlFor="dstPorts" className="block text-sm font-medium text-gray-700 mb-1">
                    {t('traceroute.fields.destinationPorts')}
                  </label>
                  <input
                    type="text"
                    id="dstPorts"
                    value={formData.headers?.dstPorts || ''}
                    onChange={(e) => updateHeaders('dstPorts', e.target.value)}
                    placeholder={t('traceroute.placeholders.destinationPorts')}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-600 focus:border-transparent"
                  />
                </div>

                {/* ICMP Options */}
                <div>
                  <label htmlFor="icmpTypes" className="block text-sm font-medium text-gray-700 mb-1">
                    {t('traceroute.fields.icmpTypes')}
                  </label>
                  <input
                    type="text"
                    id="icmpTypes"
                    value={formData.headers?.icmpTypes?.join(',') || ''}
                    onChange={(e) => updateHeaders('icmpTypes', e.target.value ? e.target.value.split(',').map(t => Number(t.trim())).filter(t => !isNaN(t)) : undefined)}
                    placeholder={t('traceroute.placeholders.icmpTypes')}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-600 focus:border-transparent"
                  />
                </div>

                <div>
                  <label htmlFor="icmpCodes" className="block text-sm font-medium text-gray-700 mb-1">
                    {t('traceroute.fields.icmpCodes')}
                  </label>
                  <input
                    type="text"
                    id="icmpCodes"
                    value={formData.headers?.icmpCodes?.join(',') || ''}
                    onChange={(e) => updateHeaders('icmpCodes', e.target.value ? e.target.value.split(',').map(c => Number(c.trim())).filter(c => !isNaN(c)) : undefined)}
                    placeholder={t('traceroute.placeholders.icmpCodes')}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-600 focus:border-transparent"
                  />
                </div>

                {/* QoS Options */}
                <div>
                  <label htmlFor="dscps" className="block text-sm font-medium text-gray-700 mb-1">
                    {t('traceroute.fields.dscpValues')}
                  </label>
                  <input
                    type="text"
                    id="dscps"
                    value={formData.headers?.dscps?.join(',') || ''}
                    onChange={(e) => updateHeaders('dscps', e.target.value ? e.target.value.split(',').map(d => Number(d.trim())).filter(d => !isNaN(d)) : undefined)}
                    placeholder={t('traceroute.placeholders.dscpValues')}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-600 focus:border-transparent"
                  />
                </div>

                <div>
                  <label htmlFor="ecns" className="block text-sm font-medium text-gray-700 mb-1">
                    {t('traceroute.fields.ecnValues')}
                  </label>
                  <input
                    type="text"
                    id="ecns"
                    value={formData.headers?.ecns?.join(',') || ''}
                    onChange={(e) => updateHeaders('ecns', e.target.value ? e.target.value.split(',').map(n => Number(n.trim())).filter(n => !isNaN(n)) : undefined)}
                    placeholder={t('traceroute.placeholders.ecnValues')}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-600 focus:border-transparent"
                  />
                </div>

                <div>
                  <label htmlFor="packetLengths" className="block text-sm font-medium text-gray-700 mb-1">
                    {t('traceroute.fields.packetLength')}
                  </label>
                  <input
                    type="text"
                    id="packetLengths"
                    value={formData.headers?.packetLengths || ''}
                    onChange={(e) => updateHeaders('packetLengths', e.target.value)}
                    placeholder={t('traceroute.placeholders.packetLength')}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-600 focus:border-transparent"
                  />
                </div>
              </div>

              {/* Path Constraints */}
              <div className="pt-4 border-t border-gray-200">
                <h4 className="text-sm font-semibold text-gray-900 mb-3">{t('traceroute.sections.pathConstraints')}</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label htmlFor="endLocation" className="block text-sm font-medium text-gray-700 mb-1">
                      {t('traceroute.fields.endLocation')}
                    </label>
                    <input
                      type="text"
                      id="endLocation"
                      value={formData.pathConstraints?.endLocation || ''}
                      onChange={(e) => updatePathConstraints('endLocation', e.target.value)}
                      placeholder={t('traceroute.placeholders.endLocation')}
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-600 focus:border-transparent"
                    />
                  </div>

                  <div>
                    <label htmlFor="transitLocations" className="block text-sm font-medium text-gray-700 mb-1">
                      {t('traceroute.fields.transitLocations')}
                    </label>
                    <input
                      type="text"
                      id="transitLocations"
                      value={formData.pathConstraints?.transitLocations || ''}
                      onChange={(e) => updatePathConstraints('transitLocations', e.target.value)}
                      placeholder={t('traceroute.placeholders.transitLocations')}
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-600 focus:border-transparent"
                    />
                  </div>

                  <div>
                    <label htmlFor="forbiddenLocations" className="block text-sm font-medium text-gray-700 mb-1">
                      {t('traceroute.fields.forbiddenLocations')}
                    </label>
                    <input
                      type="text"
                      id="forbiddenLocations"
                      value={formData.pathConstraints?.forbiddenLocations || ''}
                      onChange={(e) => updatePathConstraints('forbiddenLocations', e.target.value)}
                      placeholder={t('traceroute.placeholders.forbiddenLocations')}
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
                  <span className="text-sm font-medium text-gray-700">{t('traceroute.options.ignoreAcls')}</span>
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
            {isLoading ? t('traceroute.buttons.running') : t('traceroute.buttons.run')}
          </button>
          <button
            type="button"
            onClick={handleReset}
            disabled={isLoading}
            className="px-4 py-2 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300 disabled:bg-gray-100 disabled:cursor-not-allowed transition-colors"
          >
            {t('common.reset')}
          </button>
        </div>
      </form>

      {/* Error Display */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <div className="flex items-start gap-3">
            <XCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" aria-hidden="true" />
            <div>
              <h4 className="text-sm font-semibold text-red-900">{t('common.error')}</h4>
              <p className="text-sm text-red-700 mt-1">{error.message || t('traceroute.messages.failed')}</p>
            </div>
          </div>
        </div>
      )}

      {/* Results Display */}
      {hasResults && (
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">{t('traceroute.sections.results')}</h3>

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
  const { t } = useTranslation()
  return (
    <div className="space-y-6">
      {data.map((result, idx) => (
        <div key={idx} className="border border-gray-200 rounded-lg p-4">
          <h4 className="text-sm font-semibold text-gray-900 mb-3">{t('traceroute.labels.flow')} {idx + 1}</h4>

          {/* Flow Information */}
          <div className="mb-4 p-3 bg-gray-50 rounded-lg">
            <h5 className="text-xs font-semibold text-gray-700 mb-2">{t('traceroute.labels.flowDetails')}</h5>
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
            <p className="text-sm text-gray-500">{t('traceroute.messages.noTraces')}</p>
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
  const { t } = useTranslation()
  return (
    <div className="space-y-6">
      {data.map((result, idx) => (
        <div key={idx} className="border border-gray-200 rounded-lg p-4">
          <h4 className="text-sm font-semibold text-gray-900 mb-3">{t('traceroute.labels.flowPair')} {idx + 1}</h4>

          {/* Forward Direction */}
          <div className="mb-6">
            <div className="flex items-center gap-2 mb-3">
              <ArrowRight className="w-4 h-4 text-primary-600" aria-hidden="true" />
              <h5 className="text-sm font-semibold text-gray-900">{t('traceroute.directions.forward')}</h5>
            </div>

            <div className="mb-4 p-3 bg-gray-50 rounded-lg">
              <h6 className="text-xs font-semibold text-gray-700 mb-2">{t('traceroute.labels.flowDetails')}</h6>
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
              <p className="text-sm text-gray-500">{t('traceroute.messages.noForwardTraces')}</p>
            )}
          </div>

          {/* Reverse Direction */}
          <div>
            <div className="flex items-center gap-2 mb-3">
              <ArrowLeftRight className="w-4 h-4 text-secondary-600" aria-hidden="true" />
              <h5 className="text-sm font-semibold text-gray-900">{t('traceroute.directions.reverse')}</h5>
            </div>

            <div className="mb-4 p-3 bg-gray-50 rounded-lg">
              <h6 className="text-xs font-semibold text-gray-700 mb-2">{t('traceroute.labels.reverseFlowDetails')}</h6>
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
              <p className="text-sm text-gray-500">{t('traceroute.messages.noReverseTraces')}</p>
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
  const { t } = useTranslation()
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
          <span className="text-sm font-medium text-gray-900">{t('traceroute.labels.trace')} {index + 1}</span>
          <span className={`flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${dispositionColor}`}>
            {dispositionIcon}
            {trace.disposition}
          </span>
          {trace.hops && (
            <span className="text-xs text-gray-500">{t('traceroute.labels.hopsCount', { count: trace.hops.length })}</span>
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
            <p className="text-sm text-gray-500 mt-3">{t('traceroute.messages.noHops')}</p>
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
  const { t } = useTranslation()
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
          <span className="text-xs font-medium text-gray-900">{t('traceroute.labels.hop')} {index + 1}: {hop.node}</span>
          {hop.steps && (
            <span className="text-xs text-gray-500">({t('traceroute.labels.stepsCount', { count: hop.steps.length })})</span>
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
