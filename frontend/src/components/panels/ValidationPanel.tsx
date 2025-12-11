/**
 * Configuration validation panel with collapsible severity-based sections
 * - File parse status: successful/failed file parsing with error details
 * - Init issues: Batfish initialization errors (error severity)
 * - Parse warnings: configuration syntax warnings (warning severity)
 * - Unused structures: defined but never referenced config objects
 * - Undefined references: referenced but never defined config objects
 * - Forwarding loops: detected routing loops in network
 * - Multipath consistency: ECMP path validation
 * - Color-coded sections: red (error), yellow (warning), gray (info)
 */
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  AlertTriangle,
  XCircle,
  CheckCircle,
  FileText,
  AlertCircle,
  ChevronDown,
  ChevronRight,
  GitBranch,
} from 'lucide-react'

import {
  useFileParseStatus,
  useInitIssues,
  useParseWarnings,
  useVIConversionStatus,
  useUnusedStructures,
  useUndefinedReferences,
  useForwardingLoops,
  useMultipathConsistency,
  useLoopbackMultipathConsistency,
} from '../../hooks'

interface SectionProps {
  title: string
  icon: React.ReactNode
  isLoading: boolean
  data: any
  defaultOpen?: boolean
  severity?: 'error' | 'warning' | 'info'
}

/**
 * Collapsible validation section with severity-based styling
 * - Accordion-style: click to expand/collapse
 * - Color-coded: red (error), yellow (warning), gray (info)
 * - Badge: shows item count with severity-appropriate colors
 * - Displays JSON data or "No issues found" message
 */
function Section({ title, icon, isLoading, data, defaultOpen = false, severity = 'info' }: SectionProps) {
  const { t } = useTranslation()
  const [isOpen, setIsOpen] = useState(defaultOpen)
  const sectionId = `validation-section-${title.toLowerCase().replace(/\s+/g, '-')}`

  const hasData = data && (Array.isArray(data) ? data.length > 0 : Object.keys(data).length > 0)
  const count = data ? (Array.isArray(data) ? data.length : Object.keys(data).length) : 0

  /**
   * Get border and background colors based on severity level
   * Maps severity to Tailwind classes: error=red, warning=yellow, info=gray
   */
  const getSeverityColor = () => {
    switch (severity) {
      case 'error':
        return 'border-red-200 bg-red-50'
      case 'warning':
        return 'border-yellow-200 bg-yellow-50'
      default:
        return 'border-gray-200 bg-white'
    }
  }

  /**
   * Get badge color based on severity and data presence
   * Returns gray for no data, otherwise severity-appropriate colors
   */
  const getCountBadgeColor = () => {
    if (!hasData) return 'bg-gray-100 text-gray-600'
    switch (severity) {
      case 'error':
        return 'bg-red-100 text-red-700'
      case 'warning':
        return 'bg-yellow-100 text-yellow-700'
      default:
        return 'bg-blue-100 text-blue-700'
    }
  }

  return (
    <div className={`rounded-lg shadow-sm border ${getSeverityColor()}`}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full px-4 py-3 flex items-center justify-between hover:bg-gray-50 hover:bg-opacity-50 transition-colors focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-inset rounded-lg"
        aria-expanded={isOpen}
        aria-controls={`${sectionId}-content`}
        id={`${sectionId}-button`}
      >
        <div className="flex items-center gap-3">
          <span aria-hidden="true">{icon}</span>
          <h3 className="font-semibold text-gray-900">{title}</h3>
          {hasData && (
            <span className={`px-2 py-0.5 text-xs font-medium rounded-full ${getCountBadgeColor()}`} aria-label={`${count} items`}>
              {count}
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
            <div className="flex items-center gap-2 text-sm text-gray-700 py-3" role="status" aria-live="polite">
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-primary-600" aria-hidden="true"></div>
              <span>{t('validation.loading', { section: title.toLowerCase() })}</span>
            </div>
          ) : !hasData ? (
            <div className="flex items-center gap-2 text-sm text-gray-700 py-3">
              <CheckCircle className="w-4 h-4 text-green-600" aria-hidden="true" />
              <span>{t('validation.noIssues')}</span>
            </div>
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

export function ValidationPanel() {
  const { t } = useTranslation()

  // Validation-specific queries
  const fileParseStatus = useFileParseStatus()
  const initIssues = useInitIssues()
  const parseWarnings = useParseWarnings()
  const viConversionStatus = useVIConversionStatus()
  const unusedStructures = useUnusedStructures()
  const undefinedRefs = useUndefinedReferences()
  const forwardingLoops = useForwardingLoops()
  const multipathConsistency = useMultipathConsistency()
  const loopbackMultipathConsistency = useLoopbackMultipathConsistency()

  // Calculate overall validation status
  const hasErrors =
    (initIssues.data && Array.isArray(initIssues.data) && initIssues.data.length > 0) ||
    (undefinedRefs.data && Array.isArray(undefinedRefs.data) && undefinedRefs.data.length > 0) ||
    (forwardingLoops.data && Array.isArray(forwardingLoops.data) && forwardingLoops.data.length > 0) ||
    (multipathConsistency.data && Array.isArray(multipathConsistency.data) && multipathConsistency.data.length > 0) ||
    (loopbackMultipathConsistency.data && Array.isArray(loopbackMultipathConsistency.data) && loopbackMultipathConsistency.data.length > 0)

  /**
   * Check if any warning-level issues exist
   * Includes: parse warnings, unused structures
   */
  const hasWarnings =
    (parseWarnings.data && Array.isArray(parseWarnings.data) && parseWarnings.data.length > 0) ||
    (unusedStructures.data && Array.isArray(unusedStructures.data) && unusedStructures.data.length > 0)

  /**
   * Check if any validation query is still loading
   * Aggregates loading state from all validation data sources
   */
  const isLoading =
    fileParseStatus.isLoading ||
    initIssues.isLoading ||
    parseWarnings.isLoading ||
    viConversionStatus.isLoading ||
    unusedStructures.isLoading ||
    undefinedRefs.isLoading ||
    forwardingLoops.isLoading ||
    multipathConsistency.isLoading ||
    loopbackMultipathConsistency.isLoading

  return (
    <div className="space-y-4" role="region" aria-label="Network validation">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-gray-900">{t('validation.title')}</h2>
        {!isLoading && (
          <div className="flex items-center gap-2">
            {hasErrors ? (
              <span className="flex items-center gap-1.5 text-sm text-red-700 font-medium" role="status">
                <XCircle className="w-4 h-4" aria-hidden="true" />
                {t('validation.status.errorsFound')}
              </span>
            ) : hasWarnings ? (
              <span className="flex items-center gap-1.5 text-sm text-yellow-700 font-medium" role="status">
                <AlertTriangle className="w-4 h-4" aria-hidden="true" />
                {t('validation.status.warnings')}
              </span>
            ) : (
              <span className="flex items-center gap-1.5 text-sm text-green-700 font-medium" role="status">
                <CheckCircle className="w-4 h-4" aria-hidden="true" />
                {t('validation.status.allClear')}
              </span>
            )}
          </div>
        )}
      </div>

      <p className="text-sm text-gray-600">
        {t('validation.description')}
      </p>

      {/* Validation Sections */}
      <div className="space-y-3">
        {/* Critical Issues */}
        <Section
          title={t('validation.sections.initIssues')}
          icon={<XCircle className="w-5 h-5 text-red-600" />}
          isLoading={initIssues.isLoading}
          data={initIssues.data}
          defaultOpen={hasErrors}
          severity="error"
        />

        <Section
          title={t('validation.sections.undefinedReferences')}
          icon={<AlertCircle className="w-5 h-5 text-red-600" />}
          isLoading={undefinedRefs.isLoading}
          data={undefinedRefs.data}
          severity="error"
        />

        <Section
          title={t('validation.sections.forwardingLoops')}
          icon={<GitBranch className="w-5 h-5 text-red-600" />}
          isLoading={forwardingLoops.isLoading}
          data={forwardingLoops.data}
          severity="error"
        />

        <Section
          title={t('validation.sections.multipathConsistency')}
          icon={<AlertCircle className="w-5 h-5 text-red-600" />}
          isLoading={multipathConsistency.isLoading}
          data={multipathConsistency.data}
          severity="error"
        />

        <Section
          title={t('validation.sections.loopbackMultipathConsistency')}
          icon={<AlertCircle className="w-5 h-5 text-red-600" />}
          isLoading={loopbackMultipathConsistency.isLoading}
          data={loopbackMultipathConsistency.data}
          severity="error"
        />

        {/* Warnings */}
        <Section
          title={t('validation.sections.parseWarnings')}
          icon={<AlertTriangle className="w-5 h-5 text-yellow-600" />}
          isLoading={parseWarnings.isLoading}
          data={parseWarnings.data}
          defaultOpen={!hasErrors && hasWarnings}
          severity="warning"
        />

        <Section
          title={t('validation.sections.unusedStructures')}
          icon={<AlertTriangle className="w-5 h-5 text-yellow-600" />}
          isLoading={unusedStructures.isLoading}
          data={unusedStructures.data}
          severity="warning"
        />

        {/* Informational */}
        <Section
          title={t('validation.sections.fileParseStatus')}
          icon={<FileText className="w-5 h-5 text-blue-600" />}
          isLoading={fileParseStatus.isLoading}
          data={fileParseStatus.data}
        />

        <Section
          title={t('validation.sections.viConversionStatus')}
          icon={<FileText className="w-5 h-5 text-blue-600" />}
          isLoading={viConversionStatus.isLoading}
          data={viConversionStatus.data}
        />
      </div>
    </div>
  )
}

export default ValidationPanel