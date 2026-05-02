import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { AlertTriangle, CheckCircle, FileText, XCircle } from 'lucide-react'

import type { FileParseStatus, InitIssue, ParseWarning } from '../../types/validation'
import type { ParseResultSeverity, ParseResultSummary, ParseStatusBucket } from '../../lib/validation/parseResult'
import {
  buildFileParseStatusView,
  buildParseResultSummary,
  classifyInitIssue,
} from '../../lib/validation/parseResult'

const severityClasses: Record<ParseResultSeverity, string> = {
  success: 'border-green-200 bg-green-50 text-green-800',
  warning: 'border-yellow-200 bg-yellow-50 text-yellow-800',
  error: 'border-red-200 bg-red-50 text-red-800',
}

const severityIconClasses: Record<ParseResultSeverity, string> = {
  success: 'text-green-600',
  warning: 'text-yellow-600',
  error: 'text-red-600',
}

const statusBadgeClasses: Record<ParseStatusBucket, string> = {
  passed: 'bg-green-100 text-green-800',
  partial: 'bg-yellow-100 text-yellow-800',
  failed: 'bg-red-100 text-red-800',
  unknown: 'bg-gray-100 text-gray-700',
}

function ParseSeverityIcon({ severity }: { severity: ParseResultSeverity }) {
  if (severity === 'success') {
    return <CheckCircle className={`h-5 w-5 ${severityIconClasses[severity]}`} aria-hidden="true" />
  }
  if (severity === 'error') {
    return <XCircle className={`h-5 w-5 ${severityIconClasses[severity]}`} aria-hidden="true" />
  }
  return <AlertTriangle className={`h-5 w-5 ${severityIconClasses[severity]}`} aria-hidden="true" />
}

function formatDetectedFormats(summary: ParseResultSummary) {
  return Object.entries(summary.formats)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([format, count]) => `${format} ${count}`)
    .join(', ')
}

interface ParseResultSummaryCardProps {
  title: string
  summary: ParseResultSummary
  isLoading?: boolean
  compact?: boolean
  subtitle?: string
}

export function ParseResultSummaryCard({
  title,
  summary,
  isLoading = false,
  compact = false,
  subtitle,
}: ParseResultSummaryCardProps) {
  const { t } = useTranslation()
  const detectedFormats = formatDetectedFormats(summary)

  return (
    <section className={`rounded-lg border p-4 ${severityClasses[summary.severity]}`} aria-label={title}>
      <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
        <div className="flex min-w-0 items-start gap-3">
          <ParseSeverityIcon severity={summary.severity} />
          <div className="min-w-0">
            <h3 className="font-semibold text-gray-900">{title}</h3>
            {subtitle && <p className="mt-1 text-sm text-gray-700">{subtitle}</p>}
            {isLoading && (
              <p className="mt-1 text-sm font-medium text-blue-700" role="status">
                {t('validation.parseResult.loading')}
              </p>
            )}
          </div>
        </div>
        <span className="inline-flex w-fit rounded-full bg-white px-3 py-1 text-xs font-semibold text-gray-700 shadow-sm">
          {t(`validation.parseResult.severity.${summary.severity}`)}
        </span>
      </div>

      <div className={`mt-4 grid gap-3 ${compact ? 'grid-cols-2 lg:grid-cols-4' : 'grid-cols-2 xl:grid-cols-6'}`}>
        <Metric label={t('validation.parseResult.metrics.totalFiles')} value={summary.totalFiles} />
        <Metric label={t('validation.parseResult.metrics.passed')} value={summary.passedFiles} />
        <Metric label={t('validation.parseResult.metrics.partial')} value={summary.partialFiles} />
        <Metric label={t('validation.parseResult.metrics.failed')} value={summary.failedFiles} />
        <Metric label={t('validation.parseResult.metrics.initIssues')} value={summary.initIssues} />
        <Metric label={t('validation.parseResult.metrics.parseWarnings')} value={summary.parseWarnings} />
      </div>

      {!compact && (
        <div className="mt-3 grid gap-2 text-sm text-gray-700 md:grid-cols-2">
          <p>
            <span className="font-medium">{t('validation.parseResult.metrics.warningFiles')}:</span>{' '}
            {summary.warningFiles}
          </p>
          <p>
            <span className="font-medium">{t('validation.parseResult.metrics.detectedFormats')}:</span>{' '}
            {detectedFormats || t('common.none')}
          </p>
        </div>
      )}
    </section>
  )
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md bg-white px-3 py-2 shadow-sm">
      <div className="text-lg font-bold text-gray-900">{value}</div>
      <div className="text-xs font-medium text-gray-600">{label}</div>
    </div>
  )
}

interface ParseResultDetailsProps {
  fileStatuses?: FileParseStatus[]
  initIssues?: InitIssue[]
  parseWarnings?: ParseWarning[]
  isLoading: boolean
  isError?: boolean
  errorMessage?: string
}

export function ParseResultDetails({
  fileStatuses = [],
  initIssues = [],
  parseWarnings = [],
  isLoading,
  isError = false,
  errorMessage,
}: ParseResultDetailsProps) {
  const { t } = useTranslation()
  const [fileSearch, setFileSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState<ParseStatusBucket | 'all'>('all')
  const [issueSearch, setIssueSearch] = useState('')
  const [warningSearch, setWarningSearch] = useState('')

  const summary = useMemo(
    () => buildParseResultSummary(fileStatuses, initIssues, parseWarnings),
    [fileStatuses, initIssues, parseWarnings]
  )
  const displaySummary = isError ? { ...summary, severity: 'error' as const } : summary
  const fileRows = useMemo(
    () => buildFileParseStatusView(fileStatuses, initIssues, parseWarnings),
    [fileStatuses, initIssues, parseWarnings]
  )

  const normalizedFileSearch = fileSearch.trim().toLowerCase()
  const filteredFileRows = fileRows.filter((row) => {
    const matchesSearch =
      !normalizedFileSearch ||
      row.file_name.toLowerCase().includes(normalizedFileSearch) ||
      row.nodes.join(' ').toLowerCase().includes(normalizedFileSearch) ||
      String(row.file_format ?? '').toLowerCase().includes(normalizedFileSearch)
    const matchesStatus = statusFilter === 'all' || row.statusBucket === statusFilter
    return matchesSearch && matchesStatus
  })

  const normalizedIssueSearch = issueSearch.trim().toLowerCase()
  const filteredIssues = initIssues.filter((issue) => {
    if (!normalizedIssueSearch) return true
    return [
      issue.type,
      issue.details,
      issue.line_text,
      issue.parser_context,
      ...(issue.nodes ?? []),
      ...(issue.source_lines ?? []),
    ]
      .join(' ')
      .toLowerCase()
      .includes(normalizedIssueSearch)
  })

  const normalizedWarningSearch = warningSearch.trim().toLowerCase()
  const filteredWarnings = parseWarnings
    .filter((warning) => {
      if (!normalizedWarningSearch) return true
      return [warning.filename, warning.text, warning.parser_context, warning.comment]
        .join(' ')
        .toLowerCase()
        .includes(normalizedWarningSearch)
    })
    .sort((left, right) => {
      const fileCompare = left.filename.localeCompare(right.filename)
      return fileCompare === 0 ? left.line - right.line : fileCompare
    })

  return (
    <section className="space-y-4" aria-labelledby="parse-result-details-title">
      <ParseResultSummaryCard
        title={t('validation.parseResult.title')}
        subtitle={isError ? t('validation.parseResult.loadFailed') : t('validation.parseResult.subtitle')}
        summary={displaySummary}
        isLoading={isLoading}
      />
      {isError && (
        <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800" role="alert">
          <p className="font-semibold">{t('validation.parseResult.loadFailed')}</p>
          {errorMessage && <p className="mt-1 break-words">{errorMessage}</p>}
        </div>
      )}

      <div className="rounded-lg border border-gray-200 bg-white p-4">
        <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
          <div>
            <h3 id="parse-result-details-title" className="font-semibold text-gray-900">
              {t('validation.parseResult.fileStatusTitle')}
            </h3>
            <p className="mt-1 text-sm text-gray-600">{t('validation.parseResult.fileStatusHelp')}</p>
          </div>
          <div className="flex flex-col gap-2 sm:flex-row">
            <input
              type="search"
              value={fileSearch}
              onChange={(event) => setFileSearch(event.target.value)}
              placeholder={t('validation.parseResult.searchFiles')}
              className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-800 focus:border-primary-600 focus:outline-none focus:ring-2 focus:ring-primary-600"
              aria-label={t('validation.parseResult.searchFiles')}
            />
            <select
              value={statusFilter}
              onChange={(event) => setStatusFilter(event.target.value as ParseStatusBucket | 'all')}
              className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-800 focus:border-primary-600 focus:outline-none focus:ring-2 focus:ring-primary-600"
              aria-label={t('validation.parseResult.statusFilter')}
            >
              <option value="all">{t('validation.parseResult.statuses.all')}</option>
              <option value="passed">{t('validation.parseResult.statuses.passed')}</option>
              <option value="partial">{t('validation.parseResult.statuses.partial')}</option>
              <option value="failed">{t('validation.parseResult.statuses.failed')}</option>
              <option value="unknown">{t('validation.parseResult.statuses.unknown')}</option>
            </select>
          </div>
        </div>

        <div className="mt-4 overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200 text-sm">
            <thead className="bg-gray-50">
              <tr>
                <TableHeader>{t('validation.parseResult.columns.file')}</TableHeader>
                <TableHeader>{t('validation.parseResult.columns.status')}</TableHeader>
                <TableHeader>{t('validation.parseResult.columns.format')}</TableHeader>
                <TableHeader>{t('validation.parseResult.columns.nodes')}</TableHeader>
                <TableHeader>{t('validation.parseResult.columns.relatedWarnings')}</TableHeader>
                <TableHeader>{t('validation.parseResult.columns.relatedIssues')}</TableHeader>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 bg-white">
              {filteredFileRows.map((row) => (
                <tr key={row.file_name} className="hover:bg-gray-50">
                  <td className="max-w-md px-4 py-3 font-medium text-gray-900">
                    <span className="break-all">{row.file_name}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`rounded-full px-2 py-1 text-xs font-semibold ${statusBadgeClasses[row.statusBucket]}`}>
                      {row.status || t('common.unknown')}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-gray-700">{row.file_format || t('common.unknown')}</td>
                  <td className="px-4 py-3 text-gray-700">{row.nodes.join(', ') || t('common.none')}</td>
                  <td className="px-4 py-3 font-medium text-gray-800">{row.relatedWarningCount}</td>
                  <td className="px-4 py-3 font-medium text-gray-800">{row.relatedIssueCount}</td>
                </tr>
              ))}
              {filteredFileRows.length === 0 && <EmptyTableRow colSpan={6} />}
            </tbody>
          </table>
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <div className="rounded-lg border border-gray-200 bg-white p-4">
          <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-yellow-600" aria-hidden="true" />
              <h3 className="font-semibold text-gray-900">{t('validation.parseResult.initIssuesTitle')}</h3>
            </div>
            <input
              type="search"
              value={issueSearch}
              onChange={(event) => setIssueSearch(event.target.value)}
              placeholder={t('validation.parseResult.searchIssues')}
              className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-800 focus:border-primary-600 focus:outline-none focus:ring-2 focus:ring-primary-600"
              aria-label={t('validation.parseResult.searchIssues')}
            />
          </div>
          <div className="mt-4 max-h-96 overflow-auto">
            <table className="min-w-full divide-y divide-gray-200 text-sm">
              <thead className="bg-gray-50">
                <tr>
                  <TableHeader>{t('validation.parseResult.columns.severity')}</TableHeader>
                  <TableHeader>{t('validation.parseResult.columns.type')}</TableHeader>
                  <TableHeader>{t('validation.parseResult.columns.nodes')}</TableHeader>
                  <TableHeader>{t('validation.parseResult.columns.details')}</TableHeader>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 bg-white">
                {filteredIssues.map((issue, index) => {
                  const severity = classifyInitIssue(issue.type).severity
                  return (
                    <tr key={`${issue.type}-${index}`} className="align-top hover:bg-gray-50">
                      <td className="px-4 py-3">
                        <span className={`rounded-full px-2 py-1 text-xs font-semibold ${severityClasses[severity]}`}>
                          {t(`validation.parseResult.severity.${severity}`)}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-medium text-gray-900">{issue.type || t('common.unknown')}</td>
                      <td className="px-4 py-3 text-gray-700">{issue.nodes?.join(', ') || t('common.none')}</td>
                      <td className="max-w-lg px-4 py-3 text-gray-700">
                        <p>{issue.details || t('common.none')}</p>
                        {issue.line_text && <p className="mt-1 text-xs text-gray-600">{issue.line_text}</p>}
                        {issue.parser_context && <p className="mt-1 text-xs text-gray-500">{issue.parser_context}</p>}
                        {issue.source_lines?.length > 0 && (
                          <p className="mt-1 text-xs text-gray-500">{issue.source_lines.join(', ')}</p>
                        )}
                      </td>
                    </tr>
                  )
                })}
                {filteredIssues.length === 0 && <EmptyTableRow colSpan={4} />}
              </tbody>
            </table>
          </div>
        </div>

        <div className="rounded-lg border border-gray-200 bg-white p-4">
          <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
            <div className="flex items-center gap-2">
              <FileText className="h-5 w-5 text-blue-600" aria-hidden="true" />
              <h3 className="font-semibold text-gray-900">{t('validation.parseResult.parseWarningsTitle')}</h3>
            </div>
            <input
              type="search"
              value={warningSearch}
              onChange={(event) => setWarningSearch(event.target.value)}
              placeholder={t('validation.parseResult.searchWarnings')}
              className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-800 focus:border-primary-600 focus:outline-none focus:ring-2 focus:ring-primary-600"
              aria-label={t('validation.parseResult.searchWarnings')}
            />
          </div>
          <div className="mt-4 max-h-96 overflow-auto">
            <table className="min-w-full divide-y divide-gray-200 text-sm">
              <thead className="bg-gray-50">
                <tr>
                  <TableHeader>{t('validation.parseResult.columns.file')}</TableHeader>
                  <TableHeader>{t('validation.parseResult.columns.line')}</TableHeader>
                  <TableHeader>{t('validation.parseResult.columns.text')}</TableHeader>
                  <TableHeader>{t('validation.parseResult.columns.comment')}</TableHeader>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 bg-white">
                {filteredWarnings.map((warning, index) => (
                  <tr key={`${warning.filename}-${warning.line}-${index}`} className="align-top hover:bg-gray-50">
                    <td className="max-w-xs px-4 py-3 font-medium text-gray-900">
                      <span className="break-all">{warning.filename || t('common.unknown')}</span>
                    </td>
                    <td className="px-4 py-3 text-gray-700">{warning.line || t('common.notAvailable')}</td>
                    <td className="max-w-lg px-4 py-3 text-gray-700">
                      <p>{warning.text || t('common.none')}</p>
                      {warning.parser_context && <p className="mt-1 text-xs text-gray-500">{warning.parser_context}</p>}
                    </td>
                    <td className="max-w-sm px-4 py-3 text-gray-700">{warning.comment || t('common.none')}</td>
                  </tr>
                ))}
                {filteredWarnings.length === 0 && <EmptyTableRow colSpan={4} />}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <details className="rounded-lg border border-gray-200 bg-white p-4">
        <summary className="cursor-pointer text-sm font-semibold text-gray-800">
          {t('validation.parseResult.rawJson')}
        </summary>
        <pre className="mt-3 max-h-96 overflow-auto rounded-md bg-gray-50 p-3 text-xs text-gray-800">
          {JSON.stringify({ fileStatuses, initIssues, parseWarnings }, null, 2)}
        </pre>
      </details>
    </section>
  )
}

function TableHeader({ children }: { children: React.ReactNode }) {
  return (
    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-gray-700">
      {children}
    </th>
  )
}

function EmptyTableRow({ colSpan }: { colSpan: number }) {
  const { t } = useTranslation()
  return (
    <tr>
      <td colSpan={colSpan} className="px-4 py-6 text-center text-sm text-gray-600">
        {t('validation.parseResult.noRows')}
      </td>
    </tr>
  )
}
