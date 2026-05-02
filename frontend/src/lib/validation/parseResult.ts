import type { FileParseStatus, InitIssue, ParseWarning } from '../../types/validation'

export type ParseResultSeverity = 'success' | 'warning' | 'error'
export type ParseStatusBucket = 'passed' | 'partial' | 'failed' | 'unknown'

export interface ParseStatusClassification {
  bucket: ParseStatusBucket
  severity: ParseResultSeverity
}

export interface InitIssueClassification {
  severity: Exclude<ParseResultSeverity, 'success'>
}

export interface FileParseStatusView extends FileParseStatus {
  statusBucket: ParseStatusBucket
  severity: ParseResultSeverity
  relatedWarningCount: number
  relatedIssueCount: number
}

export interface ParseResultSummary {
  totalFiles: number
  passedFiles: number
  partialFiles: number
  failedFiles: number
  unknownFiles: number
  warningFiles: number
  affectedFiles: number
  initIssues: number
  initIssueErrors: number
  parseWarnings: number
  formats: Record<string, number>
  severity: ParseResultSeverity
}

const normalizeText = (value: unknown) => String(value ?? '').trim()

const basename = (value: string) => {
  const normalized = value.replace(/\\/g, '/')
  const parts = normalized.split('/')
  return parts[parts.length - 1] || normalized
}

export function classifyParseStatus(status: string | null | undefined): ParseStatusClassification {
  const normalized = normalizeText(status).toUpperCase()

  if (normalized === 'PASSED') {
    return { bucket: 'passed', severity: 'success' }
  }

  if (normalized.includes('PARTIAL')) {
    return { bucket: 'partial', severity: 'warning' }
  }

  if (normalized.includes('FAIL') || normalized.includes('ERROR') || normalized === 'EMPTY') {
    return { bucket: 'failed', severity: 'error' }
  }

  if (!normalized) {
    return { bucket: 'unknown', severity: 'warning' }
  }

  return { bucket: 'failed', severity: 'error' }
}

export function classifyInitIssue(type: string | null | undefined): InitIssueClassification {
  const normalized = normalizeText(type).toLowerCase()
  if (normalized.includes('error') || normalized.includes('fatal')) {
    return { severity: 'error' }
  }
  return { severity: 'warning' }
}

export function groupWarningsByFile(parseWarnings: ParseWarning[] = []) {
  const grouped = new Map<string, ParseWarning[]>()

  for (const warning of parseWarnings) {
    const filename = normalizeText(warning.filename) || 'unknown'
    grouped.set(filename, [...(grouped.get(filename) ?? []), warning])
  }

  return grouped
}

function sourceLineMatchesFile(sourceLine: string, fileName: string) {
  const source = sourceLine.toLowerCase()
  const fullName = fileName.toLowerCase()
  const baseName = basename(fileName).toLowerCase()

  return source.includes(fullName) || (!!baseName && source.includes(baseName))
}

export function issueMatchesFile(issue: InitIssue, fileName: string) {
  return (issue.source_lines ?? []).some((sourceLine) => sourceLineMatchesFile(sourceLine, fileName))
}

export function groupIssuesByFile(fileStatuses: FileParseStatus[] = [], initIssues: InitIssue[] = []) {
  const grouped = new Map<string, InitIssue[]>()

  for (const status of fileStatuses) {
    const matchedIssues = initIssues.filter((issue) => issueMatchesFile(issue, status.file_name))
    if (matchedIssues.length > 0) {
      grouped.set(status.file_name, matchedIssues)
    }
  }

  return grouped
}

export function buildFileParseStatusView(
  fileStatuses: FileParseStatus[] = [],
  initIssues: InitIssue[] = [],
  parseWarnings: ParseWarning[] = []
): FileParseStatusView[] {
  const warningsByFile = groupWarningsByFile(parseWarnings)
  const issuesByFile = groupIssuesByFile(fileStatuses, initIssues)

  return fileStatuses.map((fileStatus) => {
    const classification = classifyParseStatus(fileStatus.status)
    const baseName = basename(fileStatus.file_name)
    const directWarningCount = warningsByFile.get(fileStatus.file_name)?.length ?? 0
    const basenameWarningCount =
      baseName === fileStatus.file_name ? 0 : warningsByFile.get(baseName)?.length ?? 0
    const warningCount =
      directWarningCount + basenameWarningCount

    return {
      ...fileStatus,
      statusBucket: classification.bucket,
      severity: classification.severity,
      relatedWarningCount: warningCount,
      relatedIssueCount: issuesByFile.get(fileStatus.file_name)?.length ?? 0,
    }
  })
}

export function buildParseResultSummary(
  fileStatuses: FileParseStatus[] = [],
  initIssues: InitIssue[] = [],
  parseWarnings: ParseWarning[] = []
): ParseResultSummary {
  const summary: ParseResultSummary = {
    totalFiles: fileStatuses.length,
    passedFiles: 0,
    partialFiles: 0,
    failedFiles: 0,
    unknownFiles: 0,
    warningFiles: 0,
    affectedFiles: 0,
    initIssues: initIssues.length,
    initIssueErrors: initIssues.filter((issue) => classifyInitIssue(issue.type).severity === 'error').length,
    parseWarnings: parseWarnings.length,
    formats: {},
    severity: 'success',
  }

  const affectedFiles = new Set<string>()
  const warningFiles = new Set<string>()

  for (const status of fileStatuses) {
    const classification = classifyParseStatus(status.status)
    const fileName = normalizeText(status.file_name)

    if (classification.bucket === 'passed') summary.passedFiles += 1
    if (classification.bucket === 'partial') summary.partialFiles += 1
    if (classification.bucket === 'failed') summary.failedFiles += 1
    if (classification.bucket === 'unknown') summary.unknownFiles += 1

    if (classification.severity !== 'success' && fileName) {
      affectedFiles.add(fileName)
    }

    const format = normalizeText(status.file_format) || 'unknown'
    summary.formats[format] = (summary.formats[format] ?? 0) + 1
  }

  for (const warning of parseWarnings) {
    const fileName = normalizeText(warning.filename)
    if (fileName) {
      affectedFiles.add(fileName)
      warningFiles.add(fileName)
    }
  }

  for (const issue of initIssues) {
    for (const sourceLine of issue.source_lines ?? []) {
      const source = normalizeText(sourceLine)
      if (source) affectedFiles.add(source)
    }
  }

  summary.warningFiles = warningFiles.size
  summary.affectedFiles = affectedFiles.size

  if (summary.failedFiles > 0 || summary.initIssueErrors > 0) {
    summary.severity = 'error'
  } else if (
    summary.partialFiles > 0 ||
    summary.unknownFiles > 0 ||
    summary.parseWarnings > 0 ||
    summary.initIssues > 0
  ) {
    summary.severity = 'warning'
  }

  return summary
}
