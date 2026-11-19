import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Loader2 } from 'lucide-react'

import { useVersionDiff, useVersionFileDiff, WORKING_TREE } from '../hooks/useSnapshotVersions'
import type { VersionDiffStatus, VersionDiffSummary, VersionFileDiff } from '../types'
import { byteSizeLabel, historyErrorText } from './snapshotVersionLabels'

interface VersionDiffViewProps {
  snapshotName: string
  versionId: string
  against: string
  fromLabel: string
  againstLabel: string
}

const statusBadgeClass: Record<VersionDiffStatus, string> = {
  added: 'bg-green-50 text-green-800 border-green-200',
  removed: 'bg-red-50 text-red-800 border-red-200',
  modified: 'bg-yellow-50 text-yellow-900 border-yellow-200',
  unchanged: 'bg-gray-50 text-gray-700 border-gray-200',
}

const lineClass: Record<' ' | '+' | '-', string> = {
  ' ': 'text-gray-800',
  '+': 'bg-green-50 text-green-900',
  '-': 'bg-red-50 text-red-900',
}

function isEmptyAddedOrRemoved(file: VersionDiffSummary): boolean {
  return (file.status === 'added' && file.against_size === 0) || (file.status === 'removed' && file.size === 0)
}

function FileDiffBody({ diff, file }: { diff: VersionFileDiff; file: VersionDiffSummary }) {
  const { t } = useTranslation()

  if (diff.binary) {
    return <p className="px-3 py-2 text-sm text-gray-700">{t('snapshots.history.diff.binary')}</p>
  }
  if (diff.too_large) {
    return <p className="px-3 py-2 text-sm text-gray-700">{t('snapshots.history.diff.tooLarge')}</p>
  }
  if (diff.hunks.length === 0) {
    return diff.truncated ? (
      <p className="px-3 py-2 text-xs font-medium text-yellow-800" role="status">
        {t('snapshots.history.diff.truncated')}
      </p>
    ) : (
      <p className="px-3 py-2 text-sm text-gray-700">
        {isEmptyAddedOrRemoved(file) ? t('snapshots.history.diff.emptyFile') : t('snapshots.history.diff.noTextChanges')}
      </p>
    )
  }

  return (
    <div>
      <div className="overflow-x-auto font-mono text-xs leading-5">
        {diff.hunks.map((hunk, hunkIndex) => (
          <div key={`${hunk.old_start}-${hunk.new_start}-${hunkIndex}`}>
            <div className="bg-blue-50 px-3 text-blue-800">
              {`@@ -${hunk.old_start},${hunk.old_lines} +${hunk.new_start},${hunk.new_lines} @@`}
            </div>
            {hunk.lines.map((line, lineIndex) => (
              <div key={lineIndex} className={`whitespace-pre px-3 ${lineClass[line.type]}`}>
                {`${line.type}${line.text}`}
              </div>
            ))}
          </div>
        ))}
      </div>
      {diff.truncated && (
        <p className="border-t border-gray-200 px-3 py-2 text-xs font-medium text-yellow-800" role="status">
          {t('snapshots.history.diff.truncated')}
        </p>
      )}
    </div>
  )
}

function FileDiffPanel({
  snapshotName,
  versionId,
  against,
  file,
}: {
  snapshotName: string
  versionId: string
  against: string
  file: VersionDiffSummary
}) {
  const { t } = useTranslation()
  const path = file.path
  const fileDiffQuery = useVersionFileDiff(snapshotName, versionId, against, path)

  return (
    <div className="mt-2 rounded border border-gray-200 bg-white" role="region" aria-label={t('snapshots.history.diff.fileRegion', { path })}>
      <p className="border-b border-gray-200 bg-gray-50 px-3 py-1.5 font-mono text-xs font-semibold text-gray-800 break-all">
        {path}
      </p>
      {fileDiffQuery.isLoading && (
        <p className="flex items-center gap-2 px-3 py-2 text-sm text-gray-700" role="status">
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
          {t('snapshots.history.diff.loadingFile')}
        </p>
      )}
      {fileDiffQuery.isError && (
        <p className="px-3 py-2 text-sm text-red-700" role="alert">
          {historyErrorText(t, fileDiffQuery.error, 'snapshots.history.diff.fileLoadFailed')}
        </p>
      )}
      {fileDiffQuery.data && <FileDiffBody diff={fileDiffQuery.data} file={file} />}
    </div>
  )
}

/**
 * Diff summary from a version to another version or the working tree, with the diff of a selected file
 */
export function VersionDiffView({ snapshotName, versionId, against, fromLabel, againstLabel }: VersionDiffViewProps) {
  const { t } = useTranslation()
  const diffQuery = useVersionDiff(snapshotName, versionId, against)
  const [selectedPath, setSelectedPath] = useState<string | null>(null)
  const [showUnchanged, setShowUnchanged] = useState(false)

  const files: VersionDiffSummary[] = diffQuery.data?.files ?? []
  const changedFiles = files.filter((file) => file.status !== 'unchanged')
  const visibleFiles = showUnchanged ? files : changedFiles
  const selectedFile = files.find((file) => file.path === selectedPath) ?? null

  return (
    <div className="space-y-2" role="region" aria-label={t('snapshots.history.diff.region', { from: fromLabel, against: againstLabel })}>
      <p className="text-sm font-medium text-gray-900">
        {t('snapshots.history.diff.heading', { from: fromLabel, against: againstLabel })}
      </p>
      {diffQuery.isLoading && (
        <p className="flex items-center gap-2 text-sm text-gray-700" role="status">
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
          {t('snapshots.history.diff.loading')}
        </p>
      )}
      {diffQuery.isError && (
        <p className="text-sm text-red-700" role="alert">
          {historyErrorText(t, diffQuery.error, 'snapshots.history.diff.loadFailed')}
        </p>
      )}
      {diffQuery.data && (
        <>
          <p className="text-xs text-gray-600">
            {t('snapshots.history.diff.summary', {
              changed: changedFiles.length,
              count: files.length,
            })}
          </p>
          {files.length > changedFiles.length && (
            <label className="flex items-center gap-2 text-xs text-gray-700">
              <input
                type="checkbox"
                checked={showUnchanged}
                onChange={(event) => setShowUnchanged(event.target.checked)}
                className="h-4 w-4 rounded border-gray-300"
              />
              {t('snapshots.history.diff.showUnchanged')}
            </label>
          )}
          {visibleFiles.length === 0 ? (
            <p className="text-sm text-gray-700">{t('snapshots.history.diff.noChanges')}</p>
          ) : (
            <ul className="divide-y divide-gray-100 rounded border border-gray-200 bg-white" aria-label={t('snapshots.history.diff.fileList')}>
              {visibleFiles.map((file) => (
                <li key={file.path}>
                  <button
                    type="button"
                    onClick={() => setSelectedPath(file.path === selectedPath ? null : file.path)}
                    aria-pressed={file.path === selectedPath}
                    className="flex w-full items-center gap-3 px-3 py-1.5 text-left text-sm hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-primary-600"
                  >
                    <span className={`rounded border px-1.5 py-0.5 text-xs font-medium ${statusBadgeClass[file.status]}`}>
                      {t(`snapshots.history.diff.status.${file.status}`)}
                    </span>
                    <span className="min-w-0 flex-1 break-all font-mono text-xs text-gray-900">{file.path}</span>
                    <span className="whitespace-nowrap text-xs text-gray-600">
                      {t('snapshots.history.diff.sizes', {
                        from: byteSizeLabel(t, file.size),
                        against: byteSizeLabel(t, file.against_size),
                      })}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
          {selectedFile && (
            <FileDiffPanel
              key={`${versionId}-${against}-${selectedFile.path}`}
              snapshotName={snapshotName}
              versionId={versionId}
              against={against}
              file={selectedFile}
            />
          )}
          {against === WORKING_TREE && (
            <p className="text-xs text-gray-600">{t('snapshots.history.diff.workingNote')}</p>
          )}
        </>
      )}
    </div>
  )
}
