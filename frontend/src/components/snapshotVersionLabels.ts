import type { TFunction } from 'i18next'
import { isAxiosError } from 'axios'

import {
  getVersionErrorCode,
  getVersionErrorStatus,
  getVersioningUnavailableReason,
} from '../hooks/useSnapshotVersions'
import { isContentHashMismatchError, isSnapshotMismatchError } from '../hooks/useNetwork'
import type { SnapshotVersion, SnapshotVersionKind, VersionRef, VersioningUnavailableReason } from '../types'

const SHORT_HASH_LENGTH = 8

export function isSystemVersionKind(kind: SnapshotVersionKind): boolean {
  return kind === 'baseline' || kind === 'external'
}

export function shortContentHash(hash: string | null | undefined): string {
  return hash ? hash.slice(0, SHORT_HASH_LENGTH) : ''
}

/**
 * Commit message for display: system versions get a localized label derived from `kind`
 */
export function versionMessageLabel(t: TFunction, version: Pick<SnapshotVersion, 'kind' | 'message'>): string {
  return isSystemVersionKind(version.kind) ? t(`overview.version.systemMessage.${version.kind}`) : version.message
}

/**
 * Author for display: "System" for system versions, a dash when no author was recorded
 */
export function versionAuthorLabel(t: TFunction, version: Pick<SnapshotVersion, 'kind' | 'author'>): string {
  if (isSystemVersionKind(version.kind)) return t('overview.version.systemAuthor')
  return version.author ?? t('overview.version.noAuthor')
}

export function versionKindLabel(t: TFunction, kind: SnapshotVersionKind): string {
  return t(`overview.version.kind.${kind}`)
}

/**
 * "vN", or "vN (deleted)" when the referenced version no longer exists
 */
export function versionRefLabel(t: TFunction, ref: VersionRef): string {
  return ref.version_id === null
    ? t('overview.version.deletedVersionLabel', { seq: ref.seq })
    : t('overview.version.versionLabel', { seq: ref.seq })
}

/**
 * Labels joined with the separator of the current language
 */
export function joinLabels(t: TFunction, labels: (string | null | false | undefined)[]): string {
  return labels.filter((label): label is string => !!label).join(t('overview.version.separator'))
}

export function versioningReasonLabel(t: TFunction, reason: VersioningUnavailableReason | 'unknown'): string {
  return t(`snapshots.history.reasons.${reason}`)
}

export function byteSizeLabel(t: TFunction, size: number | null): string {
  return size === null ? t('snapshots.history.diff.noSize') : t('snapshots.history.diff.bytes', { size })
}

/**
 * Localized text for a failed history or diff request; never the server's or the HTTP client's message
 */
export function historyErrorText(t: TFunction, error: unknown, fallbackKey: string): string {
  const reason = getVersioningUnavailableReason(error)
  if (reason) return t('snapshots.history.errors.unavailable', { reason: versioningReasonLabel(t, reason) })
  if (isAxiosError(error) && !error.response) return t('errors.networkError')
  switch (getVersionErrorCode(error)) {
    case 'version_not_found':
      return t('snapshots.history.errors.versionNotFound')
    case 'version_unchanged':
      return t('snapshots.history.errors.unchanged')
    case 'version_conflict':
      return t('snapshots.history.errors.conflict')
    case 'restore_failed':
      return t('snapshots.history.errors.restoreFailed')
    case 'snapshot_not_found':
      return t('snapshots.history.errors.snapshotUnavailable')
    case 'validation_error':
      return t('snapshots.history.errors.invalidRequest')
  }
  if (getVersionErrorStatus(error) === 403) return t('snapshots.history.errors.snapshotUnavailable')
  return t(fallbackKey)
}

/**
 * Localized text for the identity mismatch errors of the hash-keyed network queries, null for any other error
 */
export function hashKeyedErrorText(t: TFunction, error: unknown): string | null {
  if (isSnapshotMismatchError(error)) return t('overview.version.snapshotMismatch')
  if (isContentHashMismatchError(error)) return t('overview.version.contentMismatch')
  return null
}

export const versionKindBadgeClass: Record<SnapshotVersionKind, string> = {
  baseline: 'bg-gray-100 text-gray-800 border-gray-300',
  manual: 'bg-blue-50 text-blue-800 border-blue-200',
  external: 'bg-purple-50 text-purple-800 border-purple-200',
  restore: 'bg-amber-50 text-amber-800 border-amber-200',
}
