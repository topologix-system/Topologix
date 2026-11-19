import { fireEvent, render, screen, within } from '@testing-library/react'
import { QueryClientProvider } from '@tanstack/react-query'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { translateEn } from '../__tests__/translateEn'
import { translateJa } from '../__tests__/translateJa'
import { createTestQueryClient, httpError, networkError, versioningUnavailable } from '../__tests__/versioning'
import { snapshotAPI } from '../services/api'
import type { VersionDiffResponse, VersionFileDiff } from '../types'
import { VersionDiffView } from './VersionDiffView'

const translation = vi.hoisted(() => ({ locale: 'en' as 'en' | 'ja' }))

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string, params?: Record<string, unknown>) =>
      translation.locale === 'ja' ? translateJa(key, params) : translateEn(key, params),
  }),
}))

const summary: VersionDiffResponse = {
  from: 'version-1',
  against: 'working',
  working_content_hash: 'w'.repeat(64),
  files: [
    { path: 'configs/r1.cfg', status: 'modified', size: 10, against_size: 12 },
    { path: 'configs/r2.cfg', status: 'unchanged', size: 5, against_size: 5 },
    { path: 'configs/r3.cfg', status: 'added', size: null, against_size: 7 },
  ],
}

const fileDiff = (overrides: Partial<VersionFileDiff>): VersionFileDiff => ({
  path: 'configs/r1.cfg',
  binary: false,
  too_large: false,
  truncated: false,
  hunks: [],
  ...overrides,
})

function renderView() {
  const queryClient = createTestQueryClient()
  return render(
    <QueryClientProvider client={queryClient}>
      <VersionDiffView snapshotName="snap-a" versionId="version-1" against="working" fromLabel="v1" againstLabel="Working files" />
    </QueryClientProvider>
  )
}

describe('VersionDiffView', () => {
  afterEach(() => {
    vi.restoreAllMocks()
    translation.locale = 'en'
  })

  it('lists the changed files of the summary and renders the unified hunks of a selected file', async () => {
    const getDiff = vi.spyOn(snapshotAPI, 'getVersionDiff').mockResolvedValue(summary)
    const getFileDiff = vi.spyOn(snapshotAPI, 'getVersionFileDiff').mockResolvedValue(
      fileDiff({
        hunks: [
          {
            old_start: 1,
            old_lines: 2,
            new_start: 1,
            new_lines: 2,
            lines: [
              { type: ' ', text: 'hostname r1' },
              { type: '-', text: ' ip address 10.0.0.1' },
              { type: '+', text: ' ip address 10.0.0.2' },
            ],
          },
        ],
      })
    )
    renderView()

    expect(await screen.findByText('configs/r1.cfg')).toBeInTheDocument()
    expect(getDiff).toHaveBeenCalledWith('snap-a', 'version-1', 'working')
    expect(screen.queryByText('configs/r2.cfg')).not.toBeInTheDocument()
    expect(screen.getByText('2 of 3 files changed')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /configs\/r1\.cfg/ }))

    expect(await screen.findByText('@@ -1,2 +1,2 @@')).toBeInTheDocument()
    expect(screen.getByText('- ip address 10.0.0.1')).toBeInTheDocument()
    expect(screen.getByText('+ ip address 10.0.0.2')).toBeInTheDocument()
    expect(getFileDiff).toHaveBeenCalledWith('snap-a', 'version-1', 'working', 'configs/r1.cfg')
  })

  it.each([
    ['binary', fileDiff({ binary: true }), 'This file is binary or not UTF-8 text: no text differences are shown.'],
    ['too_large', fileDiff({ too_large: true }), 'This file is too large or too complex to show a diff.'],
  ])('renders the %s state without hunks', async (_label, diff, message) => {
    vi.spyOn(snapshotAPI, 'getVersionDiff').mockResolvedValue(summary)
    vi.spyOn(snapshotAPI, 'getVersionFileDiff').mockResolvedValue(diff)
    renderView()

    fireEvent.click(await screen.findByRole('button', { name: /configs\/r1\.cfg/ }))

    expect(await screen.findByText(message)).toBeInTheDocument()
    expect(screen.queryByText(/^@@/)).not.toBeInTheDocument()
  })

  it('renders the hunks and a notice for a truncated diff', async () => {
    vi.spyOn(snapshotAPI, 'getVersionDiff').mockResolvedValue(summary)
    vi.spyOn(snapshotAPI, 'getVersionFileDiff').mockResolvedValue(
      fileDiff({
        truncated: true,
        hunks: [{ old_start: 1, old_lines: 1, new_start: 1, new_lines: 1, lines: [{ type: '+', text: 'line' }] }],
      })
    )
    renderView()

    fireEvent.click(await screen.findByRole('button', { name: /configs\/r1\.cfg/ }))

    expect(await screen.findByText('+line')).toBeInTheDocument()
    expect(screen.getByText('The differences were cut at the line limit; lines beyond it are not shown.')).toBeInTheDocument()
  })

  it('shows the truncation notice, not "No text differences.", for a truncated diff without hunks', async () => {
    vi.spyOn(snapshotAPI, 'getVersionDiff').mockResolvedValue(summary)
    vi.spyOn(snapshotAPI, 'getVersionFileDiff').mockResolvedValue(fileDiff({ truncated: true, hunks: [] }))
    renderView()

    fireEvent.click(await screen.findByRole('button', { name: /configs\/r1\.cfg/ }))

    expect(
      await screen.findByText('The differences were cut at the line limit; lines beyond it are not shown.')
    ).toBeInTheDocument()
    expect(screen.queryByText('No text differences.')).not.toBeInTheDocument()
  })

  it('shows "No text differences." for an untruncated diff without hunks', async () => {
    vi.spyOn(snapshotAPI, 'getVersionDiff').mockResolvedValue(summary)
    vi.spyOn(snapshotAPI, 'getVersionFileDiff').mockResolvedValue(fileDiff({ hunks: [] }))
    renderView()

    fireEvent.click(await screen.findByRole('button', { name: /configs\/r1\.cfg/ }))

    expect(await screen.findByText('No text differences.')).toBeInTheDocument()
    expect(screen.queryByText(/line limit/)).not.toBeInTheDocument()
  })

  it.each([
    ['en', 'Files', 'Show unchanged files', 'Changed files'],
    ['ja', 'ファイル', '変更のないファイルも表示', '変更されたファイル'],
  ] as const)('labels the file list truly under %s with and without unchanged files shown', async (locale, label, toggle, changedOnlyLabel) => {
    translation.locale = locale
    vi.spyOn(snapshotAPI, 'getVersionDiff').mockResolvedValue(summary)
    renderView()

    const changedOnly = await screen.findByRole('list', { name: label })
    expect(within(changedOnly).getByText('configs/r1.cfg')).toBeInTheDocument()
    expect(within(changedOnly).queryByText('configs/r2.cfg')).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('checkbox', { name: toggle }))

    const withUnchanged = screen.getByRole('list', { name: label })
    expect(within(withUnchanged).getByText('configs/r1.cfg')).toBeInTheDocument()
    expect(within(withUnchanged).getByText('configs/r2.cfg')).toBeInTheDocument()
    expect(screen.queryByRole('list', { name: changedOnlyLabel })).not.toBeInTheDocument()
  })

  it.each([
    ['an added', { path: 'configs/empty.cfg', status: 'added', size: null, against_size: 0 }, 'Added'],
    ['a removed', { path: 'configs/empty.cfg', status: 'removed', size: 0, against_size: null }, 'Removed'],
  ] as const)('shows "The file is empty." for %s empty file instead of "No text differences."', async (_label, file, badge) => {
    vi.spyOn(snapshotAPI, 'getVersionDiff').mockResolvedValue({ ...summary, files: [file] })
    vi.spyOn(snapshotAPI, 'getVersionFileDiff').mockResolvedValue(fileDiff({ path: file.path, hunks: [] }))
    renderView()

    const button = await screen.findByRole('button', { name: /configs\/empty\.cfg/ })
    expect(within(button).getByText(badge)).toBeInTheDocument()
    fireEvent.click(button)

    expect(await screen.findByText('The file is empty.')).toBeInTheDocument()
    expect(screen.queryByText('No text differences.')).not.toBeInTheDocument()
  })
})

describe('VersionDiffView errors', () => {
  afterEach(() => {
    vi.restoreAllMocks()
    translation.locale = 'en'
  })

  it.each([
    ['versioning unavailable', versioningUnavailable('storage'), 'バージョン管理を利用できません（履歴の保存領域の問題）。'],
    ['a network error', networkError(), 'ネットワークエラーが発生しました'],
    ['a 500 with a server message', httpError(500, { status: 'error', message: 'Failed to diff snapshot version' }), '差分の読み込みに失敗しました。'],
    ['an axios error without a body', httpError(500, ''), '差分の読み込みに失敗しました。'],
  ])('shows localized text for %s in Japanese, never the server or client message', async (_label, error, message) => {
    translation.locale = 'ja'
    vi.spyOn(snapshotAPI, 'getVersionDiff').mockRejectedValue(error)
    renderView()

    expect(await screen.findByText(message)).toBeInTheDocument()
    expect(screen.queryByText(/Failed to diff|Request failed|Network Error/)).not.toBeInTheDocument()
  })

  it('shows localized text for a failed file diff in Japanese', async () => {
    translation.locale = 'ja'
    vi.spyOn(snapshotAPI, 'getVersionDiff').mockResolvedValue(summary)
    vi.spyOn(snapshotAPI, 'getVersionFileDiff').mockRejectedValue(
      httpError(400, { status: 'error', message: "'path' is not a file of either side of the diff", code: 'validation_error' })
    )
    renderView()

    fireEvent.click(await screen.findByRole('button', { name: /configs\/r1\.cfg/ }))

    expect(await screen.findByText('リクエストが無効なため受け付けられませんでした。')).toBeInTheDocument()
    expect(screen.queryByText(/is not a file/)).not.toBeInTheDocument()
  })
})
