import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { createMemoryRouter, RouterProvider } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { Snapshot, SnapshotFile } from '../types'
import { useSnapshotStore } from '../store'
import { SnapshotManagement } from './SnapshotManagement'

const testState = vi.hoisted(() => ({
  files: [] as SnapshotFile[],
  snapshots: [] as Snapshot[],
  refreshFiles: () => {},
  configRefetch: vi.fn(),
  uploadMutate: vi.fn(),
  contentSaveConflict: false,
  failFormatChange: null as ((error: unknown) => void) | null,
  contentLoadError: false,
}))

vi.mock('../hooks', async () => {
  const { useState } = await import('react')
  const { AxiosError } = await import('axios')
  const idleMutation = () => ({
    isPending: false,
    variables: undefined,
    mutate: vi.fn(),
  })

  return {
    snapshotKeys: {
      files: (name: string) => ['snapshots', name, 'files'],
    },
    useSnapshots: () => ({ data: testState.snapshots, isLoading: false }),
    useSnapshotFiles: () => {
      const [, setRevision] = useState(0)
      testState.refreshFiles = () => setRevision((revision) => revision + 1)
      return { data: testState.files }
    },
    useConfigFileContent: (_name: string, filename: string, enabled: boolean) => ({
      data: enabled && !testState.contentLoadError
        ? {
            content: `hostname ${filename.replace('.cfg', '')}\ninterface Ethernet0\n`,
            sha256: 'a'.repeat(64),
            size_bytes: 46,
          }
        : undefined,
      isLoading: false,
      isError: enabled && testState.contentLoadError,
      error: enabled && testState.contentLoadError ? new Error('content unavailable') : null,
      refetch: testState.configRefetch,
    }),
    useCreateSnapshot: idleMutation,
    useDeleteSnapshot: () => ({
      isPending: false,
      variables: undefined,
      mutate: (
        _name: string,
        options?: { onSuccess?: () => void }
      ) => options?.onSuccess?.(),
    }),
    useUpdateSnapshot: idleMutation,
    useUploadFile: () => ({
      isPending: false,
      variables: undefined,
      mutate: testState.uploadMutate,
      mutateAsync: testState.uploadMutate,
    }),
    useUpdateSnapshotFileFormat: () => ({
      isPending: false,
      variables: undefined,
      mutate: (_variables: unknown, options?: { onError?: (error: unknown) => void }) => {
        testState.failFormatChange = (error) => options?.onError?.(error)
      },
    }),
    useUpdateConfigFileContent: () => ({
      isPending: false,
      variables: undefined,
      mutate: (
        _variables: unknown,
        options?: { onError?: (error: unknown) => void }
      ) => {
        if (testState.contentSaveConflict) {
          options?.onError?.(
            Object.assign(new AxiosError('conflict'), { response: { status: 409 } })
          )
        }
      },
    }),
    useDeleteSnapshotFile: idleMutation,
    useActivateSnapshot: idleMutation,
    useParseResultSummary: () => ({
      summary: {
        severity: 'success',
        totalFiles: 0,
        passedFiles: 0,
        partialFiles: 0,
        failedFiles: 0,
        unknownFiles: 0,
        warningFiles: 0,
        initIssues: 0,
        parseWarnings: 0,
        formats: {},
        failedFileNames: [],
        partialFileNames: [],
        unknownFileNames: [],
      },
      isLoading: false,
      isError: false,
    }),
  }
})

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string, params?: Record<string, string | number>) => {
      const translations: Record<string, string> = {
        'snapshots.configEditor.viewEditAria': `View or edit file ${params?.name ?? ''}`,
        'snapshots.configEditor.deleted': 'This file was deleted before the save finished.',
        'snapshots.configEditor.saveAsNew': 'Save as new file',
        'snapshots.configEditor.discardChanges': 'Discard your unsaved config changes?',
        'snapshots.configEditor.title': `Editing ${params?.name ?? ''}`,
        'snapshots.configEditor.unsavedChanges': 'Unsaved changes',
        'snapshots.fileList': 'File list',
        'snapshots.fileCount': `${params?.count ?? ''} files`,
      }
      return translations[key] ?? key
    },
  }),
}))

vi.mock('../components/ConfigFileEditor', () => ({
  ConfigFileEditor: ({
    filename,
    draft,
    onDraftChange,
    onSave,
  }: {
    filename: string
    draft: string
    onDraftChange: (content: string) => void
    onSave: () => void
  }) => (
    <>
      <textarea
        aria-label={`Editor for ${filename}`}
        value={draft}
        onChange={(event) => onDraftChange(event.target.value)}
      />
      <button type="button" onClick={onSave}>
        Save editor
      </button>
    </>
  ),
}))

vi.mock('../components/AdvancedArtifactPanel', () => ({
  AdvancedArtifactPanel: () => null,
}))

vi.mock('../components/SnapshotHistoryPanel', () => ({
  SnapshotHistoryPanel: () => null,
}))

vi.mock('../components/SnapshotFolderCombobox', () => ({
  SnapshotFolderCombobox: () => null,
}))

vi.mock('../components/validation/ParseResultDetails', () => ({
  ParseResultSummaryCard: () => null,
}))

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  const router = createMemoryRouter(
    [
      { path: '/snapshots', element: <SnapshotManagement /> },
      { path: '/', element: <div>Topology</div> },
    ],
    { initialEntries: ['/snapshots'] }
  )

  const tree = () => (
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  )
  return render(tree())
}

describe('SnapshotManagement config draft hardening', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    testState.snapshots = [
      {
        name: 'snapshot-a',
        file_count: 1,
        created_at: '2026-01-01T00:00:00Z',
        size_bytes: 46,
      },
      {
        name: 'snapshot-b',
        file_count: 0,
        created_at: '2026-01-02T00:00:00Z',
        size_bytes: 0,
      },
    ]
    testState.files = [
      {
        name: 'router.cfg',
        size_bytes: 46,
        modified_at: '2026-01-01T00:00:00Z',
      },
    ]
    testState.contentSaveConflict = false
    testState.configRefetch.mockReset()
    testState.uploadMutate.mockReset()
    testState.configRefetch.mockResolvedValue({
      isSuccess: true,
      data: {
        content: 'hostname router\ninterface Ethernet0\n',
        sha256: 'b'.repeat(64),
        size_bytes: 36,
      },
    })
    useSnapshotStore.setState({
      currentSnapshotName: null,
      isSnapshotActivationInProgress: false,
      activatingSnapshotName: null,
    })
  })

  it('keeps a dirty draft and save-as-new action when a files refetch omits the edited file', async () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: /Snapshot snapshot-a / }))
    fireEvent.click(
      await screen.findByRole('button', { name: 'View or edit file router.cfg' })
    )

    const editor = await screen.findByRole('textbox', { name: 'Editor for router.cfg' })
    const dirtyDraft = 'hostname recovered-router\ninterface Ethernet0\nrouter ospf 1\n'
    fireEvent.change(editor, { target: { value: dirtyDraft } })

    testState.files = []
    act(() => testState.refreshFiles())

    await waitFor(() => {
      expect(screen.getByRole('textbox', { name: 'Editor for router.cfg' })).toHaveValue(
        dirtyDraft
      )
    })
    expect(screen.getByRole('button', { name: 'Save as new file' })).toBeInTheDocument()
  })

  it('requires confirmation before switching snapshots and cancel keeps the draft', async () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: /Snapshot snapshot-a / }))
    fireEvent.click(
      await screen.findByRole('button', { name: 'View or edit file router.cfg' })
    )

    const editor = await screen.findByRole('textbox', { name: 'Editor for router.cfg' })
    const dirtyDraft = 'hostname stay-here\ninterface Ethernet0\nrouter bgp 65000\n'
    fireEvent.change(editor, { target: { value: dirtyDraft } })
    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(false)

    fireEvent.click(screen.getByRole('button', { name: /Snapshot snapshot-b / }))

    expect(confirmSpy).toHaveBeenCalledWith('Discard your unsaved config changes?')
    expect(screen.getByRole('textbox', { name: 'Editor for router.cfg' })).toHaveValue(
      dirtyDraft
    )
    expect(screen.getByRole('button', { name: /Snapshot snapshot-a / })).toHaveAttribute(
      'aria-pressed',
      'true'
    )
  })

  it('clears the dirty config guard when deleting the selected snapshot', async () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: /Snapshot snapshot-a / }))
    fireEvent.click(
      await screen.findByRole('button', { name: 'View or edit file router.cfg' })
    )

    const editor = await screen.findByRole('textbox', { name: 'Editor for router.cfg' })
    fireEvent.change(editor, {
      target: { value: 'hostname deleted-snapshot\ninterface Ethernet0\nrouter ospf 1\n' },
    })
    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(false)

    fireEvent.click(screen.getByRole('button', { name: 'Delete snapshot snapshot-a' }))
    fireEvent.click(await screen.findByRole('button', { name: 'common.delete' }))

    await waitFor(() => {
      expect(screen.queryByRole('textbox', { name: 'Editor for router.cfg' })).not.toBeInTheDocument()
    })
    fireEvent.click(screen.getByRole('button', { name: /Snapshot snapshot-b / }))

    expect(confirmSpy).not.toHaveBeenCalled()
    expect(screen.getByRole('button', { name: /Snapshot snapshot-b / })).toHaveAttribute(
      'aria-pressed',
      'true'
    )
  })

  it('clears the external-change banner after a successful content reload', async () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: /Snapshot snapshot-a / }))
    fireEvent.click(
      await screen.findByRole('button', { name: 'View or edit file router.cfg' })
    )
    await screen.findByRole('textbox', { name: 'Editor for router.cfg' })

    testState.files = [
      {
        name: 'router.cfg',
        size_bytes: 52,
        modified_at: '2026-01-03T00:00:00Z',
      },
    ]
    act(() => testState.refreshFiles())
    expect(await screen.findByText('snapshots.configEditor.externalChange')).toBeInTheDocument()

    testState.contentSaveConflict = true
    fireEvent.click(screen.getByRole('button', { name: 'Save editor' }))
    fireEvent.click(
      await screen.findByRole('button', { name: 'snapshots.configEditor.reload' })
    )

    await waitFor(() => expect(testState.configRefetch).toHaveBeenCalledTimes(1))
    await waitFor(() => {
      expect(screen.queryByText('snapshots.configEditor.externalChange')).not.toBeInTheDocument()
    })
  })

  it.each(['_router.cfg', '.router.cfg'])(
    'blocks paste-created filename %s before upload',
    async (filename) => {
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: /Snapshot snapshot-a / }))
      fireEvent.click(
        screen.getByRole('button', { name: 'snapshots.pasteCreate.open' })
      )

      fireEvent.change(
        screen.getByRole('textbox', { name: 'snapshots.pasteCreate.filenameLabel' }),
        { target: { value: filename } }
      )
      fireEvent.change(
        screen.getByRole('textbox', { name: 'snapshots.pasteCreate.contentLabel' }),
        { target: { value: 'hostname router\n' } }
      )
      fireEvent.click(
        screen.getByRole('button', { name: 'snapshots.pasteCreate.submit' })
      )

      expect(screen.getByRole('alert')).toHaveTextContent(
        'snapshots.pasteCreate.invalidFilename'
      )
      expect(testState.uploadMutate).not.toHaveBeenCalled()
    }
  )

  it('allows a normal paste-created filename', async () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: /Snapshot snapshot-a / }))
    fireEvent.click(
      screen.getByRole('button', { name: 'snapshots.pasteCreate.open' })
    )

    fireEvent.change(
      screen.getByRole('textbox', { name: 'snapshots.pasteCreate.filenameLabel' }),
      { target: { value: 'router2.cfg' } }
    )
    fireEvent.change(
      screen.getByRole('textbox', { name: 'snapshots.pasteCreate.contentLabel' }),
      { target: { value: 'hostname router2\n' } }
    )
    fireEvent.click(
      screen.getByRole('button', { name: 'snapshots.pasteCreate.submit' })
    )

    expect(testState.uploadMutate).toHaveBeenCalledTimes(1)
    expect(testState.uploadMutate.mock.calls[0][0].file).toMatchObject({
      name: 'router2.cfg',
    })
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    await act(async () => {})
  })
})

/** Defines `key` on `target` and returns a function that restores the previous definition */
function stubProperty(target: object, key: string, value: unknown) {
  const original = Object.getOwnPropertyDescriptor(target, key)
  Object.defineProperty(target, key, { configurable: true, writable: true, value })
  return () => {
    if (original) {
      Object.defineProperty(target, key, original)
    } else {
      Reflect.deleteProperty(target, key)
    }
  }
}

describe('SnapshotManagement file list and config editor placement', () => {
  const restoreStubs: Array<() => void> = []
  const editButton = (filename: string) =>
    screen.getByRole('button', { name: `View or edit file ${filename}` })
  const fileListToggle = () => screen.getByRole('button', { name: /^File list/ })

  async function openEditor(filename: string) {
    fireEvent.click(screen.getByRole('button', { name: /Snapshot snapshot-a / }))
    fireEvent.click(await screen.findByRole('button', { name: `View or edit file ${filename}` }))
    return screen.findByRole('textbox', { name: `Editor for ${filename}` })
  }

  beforeEach(() => {
    vi.restoreAllMocks()
    testState.snapshots = [
      { name: 'snapshot-a', file_count: 3, created_at: '2026-01-01T00:00:00Z', size_bytes: 138 },
      { name: 'snapshot-b', file_count: 0, created_at: '2026-01-02T00:00:00Z', size_bytes: 0 },
    ]
    testState.files = ['core.cfg', 'edge.cfg', 'dist.cfg'].map((name) => ({
      name,
      size_bytes: 46,
      modified_at: '2026-01-01T00:00:00Z',
    }))
    testState.contentSaveConflict = false
    testState.failFormatChange = null
    testState.contentLoadError = false
    useSnapshotStore.setState({
      currentSnapshotName: null,
      isSnapshotActivationInProgress: false,
      activatingSnapshotName: null,
    })
  })

  afterEach(() => {
    restoreStubs.splice(0).forEach((restore) => restore())
  })

  it('opens the editor in the table row right after the row of the edited file', async () => {
    renderPage()
    const editor = await openEditor('edge.cfg')

    const editedRow = editButton('edge.cfg').closest('tr')
    expect(editedRow?.nextElementSibling).toContainElement(editor)
    expect(editor.closest('td')).toHaveAttribute('colspan', '3')

    const region = screen.getByRole('region', { name: 'Editing edge.cfg' })
    expect(region).toContainElement(editor)
    expect(editButton('edge.cfg')).toHaveAttribute('aria-expanded', 'true')
    expect(editButton('edge.cfg')).toHaveAttribute('aria-controls', region.id)
    for (const other of ['core.cfg', 'dist.cfg']) {
      expect(editButton(other)).toHaveAttribute('aria-expanded', 'false')
      expect(editButton(other)).not.toHaveAttribute('aria-controls')
    }
  })

  it('moves the editor under another file after the discard confirmation', async () => {
    renderPage()
    const editor = await openEditor('edge.cfg')
    fireEvent.change(editor, { target: { value: 'hostname edge-changed\n' } })
    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(true)

    fireEvent.click(editButton('dist.cfg'))

    expect(confirmSpy).toHaveBeenCalledWith('Discard your unsaved config changes?')
    const distEditor = await screen.findByRole('textbox', { name: 'Editor for dist.cfg' })
    expect(editButton('dist.cfg').closest('tr')?.nextElementSibling).toContainElement(distEditor)
    expect(screen.queryByRole('textbox', { name: 'Editor for edge.cfg' })).not.toBeInTheDocument()
    expect(editButton('edge.cfg')).toHaveAttribute('aria-expanded', 'false')
    expect(editButton('dist.cfg')).toHaveAttribute('aria-expanded', 'true')
  })

  it('opens a large file below its row after the large-file confirmation', async () => {
    testState.files = [
      { name: 'core.cfg', size_bytes: 46, modified_at: '2026-01-01T00:00:00Z' },
      { name: 'big.cfg', size_bytes: 2 * 1024 * 1024, modified_at: '2026-01-01T00:00:00Z' },
    ]
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: /Snapshot snapshot-a / }))
    fireEvent.click(editButton('big.cfg'))
    expect(screen.queryByRole('textbox', { name: 'Editor for big.cfg' })).not.toBeInTheDocument()

    fireEvent.click(await screen.findByRole('button', { name: 'snapshots.configEditor.openLargeFile' }))

    const editor = await screen.findByRole('textbox', { name: 'Editor for big.cfg' })
    expect(editButton('big.cfg').closest('tr')?.nextElementSibling).toContainElement(editor)
  })

  it('keeps the editor of a file that left the list mounted and focused in one row at the top of the table body', async () => {
    renderPage()
    const editor = await openEditor('edge.cfg')
    const dirtyDraft = 'hostname edge-recovered\n'
    fireEvent.change(editor, { target: { value: dirtyDraft } })
    editor.focus()

    testState.files = testState.files.filter((file) => file.name !== 'edge.cfg')
    act(() => testState.refreshFiles())

    const editors = await screen.findAllByRole('textbox', { name: 'Editor for edge.cfg' })
    expect(editors).toHaveLength(1)
    expect(editors[0]).toBe(editor)
    expect(editors[0]).toHaveValue(dirtyDraft)
    expect(document.activeElement).toBe(editor)
    expect(editors[0].closest('tbody')?.firstElementChild).toContainElement(editors[0])
    expect(screen.getByRole('button', { name: 'Save as new file' })).toBeInTheDocument()
  })

  it('shows the deleted notice in the collapsed header when the edited file is deleted elsewhere', async () => {
    renderPage()
    const editor = await openEditor('edge.cfg')
    fireEvent.change(editor, { target: { value: 'hostname edge-deleted\n' } })
    fireEvent.click(fileListToggle())

    testState.files = testState.files.filter((file) => file.name !== 'edge.cfg')
    act(() => testState.refreshFiles())

    const notice = await screen.findByRole('alert')
    expect(notice).toHaveTextContent('This file was deleted before the save finished.')
    expect(notice).toBeVisible()
    expect(screen.getByText('Editing edge.cfg')).toBeVisible()
    expect(screen.getByText('Unsaved changes')).toBeVisible()
    expect(fileListToggle()).toHaveAttribute('aria-expanded', 'false')
    expect(fileListToggle()).toHaveAccessibleDescription(/This file was deleted before the save finished\./)
  })

  it('shows the load-failed notice in the collapsed header when the file content fails to load', () => {
    testState.contentLoadError = true
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: /Snapshot snapshot-a / }))
    fireEvent.click(editButton('edge.cfg'))
    fireEvent.click(fileListToggle())

    const notice = screen.getByRole('alert')
    expect(notice).toHaveTextContent('snapshots.configEditor.loadFailed')
    expect(notice).toBeVisible()
    expect(screen.getByText('Editing edge.cfg')).toBeVisible()
    expect(screen.queryByText('Unsaved changes')).not.toBeInTheDocument()
    expect(fileListToggle()).toHaveAccessibleDescription(/snapshots\.configEditor\.loadFailed/)
  })

  it('shows the external-change notice in the collapsed header when the edited file changes elsewhere', async () => {
    renderPage()
    await openEditor('edge.cfg')
    fireEvent.click(fileListToggle())

    testState.files = testState.files.map((file) =>
      file.name === 'edge.cfg' ? { ...file, size_bytes: 52, modified_at: '2026-01-03T00:00:00Z' } : file
    )
    act(() => testState.refreshFiles())

    const notice = await screen.findByRole('alert')
    expect(notice).toHaveTextContent('snapshots.configEditor.externalChange')
    expect(notice).toBeVisible()
    expect(screen.getByText('Editing edge.cfg')).toBeVisible()
    expect(fileListToggle()).toHaveAccessibleDescription(/snapshots\.configEditor\.externalChange/)
  })

  it('shows only the most severe notice in the collapsed header', async () => {
    renderPage()
    await openEditor('edge.cfg')
    fireEvent.click(fileListToggle())

    testState.files = testState.files.filter((file) => file.name !== 'edge.cfg')
    testState.contentLoadError = true
    act(() => testState.refreshFiles())

    const notice = await screen.findByRole('alert')
    expect(notice).toHaveTextContent('This file was deleted before the save finished.')
    expect(notice).not.toHaveTextContent('snapshots.configEditor.loadFailed')
  })

  it('leaves the editor notices inside the editor while the file list is expanded', async () => {
    renderPage()
    await openEditor('edge.cfg')

    testState.files = testState.files.map((file) =>
      file.name === 'edge.cfg' ? { ...file, size_bytes: 52, modified_at: '2026-01-03T00:00:00Z' } : file
    )
    act(() => testState.refreshFiles())
    const region = screen.getByRole('region', { name: 'Editing edge.cfg' })
    expect(await within(region).findByRole('alert')).toHaveTextContent('snapshots.configEditor.externalChange')
    expect(screen.getAllByRole('alert')).toHaveLength(1)

    testState.files = testState.files.filter((file) => file.name !== 'edge.cfg')
    act(() => testState.refreshFiles())
    expect(await within(region).findByText('This file was deleted before the save finished.')).toBeVisible()
    expect(screen.getAllByRole('alert')).toHaveLength(1)
    expect(fileListToggle()).toHaveAttribute('aria-expanded', 'true')
    expect(fileListToggle()).not.toHaveAttribute('aria-describedby')
    expect(screen.queryByText('Editing edge.cfg')).not.toBeInTheDocument()
  })

  it('collapses and expands the file list without losing the draft, naming the edited file while collapsed', async () => {
    renderPage()
    const editor = await openEditor('edge.cfg')
    const dirtyDraft = 'hostname edge-collapsed\n'
    fireEvent.change(editor, { target: { value: dirtyDraft } })
    expect(fileListToggle()).toHaveAttribute('aria-expanded', 'true')
    expect(within(fileListToggle()).getByLabelText('3 files')).toHaveTextContent('3')

    fireEvent.click(fileListToggle())

    expect(fileListToggle()).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
    expect(screen.queryByRole('textbox', { name: 'Editor for edge.cfg' })).not.toBeInTheDocument()
    expect(screen.getByText('Editing edge.cfg')).toBeVisible()
    expect(screen.getByText('Unsaved changes')).toBeVisible()
    expect(fileListToggle()).toHaveAccessibleDescription(/Editing edge\.cfg/)

    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(false)
    fireEvent.click(screen.getByRole('button', { name: /Snapshot snapshot-b / }))
    expect(confirmSpy).toHaveBeenCalledWith('Discard your unsaved config changes?')
    expect(screen.getByRole('button', { name: /Snapshot snapshot-a / })).toHaveAttribute('aria-pressed', 'true')

    fireEvent.click(fileListToggle())

    expect(fileListToggle()).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByRole('textbox', { name: 'Editor for edge.cfg' })).toHaveValue(dirtyDraft)
    expect(screen.queryByText('Unsaved changes')).not.toBeInTheDocument()
  })

  it('keeps the file list collapsed when another snapshot is selected', () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: /Snapshot snapshot-a / }))
    fireEvent.click(fileListToggle())

    fireEvent.click(screen.getByRole('button', { name: /Snapshot snapshot-b / }))

    expect(screen.getByRole('button', { name: /Snapshot snapshot-b / })).toHaveAttribute('aria-pressed', 'true')
    expect(fileListToggle()).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
  })

  it('expands the collapsed file list when a format change fails', () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: /Snapshot snapshot-a / }))
    fireEvent.change(screen.getAllByRole('combobox', { name: 'snapshots.format.ariaLabel' })[0], {
      target: { value: 'ios' },
    })
    fireEvent.click(fileListToggle())
    expect(screen.queryByRole('table')).not.toBeInTheDocument()

    act(() => testState.failFormatChange?.(new Error('Format update rejected')))

    expect(fileListToggle()).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByRole('alert')).toHaveTextContent('Format update rejected')
    expect(screen.getByRole('table')).toBeInTheDocument()
  })

  it.each([
    { reducedMotion: true, behavior: 'auto' },
    { reducedMotion: false, behavior: 'smooth' },
  ])(
    'scrolls the opened editor into view with $behavior scrolling and leaves focus on the edit button',
    async ({ reducedMotion, behavior }) => {
      const scrolls: Array<{ element: Element; options: unknown }> = []
      restoreStubs.push(
        stubProperty(Element.prototype, 'scrollIntoView', function (this: Element, options: unknown) {
          scrolls.push({ element: this, options })
        }),
        stubProperty(window, 'matchMedia', (query: string) => ({
          matches: reducedMotion && query === '(prefers-reduced-motion: reduce)',
        }))
      )
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: /Snapshot snapshot-a / }))
      const button = editButton('dist.cfg')
      button.focus()

      fireEvent.click(button)

      const region = await screen.findByRole('region', { name: 'Editing dist.cfg' })
      expect(scrolls.length).toBeGreaterThan(0)
      expect(scrolls.every((scroll) => scroll.element === region)).toBe(true)
      expect(scrolls[scrolls.length - 1].options).toEqual({ block: 'nearest', behavior })
      expect(document.activeElement).toBe(button)
    }
  )
})
