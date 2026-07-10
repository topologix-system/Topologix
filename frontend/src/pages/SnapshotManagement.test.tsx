import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { createMemoryRouter, RouterProvider } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

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
      data: enabled
        ? {
            content: `hostname ${filename.replace('.cfg', '')}\ninterface Ethernet0\n`,
            sha256: 'a'.repeat(64),
            size_bytes: 46,
          }
        : undefined,
      isLoading: false,
      isError: false,
      error: null,
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
    }),
    useUpdateSnapshotFileFormat: idleMutation,
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

  it('allows a normal paste-created filename', () => {
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
  })
})
