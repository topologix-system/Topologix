import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { createTestQueryClient, makeVersionState } from '../__tests__/versioning'
import { snapshotAPI } from '../services/api'
import { useSnapshotStore } from '../store'
import type { SnapshotArtifactRecord } from '../types'
import { AdvancedArtifactPanel } from './AdvancedArtifactPanel'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}))

vi.stubGlobal(
  'ResizeObserver',
  class {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
)
Element.prototype.getAnimations = () => []

const NAME = 'snap-a'

const artifact: SnapshotArtifactRecord = {
  artifact_id: 'artifact-1',
  artifact_type: 'network_config',
  label: 'Network config',
  category: 'configs',
  logical_name: 'r1',
  relative_path: 'configs/r1.cfg',
  size_bytes: 12,
  modified_at: '2026-01-01T00:00:00Z',
  metadata: {},
  mutation_policy: {
    metadata_edit: 'none',
    content_replace: 'allowed',
    safe_relocate: 'none',
    type_change: 'forbidden',
    active_snapshot_effect: 'requires_reactivate',
    preview_required: true,
    validation_required: false,
    rollback_required: false,
  },
  warnings: [],
}

describe('AdvancedArtifactPanel re-activation', () => {
  beforeEach(() => {
    useSnapshotStore.setState({ currentSnapshotName: NAME, isSnapshotActivationInProgress: false, activatingSnapshotName: null })
    vi.spyOn(snapshotAPI, 'getVersionState').mockResolvedValue(makeVersionState())
    vi.spyOn(snapshotAPI, 'getArtifactTypes').mockResolvedValue([])
    vi.spyOn(snapshotAPI, 'getArtifactTree').mockResolvedValue({ snapshot_name: NAME, artifacts: [artifact], summary: {} })
    vi.spyOn(snapshotAPI, 'previewArtifactChange').mockResolvedValue({
      artifact_type: 'network_config',
      operation: 'delete',
      current_destination: 'configs/r1.cfg',
      next_destination: 'configs/r1.cfg',
      destination_exists: true,
      requires_reinitialize: true,
      warnings: [],
      preview_token: 'preview-token',
    })
    vi.spyOn(snapshotAPI, 'deleteArtifact').mockResolvedValue({
      artifact_id: 'artifact-1',
      artifact_type: 'network_config',
      relative_path: 'configs/r1.cfg',
      requires_reinitialize: true,
    })
  })

  afterEach(() => vi.restoreAllMocks())

  it('re-activates the current snapshot once with if_stale after an artifact deletion', async () => {
    const activate = vi.spyOn(snapshotAPI, 'activate').mockResolvedValue({
      status: 'success',
      network: 'net',
      snapshot: NAME,
      file_parse_status: [],
      init_issues: [],
      parse_warnings: [],
      initialization_result: {},
      parsed: false,
    })
    const queryClient = createTestQueryClient()
    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <AdvancedArtifactPanel snapshotName={NAME} />
        </MemoryRouter>
      </QueryClientProvider>
    )

    fireEvent.click(screen.getByRole('button', { name: /snapshots\.artifacts\.title/ }))
    fireEvent.click(await screen.findByRole('button', { name: 'snapshots.artifacts.deleteAria' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: 'common.delete' }))

    await waitFor(() => expect(activate).toHaveBeenCalledTimes(1))
    expect(activate).toHaveBeenCalledWith(NAME, { if_stale: true })
    expect(await screen.findByText('snapshots.artifacts.reactivated')).toBeInTheDocument()
  })
})
