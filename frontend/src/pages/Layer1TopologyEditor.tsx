import { useState, useCallback, useEffect } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { ArrowLeft, Save, AlertCircle, CheckCircle } from 'lucide-react'
import { Layer1ConnectionForm } from '../components/Layer1ConnectionForm'
import { Layer1ConnectionTable } from '../components/Layer1ConnectionTable'
import { Layer1DeviceList } from '../components/Layer1DeviceList'
import {
  useLayer1TopologyEditor,
  useSnapshotInterfacesList,
  useSaveLayer1TopologyEditor,
} from '../hooks'
import type { Layer1Edge } from '../types'

export function Layer1TopologyEditor() {
  const { snapshotName } = useParams<{ snapshotName: string }>()
  const navigate = useNavigate()
  const { t } = useTranslation()

  const { data: topology, isLoading: topologyLoading } = useLayer1TopologyEditor(
    snapshotName || '',
    !!snapshotName
  )
  const { data: interfaces, isLoading: interfacesLoading } = useSnapshotInterfacesList(
    snapshotName || '',
    !!snapshotName
  )
  const saveMutation = useSaveLayer1TopologyEditor()

  const [localEdges, setLocalEdges] = useState<Layer1Edge[]>(topology?.edges || [])
  const [editingIndex, setEditingIndex] = useState<number | null>(null)
  const [hasChanges, setHasChanges] = useState(false)
  const [saveSuccess, setSaveSuccess] = useState(false)

  // Sync localEdges with topology data when it loads
  useEffect(() => {
    if (topology && !hasChanges && localEdges.length === 0 && topology.edges.length > 0) {
      setLocalEdges(topology.edges)
    }
  }, [topology, hasChanges, localEdges.length])

  const editingEdge = editingIndex !== null ? localEdges[editingIndex] : null

  const handleAddConnection = useCallback(
    (edge: Layer1Edge) => {
      if (editingIndex !== null) {
        const newEdges = [...localEdges]
        newEdges[editingIndex] = edge
        setLocalEdges(newEdges)
        setEditingIndex(null)
      } else {
        setLocalEdges([...localEdges, edge])
      }
      setHasChanges(true)
      setSaveSuccess(false)
    },
    [localEdges, editingIndex]
  )

  const handleEditConnection = useCallback((edge: Layer1Edge, index: number) => {
    setEditingIndex(index)
  }, [])

  const handleDeleteConnection = useCallback(
    (index: number) => {
      const newEdges = localEdges.filter((_, i) => i !== index)
      setLocalEdges(newEdges)
      setHasChanges(true)
      setSaveSuccess(false)
      if (editingIndex === index) {
        setEditingIndex(null)
      }
    },
    [localEdges, editingIndex]
  )

  const handleCancelEdit = useCallback(() => {
    setEditingIndex(null)
  }, [])

  const handleSaveAll = useCallback(() => {
    if (!snapshotName) return

    saveMutation.mutate(
      {
        snapshotName,
        topology: { edges: localEdges },
      },
      {
        onSuccess: () => {
          setHasChanges(false)
          setSaveSuccess(true)
          setTimeout(() => setSaveSuccess(false), 3000)
        },
      }
    )
  }, [snapshotName, localEdges, saveMutation])

  if (!snapshotName) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <AlertCircle className="w-12 h-12 text-red-500 mx-auto mb-4" />
          <p className="text-gray-700">{t('layer1Editor.errors.noSnapshot')}</p>
        </div>
      </div>
    )
  }

  const isLoading = topologyLoading || interfacesLoading

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4" />
          <p className="text-gray-700">{t('layer1Editor.loading')}</p>
        </div>
      </div>
    )
  }

  return (
    <div className="flex flex-col h-screen bg-gray-50">
      <header className="bg-white border-b border-gray-200 px-6 py-4 flex-shrink-0">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Link
              to="/snapshots"
              className="inline-flex items-center gap-2 text-gray-600 hover:text-gray-900"
            >
              <ArrowLeft className="w-4 h-4" />
              {t('layer1Editor.back')}
            </Link>
            <div className="h-6 w-px bg-gray-300" />
            <div>
              <h1 className="text-xl font-semibold text-gray-900">
                {t('layer1Editor.title')}
              </h1>
              <p className="text-sm text-gray-500">{snapshotName}</p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {saveSuccess && (
              <div className="flex items-center gap-2 px-3 py-1 bg-green-50 text-green-700 rounded-md">
                <CheckCircle className="w-4 h-4" />
                <span className="text-sm">{t('layer1Editor.saved')}</span>
              </div>
            )}

            {hasChanges && (
              <span className="text-sm text-orange-600">
                {t('layer1Editor.unsavedChanges')}
              </span>
            )}

            <button
              onClick={handleSaveAll}
              disabled={!hasChanges || saveMutation.isPending}
              className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:bg-gray-300 disabled:cursor-not-allowed"
            >
              <Save className="w-4 h-4" />
              {saveMutation.isPending ? t('layer1Editor.saving') : t('layer1Editor.saveAll')}
            </button>
          </div>
        </div>

        {saveMutation.isError && (
          <div className="mt-3 p-3 bg-red-50 border border-red-200 rounded-md">
            <div className="flex gap-2">
              <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
              <div className="flex-1">
                <p className="text-sm font-medium text-red-800">
                  {t('layer1Editor.errors.saveFailed')}
                </p>
                <p className="text-sm text-red-700 mt-1">
                  {saveMutation.error instanceof Error
                    ? saveMutation.error.message
                    : t('layer1Editor.errors.unknown')}
                </p>
              </div>
            </div>
          </div>
        )}
      </header>

      <div className="flex-1 overflow-hidden">
        <div className="grid grid-cols-12 gap-6 p-6 h-full">
          <div className="col-span-3 overflow-y-auto">
            <Layer1DeviceList
              interfaces={interfaces}
              isLoading={interfacesLoading}
            />
          </div>

          <div className="col-span-6 overflow-y-auto space-y-6">
            <Layer1ConnectionTable
              edges={localEdges}
              onEdit={handleEditConnection}
              onDelete={handleDeleteConnection}
            />
          </div>

          <div className="col-span-3 overflow-y-auto">
            <Layer1ConnectionForm
              interfaces={interfaces}
              editingEdge={editingEdge}
              onSubmit={handleAddConnection}
              onCancel={handleCancelEdit}
            />
          </div>
        </div>
      </div>
    </div>
  )
}
