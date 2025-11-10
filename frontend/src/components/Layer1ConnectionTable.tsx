import { useTranslation } from 'react-i18next'
import { Edit2, Trash2, ArrowRight } from 'lucide-react'
import type { Layer1Edge } from '../types'

interface Layer1ConnectionTableProps {
  edges: Layer1Edge[]
  onEdit: (edge: Layer1Edge, index: number) => void
  onDelete: (index: number) => void
}

export function Layer1ConnectionTable({
  edges,
  onEdit,
  onDelete,
}: Layer1ConnectionTableProps) {
  const { t } = useTranslation()

  if (edges.length === 0) {
    return (
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-lg font-semibold mb-4">{t('layer1Editor.connections')}</h3>
        <div className="text-center py-12 text-gray-500">
          {t('layer1Editor.noConnections')}
        </div>
      </div>
    )
  }

  return (
    <div className="bg-white rounded-lg shadow">
      <div className="p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold">{t('layer1Editor.connections')}</h3>
          <span className="text-sm text-gray-500">
            {t('layer1Editor.totalConnections', { count: edges.length })}
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  #
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  {t('layer1Editor.device1')}
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  {t('layer1Editor.interface1')}
                </th>
                <th className="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">

                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  {t('layer1Editor.device2')}
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  {t('layer1Editor.interface2')}
                </th>
                <th className="px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                  {t('layer1Editor.actions')}
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {edges.map((edge, index) => (
                <tr key={index} className="hover:bg-gray-50">
                  <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-500">
                    {index + 1}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm font-medium text-gray-900">
                    {edge.node1.hostname}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-700">
                    {edge.node1.interfaceName}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-center">
                    <ArrowRight className="w-4 h-4 text-gray-400 inline" />
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm font-medium text-gray-900">
                    {edge.node2.hostname}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-700">
                    {edge.node2.interfaceName}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-right text-sm font-medium">
                    <div className="flex justify-end gap-2">
                      <button
                        onClick={() => onEdit(edge, index)}
                        className="inline-flex items-center px-3 py-1 border border-gray-300 rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-blue-500"
                        title={t('layer1Editor.edit')}
                      >
                        <Edit2 className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => {
                          if (window.confirm(t('layer1Editor.confirmDelete'))) {
                            onDelete(index)
                          }
                        }}
                        className="inline-flex items-center px-3 py-1 border border-red-300 rounded-md text-red-700 bg-white hover:bg-red-50 focus:outline-none focus:ring-2 focus:ring-red-500"
                        title={t('layer1Editor.delete')}
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
