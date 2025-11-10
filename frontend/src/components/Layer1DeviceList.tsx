import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ChevronDown, ChevronRight, Server, Network } from 'lucide-react'
import type { SnapshotInterfaces } from '../types'

interface Layer1DeviceListProps {
  interfaces: SnapshotInterfaces | undefined
  isLoading?: boolean
}

export function Layer1DeviceList({ interfaces, isLoading }: Layer1DeviceListProps) {
  const { t } = useTranslation()
  const [expandedDevices, setExpandedDevices] = useState<Set<string>>(new Set())

  if (isLoading) {
    return (
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-lg font-semibold mb-4">{t('layer1Editor.devices')}</h3>
        <div className="flex items-center justify-center py-12 text-gray-500">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
        </div>
      </div>
    )
  }

  if (!interfaces || Object.keys(interfaces).length === 0) {
    return (
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-lg font-semibold mb-4">{t('layer1Editor.devices')}</h3>
        <div className="text-center py-12 text-gray-500">
          {t('layer1Editor.noDevices')}
        </div>
      </div>
    )
  }

  const deviceNames = Object.keys(interfaces).sort()

  const toggleDevice = (hostname: string) => {
    const newExpanded = new Set(expandedDevices)
    if (newExpanded.has(hostname)) {
      newExpanded.delete(hostname)
    } else {
      newExpanded.add(hostname)
    }
    setExpandedDevices(newExpanded)
  }

  const expandAll = () => {
    setExpandedDevices(new Set(deviceNames))
  }

  const collapseAll = () => {
    setExpandedDevices(new Set())
  }

  return (
    <div className="bg-white rounded-lg shadow h-full flex flex-col">
      <div className="p-6 border-b border-gray-200">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold">{t('layer1Editor.devices')}</h3>
          <span className="text-sm text-gray-500">
            {t('layer1Editor.totalDevices', { count: deviceNames.length })}
          </span>
        </div>

        <div className="flex gap-2">
          <button
            onClick={expandAll}
            className="px-3 py-1 text-sm border border-gray-300 rounded-md hover:bg-gray-50"
          >
            {t('layer1Editor.expandAll')}
          </button>
          <button
            onClick={collapseAll}
            className="px-3 py-1 text-sm border border-gray-300 rounded-md hover:bg-gray-50"
          >
            {t('layer1Editor.collapseAll')}
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-6 space-y-2">
        {deviceNames.map((hostname) => {
          const device = interfaces[hostname]
          const isExpanded = expandedDevices.has(hostname)

          return (
            <div key={hostname} className="border border-gray-200 rounded-lg">
              <button
                onClick={() => toggleDevice(hostname)}
                className="w-full flex items-center gap-2 p-3 hover:bg-gray-50 rounded-lg"
              >
                {isExpanded ? (
                  <ChevronDown className="w-4 h-4 text-gray-500 flex-shrink-0" />
                ) : (
                  <ChevronRight className="w-4 h-4 text-gray-500 flex-shrink-0" />
                )}
                <Server className="w-5 h-5 text-blue-600 flex-shrink-0" />
                <div className="flex-1 text-left">
                  <div className="font-medium text-gray-900">{hostname}</div>
                  <div className="text-xs text-gray-500">
                    {t('layer1Editor.interfaceCount', {
                      count: device.interfaces.length,
                    })}
                  </div>
                </div>
              </button>

              {isExpanded && (
                <div className="border-t border-gray-200 bg-gray-50">
                  {device.interfaces.length === 0 ? (
                    <div className="p-3 text-sm text-gray-500 text-center">
                      {t('layer1Editor.noInterfaces')}
                    </div>
                  ) : (
                    <div className="divide-y divide-gray-200">
                      {device.interfaces.map((iface) => (
                        <div
                          key={iface.name}
                          className="p-3 flex items-start gap-2 hover:bg-gray-100"
                        >
                          <Network className="w-4 h-4 text-gray-400 mt-0.5 flex-shrink-0" />
                          <div className="flex-1 min-w-0">
                            <div className="text-sm font-medium text-gray-900 truncate">
                              {iface.name}
                            </div>
                            {iface.description && (
                              <div className="text-xs text-gray-500 truncate">
                                {iface.description}
                              </div>
                            )}
                            <div className="mt-1">
                              <span
                                className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
                                  iface.active
                                    ? 'bg-green-100 text-green-800'
                                    : 'bg-gray-100 text-gray-800'
                                }`}
                              >
                                {iface.active
                                  ? t('layer1Editor.active')
                                  : t('layer1Editor.inactive')}
                              </span>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
