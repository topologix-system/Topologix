import { useState, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { Combobox } from '@headlessui/react'
import { Plus, X, Check, ChevronDown } from 'lucide-react'
import type { Layer1Edge, SnapshotInterfaces } from '../types'
import { useComboboxFilter } from '../hooks'

interface Layer1ConnectionFormProps {
  interfaces: SnapshotInterfaces | undefined
  editingEdge?: Layer1Edge | null
  onSubmit: (edge: Layer1Edge) => void
  onCancel?: () => void
}

export function Layer1ConnectionForm({
  interfaces,
  editingEdge,
  onSubmit,
  onCancel,
}: Layer1ConnectionFormProps) {
  const { t } = useTranslation()

  const [hostname1, setHostname1] = useState(editingEdge?.node1.hostname || '')
  const [interfaceName1, setInterfaceName1] = useState(editingEdge?.node1.interfaceName || '')
  const [hostname2, setHostname2] = useState(editingEdge?.node2.hostname || '')
  const [interfaceName2, setInterfaceName2] = useState(editingEdge?.node2.interfaceName || '')

  const hostnames = useMemo(
    () => (interfaces ? Object.keys(interfaces).sort() : []),
    [interfaces]
  )

  const hostname1Filter = useComboboxFilter(hostnames)
  const hostname2Filter = useComboboxFilter(hostnames)

  const interfaces1 = useMemo(() => {
    if (!interfaces || !hostname1) return []
    return (interfaces[hostname1]?.interfaces || []).map((iface) => iface.name)
  }, [interfaces, hostname1])

  const interfaces2 = useMemo(() => {
    if (!interfaces || !hostname2) return []
    return (interfaces[hostname2]?.interfaces || []).map((iface) => iface.name)
  }, [interfaces, hostname2])

  const interface1Filter = useComboboxFilter(interfaces1)
  const interface2Filter = useComboboxFilter(interfaces2)

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    if (!hostname1 || !interfaceName1 || !hostname2 || !interfaceName2) {
      return
    }

    if (hostname1 === hostname2) {
      alert(t('layer1Editor.errors.selfConnection'))
      return
    }

    const edge: Layer1Edge = {
      node1: { hostname: hostname1, interfaceName: interfaceName1 },
      node2: { hostname: hostname2, interfaceName: interfaceName2 },
    }

    onSubmit(edge)
    handleClear()
  }

  const handleClear = () => {
    setHostname1('')
    setInterfaceName1('')
    setHostname2('')
    setInterfaceName2('')
    hostname1Filter.setQuery('')
    interface1Filter.setQuery('')
    hostname2Filter.setQuery('')
    interface2Filter.setQuery('')
  }

  const handleHostname1Change = (value: string) => {
    setHostname1(value)
    setInterfaceName1('') // Clear interface when hostname changes
    interface1Filter.setQuery('')
  }

  const handleHostname2Change = (value: string) => {
    setHostname2(value)
    setInterfaceName2('') // Clear interface when hostname changes
    interface2Filter.setQuery('')
  }

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <h3 className="text-lg font-semibold mb-4">
        {editingEdge ? t('layer1Editor.editConnection') : t('layer1Editor.addConnection')}
      </h3>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Node 1 */}
        <div className="space-y-4">
          <h4 className="font-medium text-gray-700">{t('layer1Editor.node1')}</h4>

          {/* Hostname 1 Combobox */}
          <Combobox value={hostname1} onChange={handleHostname1Change}>
            <div className="relative">
              <Combobox.Label className="block text-sm font-medium text-gray-700 mb-1">
                {t('layer1Editor.hostname')}
              </Combobox.Label>
              <div className="relative">
                <Combobox.Input
                  onChange={(e) => hostname1Filter.setQuery(e.target.value)}
                  displayValue={(hostname: string) => hostname}
                  className="w-full px-3 py-2 pr-10 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder={t('layer1Editor.selectHostname')}
                  required
                />
                <Combobox.Button className="absolute inset-y-0 right-0 flex items-center pr-2">
                  <ChevronDown className="h-5 w-5 text-gray-400" aria-hidden="true" />
                </Combobox.Button>
              </div>
              <Combobox.Options className="absolute z-10 w-full mt-1 bg-white border border-gray-300 rounded-md shadow-lg max-h-60 overflow-auto">
                {hostname1Filter.filteredItems.length === 0 && hostname1Filter.query !== '' ? (
                  <div className="px-3 py-2 text-sm text-gray-500">
                    {t('layer1Editor.noResults')}
                  </div>
                ) : (
                  hostname1Filter.filteredItems.map((hostname) => (
                    <Combobox.Option
                      key={hostname}
                      value={hostname}
                      className={({ active }) =>
                        `relative cursor-pointer select-none py-2 pl-10 pr-4 ${
                          active ? 'bg-blue-50 text-blue-900' : 'text-gray-900'
                        }`
                      }
                    >
                      {({ selected, active }) => (
                        <>
                          <span className={`block truncate ${selected ? 'font-medium' : 'font-normal'}`}>
                            {hostname}
                          </span>
                          {selected && (
                            <span
                              className={`absolute inset-y-0 left-0 flex items-center pl-3 ${
                                active ? 'text-blue-600' : 'text-blue-600'
                              }`}
                            >
                              <Check className="h-5 w-5" aria-hidden="true" />
                            </span>
                          )}
                        </>
                      )}
                    </Combobox.Option>
                  ))
                )}
              </Combobox.Options>
            </div>
          </Combobox>

          {/* Interface 1 Combobox */}
          <Combobox value={interfaceName1} onChange={setInterfaceName1} disabled={!hostname1}>
            <div className="relative">
              <Combobox.Label className="block text-sm font-medium text-gray-700 mb-1">
                {t('layer1Editor.interface')}
              </Combobox.Label>
              <div className="relative">
                <Combobox.Input
                  onChange={(e) => interface1Filter.setQuery(e.target.value)}
                  displayValue={(interfaceName: string) => interfaceName}
                  className="w-full px-3 py-2 pr-10 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-100 disabled:cursor-not-allowed"
                  placeholder={t('layer1Editor.selectInterface')}
                  required
                />
                <Combobox.Button className="absolute inset-y-0 right-0 flex items-center pr-2">
                  <ChevronDown className="h-5 w-5 text-gray-400" aria-hidden="true" />
                </Combobox.Button>
              </div>
              <Combobox.Options className="absolute z-10 w-full mt-1 bg-white border border-gray-300 rounded-md shadow-lg max-h-60 overflow-auto">
                {interface1Filter.filteredItems.length === 0 && interface1Filter.query !== '' ? (
                  <div className="px-3 py-2 text-sm text-gray-500">
                    {t('layer1Editor.noResults')}
                  </div>
                ) : (
                  interface1Filter.filteredItems.map((interfaceName) => (
                    <Combobox.Option
                      key={interfaceName}
                      value={interfaceName}
                      className={({ active }) =>
                        `relative cursor-pointer select-none py-2 pl-10 pr-4 ${
                          active ? 'bg-blue-50 text-blue-900' : 'text-gray-900'
                        }`
                      }
                    >
                      {({ selected, active }) => (
                        <>
                          <span className={`block truncate ${selected ? 'font-medium' : 'font-normal'}`}>
                            {interfaceName}
                          </span>
                          {selected && (
                            <span
                              className={`absolute inset-y-0 left-0 flex items-center pl-3 ${
                                active ? 'text-blue-600' : 'text-blue-600'
                              }`}
                            >
                              <Check className="h-5 w-5" aria-hidden="true" />
                            </span>
                          )}
                        </>
                      )}
                    </Combobox.Option>
                  ))
                )}
              </Combobox.Options>
            </div>
          </Combobox>
        </div>

        {/* Node 2 */}
        <div className="space-y-4">
          <h4 className="font-medium text-gray-700">{t('layer1Editor.node2')}</h4>

          {/* Hostname 2 Combobox */}
          <Combobox value={hostname2} onChange={handleHostname2Change}>
            <div className="relative">
              <Combobox.Label className="block text-sm font-medium text-gray-700 mb-1">
                {t('layer1Editor.hostname')}
              </Combobox.Label>
              <div className="relative">
                <Combobox.Input
                  onChange={(e) => hostname2Filter.setQuery(e.target.value)}
                  displayValue={(hostname: string) => hostname}
                  className="w-full px-3 py-2 pr-10 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder={t('layer1Editor.selectHostname')}
                  required
                />
                <Combobox.Button className="absolute inset-y-0 right-0 flex items-center pr-2">
                  <ChevronDown className="h-5 w-5 text-gray-400" aria-hidden="true" />
                </Combobox.Button>
              </div>
              <Combobox.Options className="absolute z-10 w-full mt-1 bg-white border border-gray-300 rounded-md shadow-lg max-h-60 overflow-auto">
                {hostname2Filter.filteredItems.length === 0 && hostname2Filter.query !== '' ? (
                  <div className="px-3 py-2 text-sm text-gray-500">
                    {t('layer1Editor.noResults')}
                  </div>
                ) : (
                  hostname2Filter.filteredItems.map((hostname) => (
                    <Combobox.Option
                      key={hostname}
                      value={hostname}
                      className={({ active }) =>
                        `relative cursor-pointer select-none py-2 pl-10 pr-4 ${
                          active ? 'bg-blue-50 text-blue-900' : 'text-gray-900'
                        }`
                      }
                    >
                      {({ selected, active }) => (
                        <>
                          <span className={`block truncate ${selected ? 'font-medium' : 'font-normal'}`}>
                            {hostname}
                          </span>
                          {selected && (
                            <span
                              className={`absolute inset-y-0 left-0 flex items-center pl-3 ${
                                active ? 'text-blue-600' : 'text-blue-600'
                              }`}
                            >
                              <Check className="h-5 w-5" aria-hidden="true" />
                            </span>
                          )}
                        </>
                      )}
                    </Combobox.Option>
                  ))
                )}
              </Combobox.Options>
            </div>
          </Combobox>

          {/* Interface 2 Combobox */}
          <Combobox value={interfaceName2} onChange={setInterfaceName2} disabled={!hostname2}>
            <div className="relative">
              <Combobox.Label className="block text-sm font-medium text-gray-700 mb-1">
                {t('layer1Editor.interface')}
              </Combobox.Label>
              <div className="relative">
                <Combobox.Input
                  onChange={(e) => interface2Filter.setQuery(e.target.value)}
                  displayValue={(interfaceName: string) => interfaceName}
                  className="w-full px-3 py-2 pr-10 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-100 disabled:cursor-not-allowed"
                  placeholder={t('layer1Editor.selectInterface')}
                  required
                />
                <Combobox.Button className="absolute inset-y-0 right-0 flex items-center pr-2">
                  <ChevronDown className="h-5 w-5 text-gray-400" aria-hidden="true" />
                </Combobox.Button>
              </div>
              <Combobox.Options className="absolute z-10 w-full mt-1 bg-white border border-gray-300 rounded-md shadow-lg max-h-60 overflow-auto">
                {interface2Filter.filteredItems.length === 0 && interface2Filter.query !== '' ? (
                  <div className="px-3 py-2 text-sm text-gray-500">
                    {t('layer1Editor.noResults')}
                  </div>
                ) : (
                  interface2Filter.filteredItems.map((interfaceName) => (
                    <Combobox.Option
                      key={interfaceName}
                      value={interfaceName}
                      className={({ active }) =>
                        `relative cursor-pointer select-none py-2 pl-10 pr-4 ${
                          active ? 'bg-blue-50 text-blue-900' : 'text-gray-900'
                        }`
                      }
                    >
                      {({ selected, active }) => (
                        <>
                          <span className={`block truncate ${selected ? 'font-medium' : 'font-normal'}`}>
                            {interfaceName}
                          </span>
                          {selected && (
                            <span
                              className={`absolute inset-y-0 left-0 flex items-center pl-3 ${
                                active ? 'text-blue-600' : 'text-blue-600'
                              }`}
                            >
                              <Check className="h-5 w-5" aria-hidden="true" />
                            </span>
                          )}
                        </>
                      )}
                    </Combobox.Option>
                  ))
                )}
              </Combobox.Options>
            </div>
          </Combobox>
        </div>

        {/* Form Actions */}
        <div className="flex items-center gap-3">
          <button
            type="submit"
            className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
          >
            <Plus className="w-4 h-4" />
            {editingEdge ? t('layer1Editor.update') : t('layer1Editor.add')}
          </button>
          {onCancel && (
            <button
              type="button"
              onClick={onCancel}
              className="inline-flex items-center gap-2 px-4 py-2 border border-gray-300 text-gray-700 rounded-md hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
            >
              <X className="w-4 h-4" />
              {t('layer1Editor.cancel')}
            </button>
          )}
        </div>
      </form>
    </div>
  )
}
