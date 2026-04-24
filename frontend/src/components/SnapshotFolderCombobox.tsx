import { useMemo, useState } from 'react'
import { Combobox } from '@headlessui/react'
import { Check, ChevronDown, X } from 'lucide-react'
import { useTranslation } from 'react-i18next'

interface SnapshotFolderComboboxProps {
  id: string
  value: string
  options: string[]
  placeholder: string
  onChange: (value: string) => void
  hasError?: boolean
  ariaDescribedBy?: string
}

export function SnapshotFolderCombobox({
  id,
  value,
  options,
  placeholder,
  onChange,
  hasError = false,
  ariaDescribedBy,
}: SnapshotFolderComboboxProps) {
  const { t } = useTranslation()
  const [query, setQuery] = useState('')
  const normalizedQuery = query.trim().toLowerCase()
  const trimmedValue = value.trim()

  const filteredOptions = useMemo(() => {
    if (!normalizedQuery) return options

    return options.filter((option) =>
      option.toLowerCase().includes(normalizedQuery)
    )
  }, [options, normalizedQuery])

  const hasExactOption = useMemo(
    () => options.some((option) => option.toLowerCase() === trimmedValue.toLowerCase()),
    [options, trimmedValue]
  )

  const handleSelect = (selectedValue: string | null) => {
    setQuery('')
    onChange(selectedValue ?? '')
  }

  return (
    <Combobox value={value} onChange={handleSelect}>
      {({ open }) => (
      <div className="relative">
        <Combobox.Input
          id={id}
          value={value}
          onChange={(event) => {
            setQuery(event.target.value)
            onChange(event.target.value)
          }}
          onFocus={() => setQuery('')}
          placeholder={placeholder}
          aria-invalid={hasError}
          aria-describedby={ariaDescribedBy}
          className={`w-full px-3 py-2 pr-20 border rounded-lg focus:outline-none focus:ring-2 transition-colors ${
            hasError
              ? 'border-red-500 focus:ring-red-500 bg-red-50'
              : 'border-gray-300 focus:ring-primary-600'
          }`}
        />
        <div className="absolute inset-y-0 right-0 flex items-center gap-1 pr-2">
          {value && !open && (
            <button
              type="button"
              onClick={() => {
                setQuery('')
                onChange('')
              }}
              className="p-1 text-gray-500 hover:text-gray-700 rounded focus:outline-none focus:ring-2 focus:ring-primary-600"
              aria-label={t('snapshots.clearFolder')}
            >
              <X className="w-4 h-4" aria-hidden="true" />
            </button>
          )}
          <Combobox.Button
            className="p-1 text-gray-500 hover:text-gray-700 rounded focus:outline-none focus:ring-2 focus:ring-primary-600"
            aria-label={t('snapshots.folderSelectPlaceholder')}
            onClick={() => setQuery('')}
          >
            <ChevronDown className="w-4 h-4" aria-hidden="true" />
          </Combobox.Button>
        </div>
        <Combobox.Options className="absolute z-20 w-full mt-1 bg-white border border-gray-300 rounded-md shadow-lg max-h-60 overflow-auto">
          <Combobox.Option
            value=""
            className={({ active }) =>
              `relative cursor-pointer select-none py-2 pl-10 pr-4 ${
                active ? 'bg-blue-50 text-blue-900' : 'text-gray-900'
              }`
            }
          >
            {({ selected }) => (
              <>
                <span className={`block truncate ${selected || !trimmedValue ? 'font-medium' : 'font-normal'}`}>
                  {t('snapshots.ungroupedFolder')}
                </span>
                {(selected || !trimmedValue) && (
                  <span className="absolute inset-y-0 left-0 flex items-center pl-3 text-blue-600">
                    <Check className="w-4 h-4" aria-hidden="true" />
                  </span>
                )}
              </>
            )}
          </Combobox.Option>

          {filteredOptions.map((option) => (
            <Combobox.Option
              key={option}
              value={option}
              className={({ active }) =>
                `relative cursor-pointer select-none py-2 pl-10 pr-4 ${
                  active ? 'bg-blue-50 text-blue-900' : 'text-gray-900'
                }`
              }
            >
              {({ selected }) => (
                <>
                  <span className={`block truncate ${selected ? 'font-medium' : 'font-normal'}`}>
                    {option}
                  </span>
                  {selected && (
                    <span className="absolute inset-y-0 left-0 flex items-center pl-3 text-blue-600">
                      <Check className="w-4 h-4" aria-hidden="true" />
                    </span>
                  )}
                </>
              )}
            </Combobox.Option>
          ))}

          {filteredOptions.length === 0 && !trimmedValue && (
            <div className="px-3 py-2 text-sm text-gray-500">
              {t('snapshots.folderNoOptions')}
            </div>
          )}

          {trimmedValue && !hasExactOption && (
            <div className="px-3 py-2 text-sm text-gray-600 border-t border-gray-100">
              {t('snapshots.folderTypeToCreate', { folder: trimmedValue })}
            </div>
          )}
        </Combobox.Options>
      </div>
      )}
    </Combobox>
  )
}
