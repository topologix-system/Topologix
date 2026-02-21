import { useState, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { Combobox } from '@headlessui/react'
import { Check, ChevronDown, X } from 'lucide-react'
import {
  PROTOCOL_OPTIONS,
  COMMON_PROTOCOLS,
  type ProtocolOption,
  type ProtocolCategory,
} from '../constants/protocols'

interface ProtocolSelectorProps {
  value: string[]
  onChange: (protocols: string[]) => void
  'aria-label'?: string
}

export function ProtocolSelector({ value, onChange, 'aria-label': ariaLabel }: ProtocolSelectorProps) {
  const { t } = useTranslation()
  const [searchQuery, setSearchQuery] = useState('')
  const [showAll, setShowAll] = useState(false)

  const filteredProtocols = useMemo(() => {
    if (!searchQuery) {
      return showAll ? PROTOCOL_OPTIONS : COMMON_PROTOCOLS
    }
    const q = searchQuery.toLowerCase()
    const isNegation = q.startsWith('!')
    const searchTerm = isNegation ? q.slice(1) : q
    if (!searchTerm) return PROTOCOL_OPTIONS
    return PROTOCOL_OPTIONS.filter(
      (p) =>
        p.name.toLowerCase().includes(searchTerm) ||
        p.number.toString() === searchTerm
    )
  }, [searchQuery, showAll])

  const groupedProtocols = useMemo(() => {
    if (searchQuery) return null
    const groups = new Map<ProtocolCategory, ProtocolOption[]>()
    for (const p of filteredProtocols) {
      const list = groups.get(p.category) || []
      list.push(p)
      groups.set(p.category, list)
    }
    return groups
  }, [filteredProtocols, searchQuery])

  const rawNumberOption = useMemo(() => {
    if (!searchQuery) return null
    const isNegation = searchQuery.startsWith('!')
    const term = isNegation ? searchQuery.slice(1) : searchQuery
    const num = parseInt(term, 10)
    if (isNaN(num) || num < 0 || num > 255) return null
    const exists = PROTOCOL_OPTIONS.some((p) => p.number === num)
    if (exists) return null
    const rawValue = isNegation ? `!${num}` : `${num}`
    return rawValue
  }, [searchQuery])

  const handleChange = (selected: string[]) => {
    onChange(selected)
    setSearchQuery('')
  }

  const handleRemoveTag = (protocol: string) => {
    onChange(value.filter((v) => v !== protocol))
  }

  const handleInputKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace' && searchQuery === '' && value.length > 0) {
      onChange(value.slice(0, -1))
    }
  }

  const renderOption = (protocol: ProtocolOption, isNegated: boolean) => {
    const displayName = isNegated ? `!${protocol.name}` : protocol.name
    const optionValue = isNegated ? `!${protocol.name}` : protocol.name
    return (
      <Combobox.Option
        key={optionValue}
        value={optionValue}
        className={({ active }) =>
          `relative cursor-pointer select-none py-2 pl-10 pr-4 ${
            active ? 'bg-blue-50 text-blue-900' : 'text-gray-900'
          }`
        }
      >
        {({ selected }) => (
          <>
            <div className="flex items-center justify-between">
              <span
                className={`block truncate ${selected ? 'font-medium' : 'font-normal'}`}
              >
                {displayName}{' '}
                <span className="text-gray-400">({protocol.number})</span>
              </span>
              <span className="text-xs text-gray-400">
                {t(`traceroute.protocol.categories.${protocol.category}`)}
              </span>
            </div>
            {selected && (
              <span className="absolute inset-y-0 left-0 flex items-center pl-3 text-blue-600">
                <Check className="h-5 w-5" aria-hidden="true" />
              </span>
            )}
          </>
        )}
      </Combobox.Option>
    )
  }

  const isNegationSearch = searchQuery.startsWith('!')

  return (
    <Combobox value={value} onChange={handleChange} multiple>
      <div className="relative">
        <div className="flex flex-wrap items-center gap-1 w-full px-2 py-1.5 pr-10 border border-gray-300 rounded-md focus-within:ring-2 focus-within:ring-blue-500 focus-within:border-transparent min-h-[38px]">
          {value.map((protocol) => (
            <span
              key={protocol}
              className="inline-flex items-center bg-blue-100 text-blue-800 rounded-full px-2 py-0.5 text-sm"
            >
              {protocol}
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation()
                  handleRemoveTag(protocol)
                }}
                className="ml-1 text-blue-600 hover:text-blue-800"
                aria-label={`Remove ${protocol}`}
              >
                <X className="h-3 w-3" />
              </button>
            </span>
          ))}
          <Combobox.Input
            onChange={(e) => setSearchQuery(e.target.value)}
            onKeyDown={handleInputKeyDown}
            value={searchQuery}
            aria-label={ariaLabel || t('traceroute.fields.ipProtocols')}
            placeholder={
              value.length === 0
                ? t('traceroute.placeholders.ipProtocols')
                : ''
            }
            className="flex-1 min-w-[80px] border-none outline-none focus:ring-0 p-0 text-sm bg-transparent"
          />
        </div>
        <Combobox.Button className="absolute inset-y-0 right-0 flex items-center pr-2">
          <ChevronDown className="h-5 w-5 text-gray-400" aria-hidden="true" />
        </Combobox.Button>

        <Combobox.Options className="absolute z-10 w-full mt-1 bg-white border border-gray-300 rounded-md shadow-lg max-h-60 overflow-auto">
          {filteredProtocols.length === 0 && !rawNumberOption ? (
            <div className="px-3 py-2 text-sm text-gray-500">
              {t('traceroute.protocol.noResults')}
            </div>
          ) : (
            <>
              {rawNumberOption && (
                <Combobox.Option
                  value={rawNumberOption}
                  className={({ active }) =>
                    `relative cursor-pointer select-none py-2 pl-10 pr-4 ${
                      active ? 'bg-blue-50 text-blue-900' : 'text-gray-900'
                    }`
                  }
                >
                  {({ selected }) => (
                    <>
                      <span className="block truncate text-sm">
                        {t('traceroute.protocol.rawValue', {
                          value: rawNumberOption,
                        })}
                      </span>
                      {selected && (
                        <span className="absolute inset-y-0 left-0 flex items-center pl-3 text-blue-600">
                          <Check className="h-5 w-5" aria-hidden="true" />
                        </span>
                      )}
                    </>
                  )}
                </Combobox.Option>
              )}

              {groupedProtocols
                ? Array.from(groupedProtocols.entries()).map(
                    ([category, protocols]) => (
                      <div key={category} role="group" aria-labelledby={`category-${category}-label`}>
                        <div
                          id={`category-${category}-label`}
                          role="presentation"
                          className="px-3 py-1 text-xs font-semibold text-gray-500 uppercase tracking-wider bg-gray-50 sticky top-0"
                        >
                          {t(`traceroute.protocol.categories.${category}`)}
                        </div>
                        {protocols.map((p) =>
                          renderOption(p, false)
                        )}
                      </div>
                    )
                  )
                : filteredProtocols.map((p) =>
                    renderOption(p, isNegationSearch)
                  )}

              {!searchQuery && (
                <button
                  type="button"
                  onClick={(e) => {
                    e.preventDefault()
                    e.stopPropagation()
                    setShowAll(!showAll)
                  }}
                  className="w-full px-3 py-2 text-sm text-blue-600 hover:bg-blue-50 text-center border-t border-gray-200"
                >
                  {showAll
                    ? t('traceroute.protocol.showCommon')
                    : t('traceroute.protocol.showAll', {
                        count: PROTOCOL_OPTIONS.length,
                      })}
                </button>
              )}
            </>
          )}

          <div className="px-3 py-1.5 text-xs text-gray-400 border-t border-gray-100">
            {t('traceroute.protocol.hint')}
          </div>
        </Combobox.Options>
      </div>
    </Combobox>
  )
}
