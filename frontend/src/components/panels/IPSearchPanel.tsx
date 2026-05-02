import { useMemo, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Info, Network, Search, Server, X } from 'lucide-react'

import {
  findHostOwnerMatches,
  findInterfaceNetworkMatches,
  normalizeHostSearchInput,
} from '../../lib/ipSearch'
import type { HostSearchErrorCode, InterfaceNetworkMatchSource } from '../../types/ipSearch'
import type { IPOwner } from '../../types/ip'
import type { InterfaceProperties } from '../../types/network'

interface IPSearchPanelProps {
  ipOwners?: IPOwner[]
  interfaces?: InterfaceProperties[]
  isLoading: boolean
  error?: unknown
}

function getSearchErrorKey(error: HostSearchErrorCode | null): string | null {
  if (!error || error === 'empty') {
    return null
  }

  return `ipSearch.errors.${error}`
}

function StatusBadge({ active, label }: { active: boolean; label: string }) {
  return (
    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${active ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-700'}`}>
      {label}
    </span>
  )
}

function getDataErrorMessage(error: unknown): string | null {
  if (!error) {
    return null
  }

  if (typeof error === 'string') {
    return error
  }

  if (typeof error === 'object') {
    const maybeError = error as {
      message?: unknown
      response?: {
        data?: {
          message?: unknown
        }
      }
    }
    const responseMessage = maybeError.response?.data?.message
    if (typeof responseMessage === 'string') {
      return responseMessage
    }
    if (typeof maybeError.message === 'string') {
      return maybeError.message
    }
  }

  if (error instanceof Error) {
    return error.message
  }

  return null
}

export function IPSearchPanel({ ipOwners = [], interfaces = [], isLoading, error }: IPSearchPanelProps) {
  const { t } = useTranslation()
  const [query, setQuery] = useState('')
  const [submittedQuery, setSubmittedQuery] = useState('')
  const [includeInactive, setIncludeInactive] = useState(false)
  const hasDataError = Boolean(error)
  const dataErrorMessage = getDataErrorMessage(error)

  const currentInput = useMemo(() => normalizeHostSearchInput(query), [query])
  const submittedInput = useMemo(
    () => (submittedQuery ? normalizeHostSearchInput(submittedQuery) : null),
    [submittedQuery],
  )
  const searchErrorKey = getSearchErrorKey(currentInput.error)

  const hostMatches = useMemo(() => {
    if (!submittedInput?.ip) {
      return []
    }

    return findHostOwnerMatches(submittedInput.ip, ipOwners, { includeInactive })
  }, [submittedInput, ipOwners, includeInactive])

  const networkMatches = useMemo(() => {
    if (!submittedInput?.ip) {
      return []
    }

    return findInterfaceNetworkMatches(submittedInput.ip, interfaces, { includeInactive })
  }, [submittedInput, interfaces, includeInactive])

  const canSearch = !isLoading && !hasDataError && currentInput.ip !== null && currentInput.error === null

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!canSearch || !currentInput.ip) {
      return
    }

    setSubmittedQuery(currentInput.ip.text)
  }

  const clearQuery = () => {
    setQuery('')
    setSubmittedQuery('')
  }

  const sourceLabel = (source: InterfaceNetworkMatchSource) => {
    return source === 'primary_network'
      ? t('ipSearch.source.primaryNetwork')
      : t('ipSearch.source.allPrefixes')
  }

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 border-l-4 border-l-primary-600">
      <div className="px-4 py-3 border-b border-gray-100">
        <div className="flex items-start gap-3">
          <Search className="w-5 h-5 text-primary-600 mt-0.5" aria-hidden="true" />
          <div>
            <h3 className="font-semibold text-gray-900">{t('ipSearch.title')}</h3>
            <p className="text-xs text-gray-600 mt-1">{t('ipSearch.description')}</p>
          </div>
        </div>
      </div>

      <div className="px-4 py-4 space-y-4">
        <form className="space-y-3" onSubmit={handleSubmit}>
          <div className="grid grid-cols-1 gap-3 lg:grid-cols-[minmax(0,1fr)_auto]">
            <div>
              <label htmlFor="ip-search-input" className="block text-sm font-medium text-gray-700 mb-1">
                {t('ipSearch.inputLabel')}
              </label>
              <div className="relative">
                <input
                  id="ip-search-input"
                  type="text"
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder={t('ipSearch.placeholder')}
                  aria-invalid={!!searchErrorKey}
                  aria-describedby={searchErrorKey ? 'ip-search-error' : 'ip-search-help'}
                  className={`w-full rounded-md border px-3 py-2 pr-9 text-sm focus:outline-none focus:ring-2 focus:ring-primary-600 ${
                    searchErrorKey ? 'border-red-400' : 'border-gray-300'
                  }`}
                />
                {query && (
                  <button
                    type="button"
                    onClick={clearQuery}
                    className="absolute inset-y-0 right-0 flex w-9 items-center justify-center text-gray-400 hover:text-gray-700 focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-inset rounded-r-md"
                    aria-label={t('ipSearch.clear')}
                  >
                    <X className="w-4 h-4" aria-hidden="true" />
                  </button>
                )}
              </div>
              {searchErrorKey ? (
                <p id="ip-search-error" className="mt-1 text-xs text-red-600">
                  {t(searchErrorKey)}
                </p>
              ) : (
                <p id="ip-search-help" className="mt-1 text-xs text-gray-500">
                  {t('ipSearch.help')}
                </p>
              )}
            </div>

            <div className="flex items-end gap-2">
              <button
                type="submit"
                disabled={!canSearch}
                className="inline-flex h-10 items-center justify-center gap-2 rounded-md bg-primary-600 px-4 text-sm font-medium text-white transition-colors hover:bg-primary-700 disabled:bg-gray-400 focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-1"
              >
                <Search className="w-4 h-4" aria-hidden="true" />
                {isLoading ? t('common.loading') : t('ipSearch.search')}
              </button>
            </div>
          </div>

          <label className="inline-flex items-center gap-2 text-sm text-gray-700">
            <input
              type="checkbox"
              checked={includeInactive}
              onChange={(event) => setIncludeInactive(event.target.checked)}
              className="h-4 w-4 rounded border-gray-300 text-primary-600 focus:ring-primary-600"
            />
            {t('ipSearch.includeInactive')}
          </label>
        </form>

        {hasDataError && (
          <div className="flex items-start gap-2 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-800">
            <Info className="w-4 h-4 mt-0.5" aria-hidden="true" />
            <div>
              <p>{t('ipSearch.dataUnavailable')}</p>
              {dataErrorMessage && <p className="mt-1 text-xs">{dataErrorMessage}</p>}
            </div>
          </div>
        )}

        {hasDataError ? (
          <p className="text-sm text-gray-600">{t('ipSearch.errorBlocksResults')}</p>
        ) : !submittedInput?.ip ? (
          <p className="text-sm text-gray-600">{t('ipSearch.empty')}</p>
        ) : (
          <div className="space-y-4" aria-live="polite">
            <div className="flex flex-wrap items-center gap-2 text-sm text-gray-700">
              <span className="font-medium text-gray-900">{submittedInput.ip.text}</span>
              <span>{t('ipSearch.summary', { hostCount: hostMatches.length, networkCount: networkMatches.length })}</span>
            </div>

            <div>
              <div className="mb-2 flex items-center gap-2">
                <Server className="w-4 h-4 text-blue-600" aria-hidden="true" />
                <h4 className="text-sm font-semibold text-gray-900">{t('ipSearch.hostOwners')}</h4>
              </div>
              {hostMatches.length === 0 ? (
                <p className="text-sm text-gray-500">{t('ipSearch.noHostOwners')}</p>
              ) : (
                <div className="overflow-x-auto rounded-md border border-gray-200">
                  <table className="min-w-full divide-y divide-gray-200 text-sm">
                    <thead className="bg-gray-50">
                      <tr>
                        <th scope="col" className="px-3 py-2 text-left font-medium text-gray-700">{t('ipSearch.columns.ip')}</th>
                        <th scope="col" className="px-3 py-2 text-left font-medium text-gray-700">{t('ipSearch.columns.mask')}</th>
                        <th scope="col" className="px-3 py-2 text-left font-medium text-gray-700">{t('ipSearch.columns.node')}</th>
                        <th scope="col" className="px-3 py-2 text-left font-medium text-gray-700">{t('ipSearch.columns.interface')}</th>
                        <th scope="col" className="px-3 py-2 text-left font-medium text-gray-700">{t('ipSearch.columns.vrf')}</th>
                        <th scope="col" className="px-3 py-2 text-left font-medium text-gray-700">{t('ipSearch.columns.status')}</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-100 bg-white">
                      {hostMatches.map((match) => (
                        <tr key={`${match.node}-${match.vrf}-${match.interface}-${match.ip}`}>
                          <td className="px-3 py-2 font-mono text-gray-900">{match.ip}</td>
                          <td className="px-3 py-2 text-gray-700">{match.mask}</td>
                          <td className="px-3 py-2 text-gray-900">{match.node}</td>
                          <td className="px-3 py-2 text-gray-700">{match.interface}</td>
                          <td className="px-3 py-2 text-gray-700">{match.vrf}</td>
                          <td className="px-3 py-2">
                            <StatusBadge active={match.active} label={match.active ? t('ipSearch.status.active') : t('ipSearch.status.inactive')} />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div>
              <div className="mb-2 flex items-center gap-2">
                <Network className="w-4 h-4 text-green-600" aria-hidden="true" />
                <h4 className="text-sm font-semibold text-gray-900">{t('ipSearch.interfaceNetworks')}</h4>
              </div>
              {networkMatches.length === 0 ? (
                <p className="text-sm text-gray-500">{t('ipSearch.noInterfaceNetworks')}</p>
              ) : (
                <div className="overflow-x-auto rounded-md border border-gray-200">
                  <table className="min-w-full divide-y divide-gray-200 text-sm">
                    <thead className="bg-gray-50">
                      <tr>
                        <th scope="col" className="px-3 py-2 text-left font-medium text-gray-700">{t('ipSearch.columns.prefix')}</th>
                        <th scope="col" className="px-3 py-2 text-left font-medium text-gray-700">{t('ipSearch.columns.node')}</th>
                        <th scope="col" className="px-3 py-2 text-left font-medium text-gray-700">{t('ipSearch.columns.interface')}</th>
                        <th scope="col" className="px-3 py-2 text-left font-medium text-gray-700">{t('ipSearch.columns.vrf')}</th>
                        <th scope="col" className="px-3 py-2 text-left font-medium text-gray-700">{t('ipSearch.columns.primaryAddress')}</th>
                        <th scope="col" className="px-3 py-2 text-left font-medium text-gray-700">{t('ipSearch.columns.primaryNetwork')}</th>
                        <th scope="col" className="px-3 py-2 text-left font-medium text-gray-700">{t('ipSearch.columns.source')}</th>
                        <th scope="col" className="px-3 py-2 text-left font-medium text-gray-700">{t('ipSearch.columns.status')}</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-100 bg-white">
                      {networkMatches.map((match) => (
                        <tr key={`${match.hostname}-${match.vrf}-${match.interface}-${match.prefix}-${match.source}`}>
                          <td className="px-3 py-2 font-mono text-gray-900">{match.prefix}</td>
                          <td className="px-3 py-2 text-gray-700">{match.hostname}</td>
                          <td className="px-3 py-2 text-gray-700">{match.interface}</td>
                          <td className="px-3 py-2 text-gray-700">{match.vrf}</td>
                          <td className="px-3 py-2 font-mono text-gray-700">{match.primaryAddress || t('common.notAvailable')}</td>
                          <td className="px-3 py-2 font-mono text-gray-700">{match.primaryNetwork || t('common.notAvailable')}</td>
                          <td className="px-3 py-2 text-gray-700">{sourceLabel(match.source)}</td>
                          <td className="px-3 py-2">
                            <div className="flex flex-wrap gap-1">
                              <StatusBadge active={match.active} label={match.active ? t('ipSearch.status.active') : t('ipSearch.status.inactive')} />
                              <StatusBadge active={match.adminUp} label={match.adminUp ? t('ipSearch.status.adminUp') : t('ipSearch.status.adminDown')} />
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
