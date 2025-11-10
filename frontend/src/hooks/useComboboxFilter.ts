import { useState, useMemo } from 'react'

/**
 * Custom hook for filtering items in a combobox/autocomplete field
 * @param items - Array of items to filter
 * @returns query, setQuery, and filtered items
 */
export function useComboboxFilter<T extends string>(items: T[]) {
  const [query, setQuery] = useState('')

  const filteredItems = useMemo(() => {
    if (query === '') {
      return items
    }
    return items.filter((item) =>
      item.toLowerCase().includes(query.toLowerCase())
    )
  }, [items, query])

  return {
    query,
    setQuery,
    filteredItems,
  }
}
