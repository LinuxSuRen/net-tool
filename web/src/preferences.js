import { reactive, watch } from 'vue'

// UI state that should survive a page reload lives in localStorage. Values
// are namespaced so different views cannot collide.
const PREFIX = 'net-tool.ui.'

export function readPreference(key, fallback) {
  try {
    const raw = localStorage.getItem(PREFIX + key)
    if (raw === null) return fallback
    const parsed = JSON.parse(raw)
    return parsed === null || parsed === undefined ? fallback : parsed
  } catch (e) {
    return fallback
  }
}

export function writePreference(key, value) {
  try {
    localStorage.setItem(PREFIX + key, JSON.stringify(value))
  } catch (e) {
    // localStorage may be unavailable (private mode); state still works in memory
  }
}

// A reactive filter object whose every change is persisted under key. Stored
// values from an older build are merged onto the defaults so newly added
// filter fields are never undefined.
export function usePersistentFilter(key, fallback) {
  const stored = readPreference(`filter.${key}`, {})
  const saved = stored && typeof stored === 'object' && !Array.isArray(stored) ? stored : {}
  const filter = reactive({ ...fallback, ...saved })

  watch(filter, value => writePreference(`filter.${key}`, value), { deep: true })

  function resetFilter() {
    Object.assign(filter, fallback)
  }

  return { filter, resetFilter }
}

// Table sort state is persisted next to filters so a reload keeps the column
// and direction the user picked. Element Plus reports null when sorting is
// cleared, which we store as an empty prop/no order.
export function usePersistentSort(key, fallback = { prop: '', order: null }) {
  const stored = readPreference(`sort.${key}`, {})
  const saved = stored && typeof stored === 'object' && !Array.isArray(stored) ? stored : {}
  const defaults = { prop: '', order: null, ...fallback }
  const sort = reactive({
    prop: saved.prop || defaults.prop,
    order: ['ascending', 'descending'].includes(saved.order)
      ? saved.order
      : defaults.order
  })

  watch(sort, value => writePreference(`sort.${key}`, value), { deep: true })

  function onSortChange(change) {
    sort.prop = change.prop || ''
    sort.order = change.order || null
  }

  function resetSort() {
    Object.assign(sort, defaults)
  }

  return { sort, onSortChange, resetSort }
}
