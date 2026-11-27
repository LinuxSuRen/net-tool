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
