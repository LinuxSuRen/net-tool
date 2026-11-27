// Shared table sorting helpers. Views hand us the column value they want to
// compare so the same comparator works for numbers, text and status flags.

export function compareValues(a, b) {
  if (a === b) return 0
  if (a === null || a === undefined || a === '') return 1
  if (b === null || b === undefined || b === '') return -1
  if (typeof a === 'number' && typeof b === 'number') return a - b
  return String(a).localeCompare(String(b), 'zh-CN', { numeric: true, sensitivity: 'base' })
}

export function sortRows(rows, sort, valueOf) {
  if (!sort || !sort.prop || !sort.order) return rows
  const dir = sort.order === 'ascending' ? 1 : -1
  return [...rows].sort((a, b) =>
    dir * compareValues(valueOf(a, sort.prop), valueOf(b, sort.prop))
  )
}
