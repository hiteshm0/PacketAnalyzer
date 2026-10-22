import { Filter, X } from 'lucide-react'
import type { Filters } from '../types'

interface FilterBarProps {
  filters: Filters
  onChangeFilter: (key: keyof Filters, value: string) => void
  onClearFilters: () => void
}

export function FilterBar({ filters, onChangeFilter, onClearFilters }: FilterBarProps) {
  const activeCount = [filters.protocol, filters.ip, filters.port].filter(Boolean).length

  return (
    <section className="filters">
      <div className="filter-label">
        <Filter size={14} />
        <span>Filters</span>
        {activeCount > 0 && <span className="filter-badge">{activeCount}</span>}
      </div>

      <label>
        Protocol
        <select value={filters.protocol} onChange={e => onChangeFilter('protocol', e.target.value)}>
          <option value="">All</option>
          {['TCP', 'UDP', 'ICMP', 'ARP', 'OTHER'].map(x => (
            <option key={x}>{x}</option>
          ))}
        </select>
      </label>

      <label>
        IP
        <input
          placeholder="Source or destination"
          value={filters.ip}
          onChange={e => onChangeFilter('ip', e.target.value)}
        />
      </label>

      <label>
        Port
        <input
          type="number"
          min="0"
          max="65535"
          placeholder="Source or destination"
          value={filters.port}
          onChange={e => onChangeFilter('port', e.target.value)}
        />
      </label>

      {activeCount > 0 && (
        <button className="clear-filters" onClick={onClearFilters}>
          <X size={14} />
          Clear
        </button>
      )}
    </section>
  )
}
