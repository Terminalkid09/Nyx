import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'

vi.mock('../../api/client', () => ({
  apiClient: {
    get: vi.fn().mockRejectedValue(new Error('no backend')),
  },
}))

vi.mock('recharts', () => ({
  ResponsiveContainer: ({ children }: any) => <div>{children}</div>,
  PieChart: ({ children }: any) => <div>{children}</div>,
  Pie: () => null,
  Cell: () => null,
  Tooltip: () => null,
  LineChart: ({ children }: any) => <div>{children}</div>,
  Line: () => null,
  XAxis: () => null,
  YAxis: () => null,
  CartesianGrid: () => null,
  BarChart: ({ children }: any) => <div>{children}</div>,
  Bar: () => null,
  Legend: () => null,
}))

describe('Dashboard', () => {
  it('renders the dashboard header in loading state', async () => {
    const { Dashboard } = await import('../Dashboard')
    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>
    )
    expect(screen.getByText('Dashboard')).toBeInTheDocument()
  })
})
