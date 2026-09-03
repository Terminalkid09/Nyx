import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, cleanup } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'

const repeaterApi = vi.hoisted(() => ({
  sendRequest: vi.fn(),
  fetchTabs: vi.fn(),
  createTab: vi.fn(),
  closeTab: vi.fn(),
  fetchTabHistory: vi.fn(),
}))

vi.mock('../../api/endpoints/repeater', () => repeaterApi)

describe('Repeater', () => {
  beforeEach(() => {
    cleanup()
    vi.clearAllMocks()
    repeaterApi.sendRequest.mockResolvedValue({
      status: 200,
      headers: {},
      body: 'ok',
      time_ms: 10,
    })
  })

  it('keeps the prefill tab when backend tabs load (regression)', async () => {
    repeaterApi.fetchTabs.mockResolvedValue([
      { id: 'backend-1', name: 'Saved', created_at: '', history_count: 2 },
    ])
    repeaterApi.fetchTabHistory.mockResolvedValue([
      {
        method: 'GET',
        url: 'https://bank.example.com/transfer',
        headers: { Host: 'bank.example.com' },
        body: null,
        response_status: 200,
        response_headers: {},
        response_body: '',
        time_ms: 10,
        timestamp: '2026-01-01T00:00:00Z',
      },
    ])

    const { Repeater } = await import('../Repeater/Repeater')
    render(
      <MemoryRouter
        initialEntries={[
          {
            pathname: '/repeater',
            search: '',
            state: {
              url: 'target.example.com/api/login',
              method: 'POST',
              headers: 'Content-Type: application/json',
              body: '{"user":"a"}',
            },
          },
        ]}
      >
        <Repeater />
      </MemoryRouter>
    )

    // The prefilled URL must survive the backend tab merge.
    await waitFor(() => {
      expect(
        screen.getByPlaceholderText('target.com/api/endpoint')
      ).toHaveValue('target.example.com/api/login')
    })

    // Saved backend tab is appended, not replacing the prefill tab.
    await waitFor(() => {
      expect(repeaterApi.fetchTabs).toHaveBeenCalledTimes(1)
    })
    expect(screen.getByText('Saved')).toBeInTheDocument()
    expect(
      screen.getByPlaceholderText('target.com/api/endpoint')
    ).toHaveValue('target.example.com/api/login')
  })

  it('replaces the empty initial tab with backend tabs when no prefill', async () => {
    repeaterApi.fetchTabs.mockResolvedValue([
      { id: 'backend-1', name: 'Saved', history_count: 1 },
    ])
    repeaterApi.fetchTabHistory.mockResolvedValue([
      {
        method: 'GET',
        url: 'https://bank.example.com/transfer',
        headers: {},
        body: null,
        response_status: 200,
        response_headers: {},
        response_body: '',
        time_ms: 10,
        timestamp: '2026-01-01T00:00:00Z',
      },
    ])

    const { Repeater } = await import('../Repeater/Repeater')
    render(
      <MemoryRouter initialEntries={[{ pathname: '/repeater' }]}>
        <Repeater />
      </MemoryRouter>
    )

    await waitFor(() => {
      expect(repeaterApi.fetchTabs).toHaveBeenCalledTimes(1)
    })
    expect(screen.getByText('Saved')).toBeInTheDocument()
    // No prefill -> the loaded backend data fills the editor.
    await waitFor(() => {
      expect(
        screen.getByPlaceholderText('target.com/api/endpoint')
      ).toHaveValue('bank.example.com/transfer')
    })
  })
})