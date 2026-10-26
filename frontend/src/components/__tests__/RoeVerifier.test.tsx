import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react'
import { RulesOfEngagement } from '../RoE/RulesOfEngagement'
import { Verifier } from '../Verifier/Verifier'

const { PROFILE } = vi.hoisted(() => ({
  PROFILE: {
    id: '11111111-1111-1111-1111-111111111111',
    name: 'ACME engagement',
    targets: ['*.acme.test'],
    exclusions: ['admin.acme.test'],
    window_start: null,
    window_end: null,
    max_rps: 2,
    signature: 'deadbeef',
    signature_valid: true,
    active: true,
    created_at: '2026-10-26T10:00:00+00:00',
  },
}))

vi.mock('../../api/endpoints/roe', () => ({
  listRoEProfiles: vi.fn().mockResolvedValue([PROFILE]),
  createRoEProfile: vi.fn(),
  updateRoEProfile: vi.fn(),
  deleteRoEProfile: vi.fn(),
  setRoEProfileActive: vi.fn().mockResolvedValue({ ...PROFILE, active: false }),
  verifyRoEProfile: vi.fn(),
}))

vi.mock('../../api/endpoints/verifier', () => ({
  verifyExploit: vi.fn().mockResolvedValue({
    verdict: 'confirmed',
    signals: ['status_changed'],
    status_delta: 500,
    length_delta: 128,
    time_delta_ms: 12,
    similarity: 0.12,
  }),
}))

import { setRoEProfileActive } from '../../api/endpoints/roe'
import { verifyExploit } from '../../api/endpoints/verifier'

beforeEach(() => {
  vi.clearAllMocks()
})

afterEach(() => {
  cleanup()
})

describe('RulesOfEngagement', () => {
  it('renders signed profiles and toggles activation', async () => {
    render(<RulesOfEngagement />)

    await screen.findByText('ACME engagement')
    expect(screen.getByText('SIGNATURE VALID')).toBeInTheDocument()
    expect(screen.getByText('*.acme.test')).toBeInTheDocument()
    expect(screen.getByText('admin.acme.test')).toBeInTheDocument()
    expect(screen.getByText('2 req/s')).toBeInTheDocument()

    fireEvent.click(screen.getByTitle('Deactivate'))
    await waitFor(() =>
      expect(setRoEProfileActive).toHaveBeenCalledWith(PROFILE.id, false),
    )
  })
})

describe('Verifier', () => {
  it('submits the hypothesis and shows the differential verdict', async () => {
    render(<Verifier />)

    fireEvent.change(
      screen.getByPlaceholderText('https://target.test/api/items?id=1'),
      { target: { value: 'https://target.test/api/items?id=1' } },
    )
    fireEvent.change(screen.getByPlaceholderText('id'), { target: { value: 'id' } })
    fireEvent.change(screen.getByPlaceholderText("1' OR 1=1--"), {
      target: { value: "1' OR 1=1--" },
    })
    fireEvent.click(screen.getByRole('button', { name: /verify/i }))

    await screen.findByText('Confirmed')
    expect(verifyExploit).toHaveBeenCalledWith(
      expect.objectContaining({
        url: 'https://target.test/api/items?id=1',
        param: 'id',
        payload: "1' OR 1=1--",
      }),
    )
    expect(screen.getByText('HTTP status changed')).toBeInTheDocument()
    expect(screen.getByText('+500')).toBeInTheDocument()
    expect(screen.getByText('12.0%')).toBeInTheDocument()
  })
})
