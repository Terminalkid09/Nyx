import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, cleanup, waitFor, fireEvent } from '@testing-library/react'

// ── Mock useNavigate — Network is rendered outside a Router in tests ─────────
const mockNavigate = vi.fn()
vi.mock('react-router-dom', () => ({
  useNavigate: () => mockNavigate,
}))

import { Network } from '../Network/Network'

// ── Mock the axios apiClient so no real backend is contacted ─────────────────

const STATUS_IDLE = {
  running: false,
  interface: '',
  bpf_filter: '',
  pcap_path: null,
  stats: {
    pps: 0, bps: 0, active_flows: 0, tcp_streams: 0, udp_flows: 0,
    bytes_total: 0, packets_total: 0, errors: 0,
    by_protocol: {}, by_port: {}, timestamp: '2026-08-30T12:00:00',
  },
  tcp_streams: 0,
  udp_flows: 0,
  packets_buffered: 0,
  frames_buffered: 0,
}

const INTERFACES = [
  { name: 'Wi-Fi', is_up: true, is_loopback: false, ipv4: ['192.168.1.59'], is_default: true },
  { name: 'McAfee_VPN', is_up: true, is_loopback: false, ipv4: ['10.0.7.232'], is_default: false },
  { name: 'Ethernet', is_up: false, is_loopback: false, ipv4: [], is_default: false },
  { name: 'Loopback Pseudo-Interface 1', is_up: true, is_loopback: true, ipv4: ['127.0.0.1'], is_default: false },
]

vi.mock('../../api/client', () => {
  return {
    apiClient: {
      get: vi.fn(async (url: string) => {
        if (url === '/api/network/status') {
          return { data: { ...STATUS_IDLE } }
        }
        if (url === '/api/network/interfaces') {
          return { data: INTERFACES }
        }
        return { data: [] }
      }),
      post: vi.fn(async () => ({ data: {} })),
    },
  }
})

import { apiClient } from '../../api/client'

/** Restore the module-level default mock — mockImplementation set by one
 *  test persists into the next, so every beforeEach must re-seed it. */
function mockDefault() {
  vi.mocked(apiClient.get).mockImplementation(async (url: string) => {
    if (url === '/api/network/status') return { data: { ...STATUS_IDLE } }
    if (url === '/api/network/interfaces') return { data: INTERFACES }
    return { data: [] }
  })
}

describe('Network — adaptive capture UI', () => {
  beforeEach(() => {
    cleanup()
    vi.clearAllMocks()
    mockDefault()
  })

  it('defaults the interface selector to "auto" and lists discovered interfaces', async () => {
    render(<Network />)
    // The dropdown eventually renders with the auto option preselected.
    const select = (await screen.findByRole('combobox')) as HTMLSelectElement
    expect(select.value).toBe('auto')
    await waitFor(() => expect(screen.getByText(/Auto — follow active interface/)).not.toBeNull())
    // Interfaces from /api/network/interfaces appear as options.
    await waitFor(() => expect((select.options.length) >= 5).toBe(true))
    expect(select.textContent).toContain('Wi-Fi — active')
    expect(select.textContent).toContain('McAfee_VPN')
    expect(select.textContent).toContain('Ethernet (down)')
    expect(select.textContent).toContain('Loopback Pseudo-Interface 1 (loopback)')
    expect(apiClient.get).toHaveBeenCalledWith('/api/network/interfaces')
  })

  it('shows the interface_changes badge when the watchdog rebound', async () => {
    vi.mocked(apiClient.get).mockImplementation(async (url: string) => {
      if (url === '/api/network/status') {
        return {
          data: {
            ...STATUS_IDLE,
            running: true,
            interface: 'Ethernet',
            interface_changes: 2,
            stats: { ...STATUS_IDLE.stats, packets_total: 42 },
          },
        }
      }
      if (url === '/api/network/interfaces') return { data: INTERFACES }
      return { data: [] }
    })

    render(<Network />)
    await waitFor(() =>
      expect(screen.getByText(/2 interface changes/)).not.toBeNull(),
    )
    // No badge in singular wording path is fine; also confirm the rebound
    // interface is shown in the status line.
    await waitFor(() => expect(screen.getByText(/Capturing on Ethernet/)).not.toBeNull())
  })

  it('hides the badge when there were no interface changes', async () => {
    vi.mocked(apiClient.get).mockImplementation(async (url: string) => {
      if (url === '/api/network/status') return { data: { ...STATUS_IDLE } }
      if (url === '/api/network/interfaces') return { data: INTERFACES }
      return { data: [] }
    })

    render(<Network />)
    await waitFor(() => expect(screen.getByText(/Capture stopped/)).not.toBeNull())
    expect(screen.queryByText(/interface change/)).toBeNull()
  })

  it('falls back to the free-text input when /interfaces is unavailable', async () => {
    vi.mocked(apiClient.get).mockImplementation(async (url: string) => {
      if (url === '/api/network/status') return { data: { ...STATUS_IDLE } }
      if (url === '/api/network/interfaces') {
        throw new Error('404 — older backend')
      }
      return { data: [] }
    })

    render(<Network />)
    // The text fallback keeps capture usable on older backends.
    const input = await screen.findByPlaceholderText(/Interface \(e\.g\. Wi-Fi/)
    expect(input).not.toBeNull()
    expect(screen.queryByRole('combobox')).toBeNull()
  })
})

describe('Network — BPF protocol checkboxes + advanced mode', () => {
  beforeEach(() => {
    cleanup()
    vi.clearAllMocks()
    mockDefault()
  })

  it('composes the BPF from checked protocols and sends it on Start', async () => {
    render(<Network />)
    // Default: all four on → the backend's widened default expression.
    await waitFor(() =>
      expect(screen.getByText(/→ tcp or udp or icmp or arp/)).not.toBeNull(),
    )
    // Uncheck ICMP + ARP → only tcp or udp remains.
    fireEvent.click(screen.getByRole('checkbox', { name: 'ICMP' }))
    fireEvent.click(screen.getByRole('checkbox', { name: 'ARP' }))
    await waitFor(() => expect(screen.getByText(/→ tcp or udp$/)).not.toBeNull())

    fireEvent.click(screen.getByText('Start Capture'))
    expect(apiClient.post).toHaveBeenCalledWith('/api/network/capture/start', {
      interface: 'auto',
      bpf_filter: 'tcp or udp',
      pcap_path: null,
    })
  })

  it('disables Start when no protocol is selected', async () => {
    render(<Network />)
    await waitFor(() => screen.getByRole('combobox'))
    for (const p of ['TCP', 'UDP', 'ICMP', 'ARP']) {
      fireEvent.click(screen.getByRole('checkbox', { name: p }))
    }
    await waitFor(() =>
      expect(screen.getByText(/no protocol selected/)).not.toBeNull(),
    )
    const btn = screen.getByText('Start Capture').closest('button') as HTMLButtonElement
    expect(btn.disabled).toBe(true)
  })

  it('advanced mode swaps checkboxes for a raw BPF input seeded with the composed expression', async () => {
    render(<Network />)
    await waitFor(() => screen.getByRole('combobox'))
    fireEvent.click(screen.getByRole('checkbox', { name: 'Advanced BPF' }))
    const raw = await screen.findByPlaceholderText(/raw BPF/)
    expect((raw as HTMLInputElement).value).toBe('tcp or udp or icmp or arp')
    // Editing the raw expression is what gets sent on Start.
    fireEvent.change(raw, { target: { value: 'tcp port 443' } })
    fireEvent.click(screen.getByText('Start Capture'))
    expect(apiClient.post).toHaveBeenCalledWith('/api/network/capture/start', {
      interface: 'auto',
      bpf_filter: 'tcp port 443',
      pcap_path: null,
    })
  })
})

describe('Network — packet detail (double-click, Wireshark-style)', () => {
  beforeEach(() => {
    cleanup()
    vi.clearAllMocks()
    mockDefault()
  })

  const PACKETS = [
    {
      seq: 42,
      timestamp: '2026-08-30T12:00:00',
      length: 74,
      proto: 'tcp',
      src: '10.0.0.1',
      dst: '93.184.216.34',
      sport: 54321,
      dport: 80,
    },
  ]

  const DETAIL = {
    seq: 42,
    timestamp: '2026-08-30T12:00:00',
    length: 74,
    sniffed_on: 'Wi-Fi',
    proto: 'tcp',
    layers: [
      { name: 'Ethernet', fields: { dst: '11:22:33:44:55:66' } },
      { name: 'IP', fields: { src: '10.0.0.1', dst: '93.184.216.34' } },
      { name: 'TCP', fields: { dport: { repr: 'http', raw: 80 } } },
    ],
    hexdump: '0000  11 22 33 44 55 66  aa bb cc dd ee ff  08 00',
  }

  it('double-clicking a packet row fetches and renders the layer tree', async () => {
    vi.mocked(apiClient.get).mockImplementation(async (url: string) => {
      if (url === '/api/network/status') return { data: { ...STATUS_IDLE } }
      if (url === '/api/network/interfaces') return { data: INTERFACES }
      if (url === '/api/network/packets') return { data: PACKETS }
      if (url === '/api/network/packets/42') return { data: DETAIL }
      return { data: [] }
    })

    render(<Network />)
    const srcCell = await screen.findByText('10.0.0.1')
    fireEvent.doubleClick(srcCell.closest('tr')!)

    await waitFor(() =>
      expect(screen.getByText(/Packet #42/)).not.toBeNull(),
    )
    // Layer tree renders Wireshark-style names, fields and the bytes pane.
    await waitFor(() => expect(screen.getByText('Ethernet')).not.toBeNull())
    expect(screen.getByText('IP')).not.toBeNull()
    // "TCP" also matches the BPF checkbox label behind the modal — the
    // layer row is the one inside a <button>.
    expect(screen.getAllByText('TCP').length).toBeGreaterThan(0)
    // dst IP appears in the table row AND the IP layer fields — both fine.
    expect(screen.getAllByText('93.184.216.34').length).toBeGreaterThan(0)
    // testing-library normalizes runs of whitespace — match the hexdump flexibly.
    expect(screen.getByText(/0000\s+11 22 33/)).not.toBeNull()
    expect(apiClient.get).toHaveBeenCalledWith('/api/network/packets/42')

    // Collapsing a layer hides its fields.
    const tcpLayer = screen.getAllByText('TCP').find((el) => el.closest('button'))!
    fireEvent.click(tcpLayer)
    await waitFor(() => expect(screen.queryByText('http')).toBeNull())

    // Close button dismisses the modal.
    fireEvent.click(screen.getByRole('button', { name: 'Close packet detail' }))
    expect(screen.queryByText(/Packet #42/)).toBeNull()
  })

  it('shows a friendly error when the packet left the buffer (404)', async () => {
    vi.mocked(apiClient.get).mockImplementation(async (url: string) => {
      if (url === '/api/network/status') return { data: { ...STATUS_IDLE } }
      if (url === '/api/network/interfaces') return { data: INTERFACES }
      if (url === '/api/network/packets') return { data: PACKETS }
      if (url === '/api/network/packets/42') {
        throw Object.assign(new Error('Request failed'), {
          response: { data: { detail: 'Packet 42 not in buffer' } },
        })
      }
      return { data: [] }
    })

    render(<Network />)
    const srcCell = await screen.findByText('10.0.0.1')
    fireEvent.doubleClick(srcCell.closest('tr')!)

    await waitFor(() =>
      expect(screen.getByText(/Packet 42 not in buffer/)).not.toBeNull(),
    )
  })
})

describe('Network — MITM stream integration (Proxy link + stream detail)', () => {
  beforeEach(() => {
    cleanup()
    vi.clearAllMocks()
    mockDefault()
  })

  const STREAMS = [
    {
      stream_id: '192.168.1.59-93.184.216.34-54321-443-6',
      five_tuple: {
        src_ip: '192.168.1.59', dst_ip: '93.184.216.34',
        src_port: 54321, dst_port: 443, protocol: 6,
      },
      transport: 'tcp',
      frame_count: 12,
      start_time: '2026-08-30T12:00:00',
      last_seen: '2026-08-30T12:00:10',
      bytes_total: 4096,
      sni: 'example.com',
      link: { type: 'proxy', protocol: 'tls' },
    },
  ]

  const STREAM_FRAMES = [
    {
      frame_type: 'tls',
      timestamp: '2026-08-30T12:00:01',
      data: { sni: 'example.com', note: 'TLS handled by mitmproxy' },
    },
    {
      frame_type: 'tcp_frame',
      timestamp: '2026-08-30T12:00:02',
      data: { seq: 1, payload_length: 517, is_client: true },
    },
  ]

  it('renders the SNI label and a clickable Proxy chip that navigates', async () => {
    vi.mocked(apiClient.get).mockImplementation(async (url: string) => {
      if (url === '/api/network/status') return { data: { ...STATUS_IDLE } }
      if (url === '/api/network/interfaces') return { data: INTERFACES }
      if (url === '/api/network/streams') return { data: STREAMS }
      return { data: [] }
    })

    render(<Network />)

    // SNI column shows the hostname extracted from the ClientHello.
    await waitFor(() => expect(screen.getByText('example.com')).not.toBeNull())

    // The Proxy chip is a real button — clicking it jumps to the Proxy tab.
    const chip = screen.getByRole('button', { name: /tls → Proxy tab/ })
    fireEvent.click(chip)
    expect(mockNavigate).toHaveBeenCalledWith('/proxy')
  })

  it('double-clicking a stream row opens the frame-by-frame conversation', async () => {
    vi.mocked(apiClient.get).mockImplementation(async (url: string) => {
      if (url === '/api/network/status') return { data: { ...STATUS_IDLE } }
      if (url === '/api/network/interfaces') return { data: INTERFACES }
      if (url === '/api/network/streams') return { data: STREAMS }
      if (url === '/api/network/streams/192.168.1.59-93.184.216.34-54321-443-6/frames') {
        return { data: STREAM_FRAMES }
      }
      return { data: [] }
    })

    render(<Network />)
    const sniCell = await screen.findByText('example.com')
    fireEvent.doubleClick(sniCell.closest('tr')!)

    // Modal header shows the five-tuple + SNI.
    await waitFor(() =>
      expect(screen.getByText(/192\.168\.1\.59:54321 → 93\.184\.216\.34:443 · example\.com/)).not.toBeNull(),
    )
    // Frames render with type coloring and the shared frameSummary text.
    await waitFor(() => expect(screen.getByText(/TLS → example\.com/)).not.toBeNull())
    expect(screen.getByText(/TCP seq=1 len=517 C→S/)).not.toBeNull()
    expect(apiClient.get).toHaveBeenCalledWith(
      '/api/network/streams/192.168.1.59-93.184.216.34-54321-443-6/frames',
    )

    // Close dismisses the modal (the five-tuple alone also exists in the
    // table row behind it — assert on the modal-only header + SNI combo).
    fireEvent.click(screen.getByRole('button', { name: 'Close stream detail' }))
    expect(screen.queryByText(/54321 → 93\.184\.216\.34:443 · example\.com/)).toBeNull()
  })

  it('shows an error in the stream modal when the frames request fails', async () => {
    vi.mocked(apiClient.get).mockImplementation(async (url: string) => {
      if (url === '/api/network/status') return { data: { ...STATUS_IDLE } }
      if (url === '/api/network/interfaces') return { data: INTERFACES }
      if (url === '/api/network/streams') return { data: STREAMS }
      if (url.startsWith('/api/network/streams/')) {
        throw Object.assign(new Error('Request failed'), {
          response: { data: { detail: 'stream not found' } },
        })
      }
      return { data: [] }
    })

    render(<Network />)
    const sniCell = await screen.findByText('example.com')
    fireEvent.doubleClick(sniCell.closest('tr')!)

    await waitFor(() =>
      expect(screen.getByText(/stream not found/)).not.toBeNull(),
    )
  })
})

describe('Network — capture visibility warnings (virtual adapter + single-host filter)', () => {
  beforeEach(() => {
    cleanup()
    vi.clearAllMocks()
    mockDefault()
  })

  it('warns when capturing on a VPN/virtual adapter (running)', async () => {
    vi.mocked(apiClient.get).mockImplementation(async (url: string) => {
      if (url === '/api/network/status') {
        return { data: { ...STATUS_IDLE, running: true, interface: 'McAfee_VPN' } }
      }
      if (url === '/api/network/interfaces') return { data: INTERFACES }
      return { data: [] }
    })

    render(<Network />)
    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain('McAfee_VPN')
    expect(alert.textContent).toContain('VPN/virtual adapter')
  })

  it('warns pre-start when a virtual adapter is selected in the dropdown', async () => {
    render(<Network />)
    const select = (await screen.findByRole('combobox')) as HTMLSelectElement
    fireEvent.change(select, { target: { value: 'McAfee_VPN' } })
    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain('McAfee_VPN')
  })

  it('does not warn on a physical adapter', async () => {
    vi.mocked(apiClient.get).mockImplementation(async (url: string) => {
      if (url === '/api/network/status') {
        return { data: { ...STATUS_IDLE, running: true, interface: 'Wi-Fi' } }
      }
      if (url === '/api/network/interfaces') return { data: INTERFACES }
      return { data: [] }
    })

    render(<Network />)
    await waitFor(() => expect(screen.getByText(/Capturing on Wi-Fi/)).not.toBeNull())
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it('warns when the active filter is a single host (running)', async () => {
    vi.mocked(apiClient.get).mockImplementation(async (url: string) => {
      if (url === '/api/network/status') {
        return {
          data: {
            ...STATUS_IDLE,
            running: true,
            interface: 'Wi-Fi',
            bpf_filter: 'host 216.24.57.15',
          },
        }
      }
      if (url === '/api/network/interfaces') return { data: INTERFACES }
      return { data: [] }
    })

    render(<Network />)
    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain('host 216.24.57.15')
    expect(alert.textContent).toContain('only')
  })

  it('warns live while typing a host filter in Advanced mode', async () => {
    render(<Network />)
    await screen.findByRole('combobox')
    fireEvent.click(screen.getByRole('checkbox', { name: 'Advanced BPF' }))
    const raw = (await screen.findByPlaceholderText(/raw BPF/)) as HTMLInputElement
    fireEvent.change(raw, { target: { value: 'host 93.184.216.34' } })
    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain('host 93.184.216.34')
  })

  it('does not warn for wide filters', async () => {
    vi.mocked(apiClient.get).mockImplementation(async (url: string) => {
      if (url === '/api/network/status') {
        return {
          data: { ...STATUS_IDLE, running: true, interface: 'Wi-Fi', bpf_filter: 'tcp or udp' },
        }
      }
      if (url === '/api/network/interfaces') return { data: INTERFACES }
      return { data: [] }
    })

    render(<Network />)
    await waitFor(() => expect(screen.getByText(/Capturing on Wi-Fi/)).not.toBeNull())
    expect(screen.queryByRole('alert')).toBeNull()
  })
})

describe('Network — QUIC connections table', () => {
  const QUIC_CONNS = [
    {
      conn_id: 'aabbccdd11223344',
      dcid: 'aabbccdd11223344',
      version: 1,
      packet_count: 42,
      packet_types: { initial: 1, handshake: 3, short: 38 },
      first_seen: '2026-09-03T08:41:30',
      last_seen: '2026-09-03T08:41:33',
      five_tuple: { src_ip: '192.168.1.59', dst_ip: '142.250.184.174', src_port: 55000, dst_port: 443 },
    },
    {
      conn_id: 'ffff000011112222',
      dcid: 'ffff000011112222',
      version: 2,
      packet_count: 7,
      packet_types: { initial: 1, short: 6 },
      first_seen: '2026-09-03T08:41:31',
      last_seen: '2026-09-03T08:41:34',
      five_tuple: { src_ip: '172.217.16.14', dst_ip: '192.168.1.59', src_port: 443, dst_port: 55001 },
    },
  ]

  beforeEach(() => {
    cleanup()
    vi.clearAllMocks()
    vi.mocked(apiClient.get).mockImplementation(async (url: string) => {
      if (url === '/api/network/status') return { data: { ...STATUS_IDLE, running: true, interface: 'Wi-Fi' } }
      if (url === '/api/network/interfaces') return { data: INTERFACES }
      if (url === '/api/network/quic') return { data: QUIC_CONNS }
      return { data: [] }
    })
  })

  it('hides the section entirely when there are no QUIC connections', async () => {
    vi.mocked(apiClient.get).mockImplementation(async (url: string) => {
      if (url === '/api/network/status') return { data: { ...STATUS_IDLE, running: true, interface: 'Wi-Fi' } }
      if (url === '/api/network/interfaces') return { data: INTERFACES }
      return { data: [] }
    })

    render(<Network />)
    await waitFor(() => expect(screen.getByText(/Capturing on Wi-Fi/)).not.toBeNull())
    expect(screen.queryByText(/QUIC connections/)).toBeNull()
  })

  it('shows a collapsed table that expands to the per-connection rows', async () => {
    render(<Network />)

    // Section appears (collapsed by default) once connections exist.
    const toggle = await screen.findByRole('button', { name: /QUIC connections \(2\)/ })
    // Rows not rendered while collapsed.
    expect(screen.queryByText('142.250.184.174:443')).toBeNull()

    fireEvent.click(toggle)

    // Peer resolved to the 443-speaking side for both directions.
    expect(await screen.findByText('142.250.184.174:443')).not.toBeNull()
    expect(screen.getByText('aabbccdd1122…')).not.toBeNull()   // conn id truncated
    expect(screen.getByText('42')).not.toBeNull()                  // packet count
    expect(screen.getByText(/initial×1 \+ handshake×3 \+ short×38/)).not.toBeNull()
    // Second connection (server-initiated row): peer is the src side.
    expect(screen.getByText('172.217.16.14:443')).not.toBeNull()  // server-initiated row: peer = src side
    expect(screen.getByText(/v2/)).not.toBeNull()
    // Collapsing again hides the rows.
    fireEvent.click(screen.getByRole('button', { name: /QUIC connections \(2\)/ }))
    expect(screen.queryByText('142.250.184.174:443')).toBeNull()
  })

  it('opens the connection detail modal on double-click of a quic frames row', async () => {
    const QUIC_FRAME = {
      frame_type: 'quic',
      timestamp: '2026-09-03T08:41:33',
      data: {
        aggregated: true,
        conn_id: 'aabbccdd11223344',
        dcid: 'aabbccdd11223344',
        version: 1,
        packet_count: 3,
        packet_types: { initial: 1, short: 2 },
      },
      five_tuple: { src_ip: '192.168.1.59', dst_ip: '142.250.184.174', src_port: 55000, dst_port: 443, protocol: 17 },
    }
    vi.mocked(apiClient.get).mockImplementation(async (url: string) => {
      if (url === '/api/network/status') return { data: { ...STATUS_IDLE, running: true, interface: 'Wi-Fi' } }
      if (url === '/api/network/interfaces') return { data: INTERFACES }
      if (url === '/api/network/quic') return { data: QUIC_CONNS }
      if (url === '/api/network/frames') return { data: [QUIC_FRAME] }
      return { data: [] }
    })

    render(<Network />)

    // The aggregated frame row appears in the frames list (CID truncated to 8).
    const row = await screen.findByText(/QUIC conn aabbccdd… · 3 packets/)
    // Enriched live from the registry: 42 packets there vs 3 in the frame.
    fireEvent.doubleClick(row)

    const dialog = await screen.findByLabelText('Close QUIC detail')
    expect(dialog).not.toBeNull()
    // Modal shows registry-live count (42), the full CID, five-tuple, types.
    expect(screen.getByText('42')).not.toBeNull()
    expect(screen.getByText('aabbccdd11223344')).not.toBeNull()
    expect(screen.getByText(/192.168.1.59:55000 → 142.250.184.174:443 · UDP/)).not.toBeNull()
    expect(screen.getByText('initial: 1')).not.toBeNull()
    expect(screen.getByText('short: 38')).not.toBeNull()

    // Close restores the base view.
    fireEvent.click(dialog)
    expect(screen.queryByLabelText('Close QUIC detail')).toBeNull()
  })
})
