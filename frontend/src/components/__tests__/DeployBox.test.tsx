import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'
import { DeployBox } from '../Mitm/DeployBox'

const CA_PEM = `-----BEGIN CERTIFICATE-----
MIIBzTCCAXKgAwIBAgIRAK6n6PSspQ5O5O6g7v9budIwCgYIKoZIzj0EAwIwGjEY
MBYGA1UEAwwPTXl0ZXNrbUl0bTIQy29tIFYxMB4XDTIyMDYwMTAwMDAwMFoXDTI1
MDYwMTAwMDAwMFowGjEYMBYGA1UEAwwPTXl0ZXNrbUl0bTIQy29tIFYxMCIwDQYJ
KoZIhvcNAQEFAASAAQICFQ==
-----END CERTIFICATE-----`

function mockFetch(pem?: string) {
  if (pem) {
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true, text: () => Promise.resolve(pem) } as any)
  } else {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('no backend'))
  }
}

describe('DeployBox', () => {
  beforeEach(() => {
    cleanup()
    vi.restoreAllMocks()
    mockFetch(CA_PEM)
  })

  it('defaults to Windows and targets the given proxy host/port', async () => {
    render(<DeployBox host="10.0.0.5" proxyPort={8080} caPort={18081} />)
    await waitFor(() => expect(screen.queryByText(/CA certificate embedded/)).not.toBeNull())
    expect(screen.getByText('Windows')).toBeInTheDocument()
    expect(screen.getAllByText(/10\.0\.0\.5:8080/).length).toBeGreaterThan(0)
    const pre = screen.getByText((c) => c.includes('Import-Certificate'))
    expect(pre.textContent).toContain('Cert:\\LocalMachine\\Root')
    expect(pre.textContent).toContain('FromBase64String')
    // Embedded CA: no runtime download URL in the command.
    expect(pre.textContent).not.toContain('DownloadFile')
  })

  it('generates a macOS command with networksetup and embedded cert', async () => {
    render(<DeployBox host="10.0.0.5" proxyPort={8080} />)
    await waitFor(() => expect(screen.queryByText(/CA certificate embedded/)).not.toBeNull())
    fireEvent.click(screen.getByText('macOS'))
    const pre = screen.getByText(
      (content) => content.includes('networksetup -setsecurewebproxy')
    )
    expect(pre.textContent).toContain('security add-trusted-cert')
    expect(pre.textContent).toContain('base64 -d')
  })

  it('generates a Linux command with gsettings + CA install', async () => {
    render(<DeployBox host="10.0.0.5" proxyPort={8080} />)
    await waitFor(() => expect(screen.queryByText(/CA certificate embedded/)).not.toBeNull())
    fireEvent.click(screen.getByText('Linux / IoT'))
    const pre = screen.getByText((c) => c.includes('gsettings set org.gnome.system.proxy'))
    expect(pre.textContent).toContain('update-ca-certificates')
    expect(pre.textContent).toContain('10.0.0.5')
  })

  it('generates an Android command with settings put global http_proxy', async () => {
    render(<DeployBox host="10.0.0.5" proxyPort={8080} />)
    await waitFor(() => expect(screen.queryByText(/CA certificate embedded/)).not.toBeNull())
    fireEvent.click(screen.getByText('Android'))
    const pre = screen.getByText((c) => c.includes('settings put global http_proxy'))
    expect(pre.textContent).toContain('http_proxy 10.0.0.5:8080')
  })

  it('falls back to runtime download when the CA cannot be fetched', async () => {
    mockFetch()
    render(<DeployBox host="10.0.0.5" proxyPort={8080} caPort={18081} />)
    await waitFor(() => expect(screen.queryByText(/sarà scaricato a runtime/)).not.toBeNull())
    const pre = screen.getByText((c) => c.includes('Import-Certificate'))
    expect(pre.textContent).toContain('DownloadFile')
    expect(pre.textContent).toContain('http://10.0.0.5:18081/api/ca-certificate')
  })
})
