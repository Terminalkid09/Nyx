import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import { AbTest } from '../AbTest/AbTest'
import { Importer } from '../Importer/Importer'

vi.mock('../../api/endpoints/abTest', () => ({
  runAbTest: vi.fn().mockResolvedValue({
    verdict: 'suspected_idor',
    severity: 'high',
    confidence: 0.91,
    similarity: 0.97,
    signals: ['identity_b_sees_identity_a_record'],
    samples: [
      {
        label: 'A',
        status: 200,
        length: 512,
        content_type: 'application/json',
        location: null,
        challenge: false,
        time_ms: 42,
        error: null,
        body_preview: '{"id":1,"email":"a@acme.test"}',
      },
      {
        label: 'B',
        status: 200,
        length: 512,
        content_type: 'application/json',
        location: null,
        challenge: false,
        time_ms: 45,
        error: null,
        body_preview: '{"id":1,"email":"a@acme.test"}',
      },
    ],
  }),
}))

// vi.mock is hoisted above the imports, so the fixture has to be hoisted too.
const { INVENTORY } = vi.hoisted(() => ({
  INVENTORY: {
    spec: { version: '3.0.3', title: 'Acme API', api_version: '1.4' },
    servers: ['https://api.acme.test'],
    endpoint_count: 2,
    method_counts: { get: 2 },
    endpoints: [
      {
        method: 'get',
        path: '/users',
        url: 'https://api.acme.test/users',
        operation_id: 'listUsers',
        summary: 'List users',
        parameters: [{ name: 'page', in: 'query', required: false, type: 'integer' }],
        content_types: [],
        security: [],
        authenticated: false,
      },
      {
        method: 'get',
        path: '/admin',
        url: 'https://api.acme.test/admin',
        operation_id: 'admin',
        summary: null,
        parameters: [],
        content_types: [],
        security: ['bearer'],
        authenticated: true,
      },
    ],
    warnings: [
      {
        severity: 'medium',
        code: 'plaintext_server',
        message: 'Server https://api.acme.test is plain HTTP.',
        method: null,
        path: null,
      },
    ],
    filename: 'acme.yaml',
    scope: { added: ['api.acme.test'], skipped: [] },
  },
}))

vi.mock('../../api/endpoints/imports', () => ({
  importOpenApi: vi.fn().mockResolvedValue(INVENTORY),
  importBurp: vi.fn().mockResolvedValue({
    ...INVENTORY,
    spec: { version: 'burp-xml', title: 'acme', api_version: '' },
    item_count: 42,
    filename: 'acme.xml',
    scope: undefined,
  }),
}))

import { runAbTest } from '../../api/endpoints/abTest'
import { importBurp, importOpenApi } from '../../api/endpoints/imports'

beforeEach(() => {
  vi.clearAllMocks()
})

afterEach(() => {
  cleanup()
})

describe('AbTest', () => {
  it('parses the header textareas and shows the differential verdict', async () => {
    render(<AbTest />)

    fireEvent.change(screen.getByPlaceholderText('https://target.test/admin/users/1'), {
      target: { value: 'https://target.test/admin/users/1' },
    })
    fireEvent.change(screen.getByPlaceholderText('Cookie: session=a…'), {
      target: { value: 'Cookie: sid=a\nX-Tenant: acme' },
    })
    fireEvent.change(screen.getByPlaceholderText('Cookie: session=b…'), {
      target: { value: 'Cookie: sid=b' },
    })
    fireEvent.click(screen.getByRole('button', { name: /run comparison/i }))

    await screen.findByText('Suspected IDOR')
    expect(screen.getByText('identity_b_sees_identity_a_record')).toBeInTheDocument()
    expect(screen.getByText(/confidence 91%/)).toBeInTheDocument()

    expect(runAbTest).toHaveBeenCalledWith(
      expect.objectContaining({
        url: 'https://target.test/admin/users/1',
        identity_a: expect.objectContaining({
          headers: { Cookie: 'sid=a', 'X-Tenant': 'acme' },
        }),
        identity_b: expect.objectContaining({ headers: { Cookie: 'sid=b' } }),
        anonymous: true,
      }),
    )
  })
})

describe('Importer', () => {
  it('imports a pasted document and renders the inventory', async () => {
    render(<Importer />)

    fireEvent.change(screen.getByPlaceholderText(/openapi: 3\.0\.3/), {
      target: { value: 'openapi: 3.0.3\npaths: {}' },
    })
    fireEvent.click(screen.getByRole('button', { name: /import document/i }))

    await screen.findByText('Acme API')
    expect(screen.getByText('Endpoints')).toBeInTheDocument()
    expect(screen.getByText('/users')).toBeInTheDocument()
    expect(screen.getByText('List users')).toBeInTheDocument()
    // A declared bearer scheme shows as the auth requirement of that endpoint.
    expect(screen.getByText('bearer')).toBeInTheDocument()
    // Plain-HTTP server warning from the contract review.
    expect(screen.getByText(/is plain HTTP/i)).toBeInTheDocument()

    expect(importOpenApi).toHaveBeenCalledWith(
      expect.objectContaining({
        document: 'openapi: 3.0.3\npaths: {}',
        apply_scope: false,
      }),
    )
  })

  it('sends a Burp export to the Burp importer', async () => {
    render(<Importer />)

    fireEvent.click(screen.getByRole('button', { name: 'Burp XML' }))
    fireEvent.change(screen.getByPlaceholderText(/<items burpVersion/), {
      target: { value: '<items><item><url>https://acme.test/x</url></item></items>' },
    })
    fireEvent.click(screen.getByRole('button', { name: /import document/i }))

    await screen.findByText(/Burp export/)
    expect(importBurp).toHaveBeenCalledWith(
      expect.objectContaining({
        document: '<items><item><url>https://acme.test/x</url></item></items>',
      }),
    )
    expect(importOpenApi).not.toHaveBeenCalled()
  })
})
