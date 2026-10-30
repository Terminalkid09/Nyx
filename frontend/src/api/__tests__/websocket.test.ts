import { describe, expect, it } from 'vitest'

import { buildWsUrl } from '../websocket'

describe('buildWsUrl', () => {
  it('leaves the URL unchanged without a token', () => {
    expect(buildWsUrl('ws://127.0.0.1:8000/ws/traffic', null)).toBe(
      'ws://127.0.0.1:8000/ws/traffic',
    )
  })

  it('appends the token as a query parameter', () => {
    expect(buildWsUrl('ws://127.0.0.1:8000/ws/traffic', 'abc')).toBe(
      'ws://127.0.0.1:8000/ws/traffic?token=abc',
    )
  })

  it('keeps existing query parameters and encodes the token', () => {
    expect(buildWsUrl('ws://host/ws/traffic?x=1', 'a b&c')).toBe(
      'ws://host/ws/traffic?x=1&token=a%20b%26c',
    )
  })
})
