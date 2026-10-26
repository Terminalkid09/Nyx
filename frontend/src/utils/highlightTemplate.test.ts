import { describe, expect, it } from 'vitest'
import { escapeHtml, highlightTemplate } from './highlightTemplate'

describe('escapeHtml', () => {
  it('escapes markup and quotes', () => {
    expect(escapeHtml('<img src=x onerror="alert(1)">')).toBe(
      '&lt;img src=x onerror=&quot;alert(1)&quot;&gt;',
    )
  })

  it("escapes single quotes and ampersands", () => {
    expect(escapeHtml("a'b & c")).toBe('a&#39;b &amp; c')
  })
})

describe('highlightTemplate', () => {
  it('wraps §markers§ in a mark element', () => {
    expect(highlightTemplate('GET /?q=§1§')).toContain('<mark')
    expect(highlightTemplate('GET /?q=§1§')).toContain('§1§</mark>')
  })

  it('does not let target markup reach the DOM', () => {
    const rendered = highlightTemplate('<img src=x onerror="alert(1)">§payload§')
    expect(rendered).not.toContain('<img')
    expect(rendered).toContain('&lt;img')
    expect(rendered).toContain('<mark')
  })

  it('escapes ampersands before wrapping so markers survive', () => {
    const rendered = highlightTemplate('a=1&b=§2§')
    expect(rendered).toContain('a=1&amp;b=')
    expect(rendered).toContain('§2§</mark>')
  })
})
