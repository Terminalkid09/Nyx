/**
 * Render a fuzzer request template with §markers§ highlighted.
 *
 * The template is attacker-controlled: it is the raw request captured from
 * the target, so it can contain `<img src=x onerror=...>`. The old code ran
 * the marker replace first and fed the result to dangerouslySetInnerHTML,
 * which put target HTML in the renderer's DOM. Escaping first and wrapping
 * afterwards keeps the markup inert; the only HTML that survives is the
 * <mark> element this function emits.
 */

const ESCAPES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
}

export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (ch) => ESCAPES[ch])
}

export function highlightTemplate(template: string): string {
  return escapeHtml(template).replace(
    /§([^§]+)§/g,
    (_match, inner: string) =>
      `<mark class="bg-purple-700 text-purple-200 rounded px-0.5">§${inner}§</mark>`,
  )
}
