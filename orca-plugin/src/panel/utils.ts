import type { PolicyInspectionReport } from '../types.ts'

export function escapeHtml(str: unknown): string {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

export async function copyText(text: string, btn?: HTMLElement | null): Promise<void> {
  try {
    await navigator.clipboard.writeText(text)
    if (btn) {
      const prev = btn.textContent
      btn.textContent = 'Copied'
      setTimeout(() => {
        btn.textContent = prev
      }, 1000)
    }
  } catch {}
}

export function endpointsSignature(rep: PolicyInspectionReport | null): string {
  const eps = rep?.agents?.[0]?.endpoints || []
  return eps.map(e => `${e.host}:${e.port}:${e.ruleScope || ''}:${(e.l7Rules || []).length}`).join('|')
}

export function sandboxesSignature(rep: PolicyInspectionReport | null): string {
  const sbs = rep?.activeSandboxes || []
  return sbs.map(s => `${s.name}:${s.phase || ''}`).join('|')
}

export function setupSignature(rep: PolicyInspectionReport | null): string {
  if (!rep) return ''
  const imgs = (rep.sandboxImages?.images || [])
    .map(i => `${i.name}:${i.present ? '1' : '0'}:${i.size || ''}`)
    .join('|')
  const wraps = (rep.setup?.wrappers || []).map(w => (w.present ? '1' : '0')).join('')
  const pols = (rep.setup?.policies || []).map(p => (p.present ? '1' : '0')).join('')
  return `${rep.sandboxImages?.dockerAvailable ? '1' : '0'}:${imgs}:${wraps}:${pols}`
}
