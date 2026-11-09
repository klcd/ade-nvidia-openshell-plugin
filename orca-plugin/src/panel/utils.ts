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
