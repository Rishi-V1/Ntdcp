import { AlertTriangle, CircleHelp, Eye, Info, Loader2, Telescope, X } from 'lucide-react'
import { useEffect, type ReactNode } from 'react'
import type { EvidenceStatus, IncidentStatus, Severity } from '../api/types'
import { STATUS_LABELS } from '../lib/format'

export function cx(...c: (string | false | null | undefined)[]) {
  return c.filter(Boolean).join(' ')
}

export function Card({ title, subtitle, actions, children, className, bodyClass, id }: {
  title?: ReactNode; subtitle?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; bodyClass?: string; id?: string
}) {
  return (
    <section id={id} className={cx('min-w-0 rounded-lg bg-white shadow-sm ring-1 ring-ink-600', className)}>
      {(title || actions) && (
        <header className="flex items-start justify-between gap-3 px-5 pt-4 pb-1">
          <div className="min-w-0">
            {title && <h2 className="text-[14px] font-semibold text-fg">{title}</h2>}
            {subtitle && <p className="mt-0.5 text-xs text-muted">{subtitle}</p>}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={cx('p-5', (title || actions) ? 'pt-3' : null, bodyClass)}>{children}</div>
    </section>
  )
}

export function Stat({ label, value, hint, tone, icon, accent = 'sky' }: { label: string; value: ReactNode; hint?: ReactNode; tone?: string; icon?: ReactNode; accent?: 'sky' | 'blue' | 'rose' | 'violet' | 'teal' | 'amber' }) {
  const ac = { sky: 'bg-sky-100 text-sky-700', blue: 'bg-blue-100 text-blue-700', rose: 'bg-rose-100 text-rose-700',
    violet: 'bg-violet-100 text-violet-700', teal: 'bg-teal-100 text-teal-700', amber: 'bg-amber-100 text-amber-700' }[accent]
  return (
    <div className="flex min-w-0 items-start gap-3 rounded-lg bg-white px-4 py-4 shadow-sm ring-1 ring-ink-600">
      {icon && <div className={cx('grid h-10 w-10 shrink-0 place-items-center rounded-md', ac)}>{icon}</div>}
      <div className="min-w-0">
        <div className="text-[11px] font-semibold uppercase tracking-wider text-faint">{label}</div>
        <div className={cx('num mt-0.5 text-2xl font-bold tracking-tight', tone ?? 'text-fg')}>{value}</div>
        {hint && <div className="mt-0.5 text-xs text-muted">{hint}</div>}
      </div>
    </div>
  )
}

const SEV_CLASS: Record<string, string> = {
  Critical: 'bg-sev-critical/15 text-rose-700 ring-sev-critical/40',
  High: 'bg-sev-high/15 text-orange-700 ring-sev-high/40',
  Medium: 'bg-sev-medium/10 text-yellow-800 ring-sev-medium/30',
  Low: 'bg-sev-low/10 text-emerald-700 ring-sev-low/30',
  Informational: 'bg-slate-500/10 text-slate-700 ring-slate-500/30',
}
export const SEV_COLOR: Record<string, string> = {
  Critical: '#e11d48', High: '#ea580c', Medium: '#ca8a04', Low: '#059669', Informational: '#64748b',
}

export function SeverityBadge({ severity, compact }: { severity: Severity | string; compact?: boolean }) {
  return (
    <span className={cx('inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-semibold ring-1 ring-inset whitespace-nowrap', SEV_CLASS[severity] ?? SEV_CLASS.Informational)}>
      {compact ? severity.slice(0, 4) : severity}
    </span>
  )
}

const STATUS_CLASS: Record<string, string> = {
  new: 'bg-sky-500/10 text-sky-700 ring-sky-500/30',
  in_progress: 'bg-violet-500/10 text-violet-700 ring-violet-500/30',
  escalated: 'bg-rose-500/10 text-rose-700 ring-rose-500/30',
  resolved: 'bg-emerald-500/10 text-emerald-700 ring-emerald-500/30',
  closed: 'bg-slate-500/10 text-slate-700 ring-slate-500/30',
}

export function StatusBadge({ status }: { status: IncidentStatus | string }) {
  return <span className={cx('inline-flex rounded-md px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset whitespace-nowrap', STATUS_CLASS[status] ?? STATUS_CLASS.closed)}>{STATUS_LABELS[status] ?? status}</span>
}

/** Observed = solid with eye icon; Inferred = dashed outline with telescope icon; never colour alone. */
export function EvidenceBadge({ status, small }: { status: EvidenceStatus | string; small?: boolean }) {
  if (status === 'OBSERVED')
    return (
      <span title="Observed: directly present in the telemetry" className={cx('inline-flex items-center gap-1 rounded-md border border-observed/60 bg-observed/15 font-semibold text-sky-700 whitespace-nowrap', small ? 'px-1.5 py-0 text-[10px]' : 'px-2 py-0.5 text-[11px]')}>
        <Eye size={small ? 10 : 12} aria-hidden />Observed
      </span>
    )
  if (status === 'INFERRED')
    return (
      <span title="Inferred: a hypothesis from indirect indicators" className={cx('inferred-outline inline-flex items-center gap-1 rounded-md border border-inferred/70 bg-transparent font-semibold text-amber-700 italic whitespace-nowrap', small ? 'px-1.5 py-0 text-[10px]' : 'px-2 py-0.5 text-[11px]')}>
        <Telescope size={small ? 10 : 12} aria-hidden />Inferred
      </span>
    )
  return (
    <span title="No supporting evidence in the telemetry" className={cx('inline-flex items-center gap-1 rounded-md border border-ink-600 text-faint whitespace-nowrap', small ? 'px-1.5 py-0 text-[10px]' : 'px-2 py-0.5 text-[11px]')}>
      Not observed
    </span>
  )
}

export function SensorBadge({ sensor }: { sensor: string }) {
  const c = sensor === 'suricata' ? 'text-suricata ring-suricata/40 bg-suricata/10' : sensor === 'zeek' ? 'text-zeek ring-zeek/40 bg-zeek/10' : 'text-muted ring-ink-500'
  return <span className={cx('inline-flex rounded px-1.5 py-0 text-[10px] font-semibold uppercase tracking-wide ring-1 ring-inset', c)}>{sensor}</span>
}

export function Chip({ children, title, className }: { children: ReactNode; title?: string; className?: string }) {
  return <span title={title} className={cx('inline-flex items-center rounded border border-ink-600 bg-ink-800 px-1.5 py-0.5 text-[11px] text-muted whitespace-nowrap', className)}>{children}</span>
}

export function Button({ children, onClick, variant = 'secondary', disabled, type = 'button', title, size = 'md', className }: {
  children: ReactNode; onClick?: () => void; variant?: 'primary' | 'secondary' | 'ghost' | 'danger'; disabled?: boolean
  type?: 'button' | 'submit'; title?: string; size?: 'sm' | 'md'; className?: string
}) {
  const v = {
    primary: 'bg-gradient-to-r from-sky-500 to-blue-600 text-white font-semibold shadow-md shadow-sky-600/25 hover:from-sky-600 hover:to-blue-700',
    secondary: 'bg-white text-fg ring-1 ring-ink-600 shadow-sm hover:bg-sky-50 hover:ring-sky-300',
    ghost: 'text-muted hover:text-fg hover:bg-sky-50',
    danger: 'bg-rose-50 text-rose-700 ring-1 ring-rose-200 hover:bg-rose-100',
  }[variant]
  return (
    <button type={type} title={title} disabled={disabled} onClick={onClick}
      className={cx('inline-flex items-center justify-center gap-1.5 rounded-full transition-all disabled:cursor-not-allowed disabled:opacity-50',
        size === 'sm' ? 'px-3 py-1 text-xs' : 'px-4 py-2 text-sm', v, className)}>
      {children}
    </button>
  )
}

export function Spinner({ label = 'Loading…' }: { label?: string }) {
  return (
    <div role="status" className="flex items-center justify-center gap-2 py-10 text-sm text-muted">
      <Loader2 className="animate-spin" size={16} aria-hidden />{label}
    </div>
  )
}

export function ErrorState({ error, onRetry }: { error: Error | string; onRetry?: () => void }) {
  return (
    <div role="alert" className="flex flex-col items-center gap-3 rounded-xl border border-rose-500/30 bg-rose-500/5 px-6 py-8 text-center">
      <AlertTriangle className="text-rose-600" aria-hidden />
      <p className="text-sm text-rose-700">{typeof error === 'string' ? error : error.message}</p>
      {onRetry && <Button size="sm" onClick={onRetry}>Retry</Button>}
    </div>
  )
}

export function EmptyState({ title, children, icon }: { title: string; children?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-2 rounded-2xl border border-dashed border-sky-200 bg-white/70 px-6 py-12 text-center">
      <div className="text-faint">{icon ?? <Info aria-hidden />}</div>
      <p className="text-sm font-medium text-fg">{title}</p>
      {children && <div className="max-w-md text-xs text-muted">{children}</div>}
    </div>
  )
}

export function HelpTip({ text }: { text: string }) {
  return (
    <span className="group relative inline-flex align-middle">
      <CircleHelp size={13} className="cursor-help text-faint group-hover:text-muted" aria-label={text} tabIndex={0} />
      <span role="tooltip" className="pointer-events-none absolute left-1/2 top-5 z-50 hidden w-64 -translate-x-1/2 rounded-lg border border-ink-600 bg-ink-950 px-3 py-2 text-xs font-normal normal-case tracking-normal text-fg shadow-xl group-hover:block group-focus-within:block">
        {text}
      </span>
    </span>
  )
}

export function Pagination({ page, pageSize, total, onPage }: { page: number; pageSize: number; total: number; onPage: (p: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / pageSize))
  return (
    <div className="flex items-center justify-between gap-3 pt-3 text-xs text-muted">
      <span className="num">{total === 0 ? '0 results' : `${(page - 1) * pageSize + 1}–${Math.min(total, page * pageSize)} of ${total.toLocaleString()}`}</span>
      <div className="flex items-center gap-1">
        <Button size="sm" variant="ghost" disabled={page <= 1} onClick={() => onPage(page - 1)}>Previous</Button>
        <span className="num px-2">Page {page} / {pages}</span>
        <Button size="sm" variant="ghost" disabled={page >= pages} onClick={() => onPage(page + 1)}>Next</Button>
      </div>
    </div>
  )
}

export function Drawer({ open, onClose, title, children, wide }: { open: boolean; onClose: () => void; title: ReactNode; children: ReactNode; wide?: boolean }) {
  useEffect(() => {
    if (!open) return
    const h = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [open, onClose])
  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 flex justify-end" role="dialog" aria-modal="true">
      <button aria-label="Close" className="absolute inset-0 bg-black/50" onClick={onClose} />
      <div className={cx('relative flex h-full w-full flex-col border-l border-ink-600 bg-ink-900 shadow-2xl', wide ? 'max-w-3xl' : 'max-w-xl')}>
        <div className="flex items-center justify-between border-b border-ink-700 px-5 py-3">
          <div className="min-w-0 text-sm font-semibold">{title}</div>
          <Button variant="ghost" size="sm" onClick={onClose}><X size={16} aria-hidden /><span className="sr-only">Close</span></Button>
        </div>
        <div className="flex-1 overflow-y-auto p-5">{children}</div>
      </div>
    </div>
  )
}

export function JsonBlock({ value }: { value: unknown }) {
  let text: string
  if (typeof value === 'string') {
    try { text = JSON.stringify(JSON.parse(value), null, 2) } catch { text = value }
  } else text = JSON.stringify(value, null, 2)
  // rendered as text content: untrusted log values are never interpreted as HTML
  return <pre className="mono max-h-[60vh] overflow-auto whitespace-pre-wrap break-all rounded-lg border border-ink-700 bg-ink-950 p-3 text-[11px] leading-relaxed text-slate-700">{text}</pre>
}

export function ScoreBar({ value, max = 100, color = '#0ea5e9', label }: { value: number; max?: number; color?: string; label?: string }) {
  const pct = Math.max(0, Math.min(100, (value / max) * 100))
  return (
    <div className="flex items-center gap-2" aria-label={label}>
      <div className="h-1.5 w-full min-w-10 overflow-hidden rounded-full bg-sky-100">
        <div className="h-full rounded-full" style={{ width: `${pct}%`, background: color }} />
      </div>
    </div>
  )
}

export function Select({ value, onChange, options, label, className }: {
  value: string; onChange: (v: string) => void; options: { value: string; label: string }[]; label: string; className?: string
}) {
  return (
    <label className={cx('flex flex-col gap-1 text-xs text-muted', className)}>
      <span>{label}</span>
      <select value={value} onChange={(e) => onChange(e.target.value)}
        className="rounded-xl border-0 bg-white px-3 py-2 text-sm text-fg shadow-sm ring-1 ring-ink-600 focus:ring-sky-400">
        {options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
    </label>
  )
}

export function TextInput({ value, onChange, label, placeholder, type = 'text', className, ariaLabel }: {
  value: string | number; onChange: (v: string) => void; label?: string; placeholder?: string; type?: string; className?: string; ariaLabel?: string
}) {
  return (
    <label className={cx('flex flex-col gap-1 text-xs text-muted', className)}>
      {label && <span>{label}</span>}
      <input type={type} value={value} placeholder={placeholder} aria-label={ariaLabel ?? label} onChange={(e) => onChange(e.target.value)}
        className="rounded-xl border-0 bg-white px-3 py-2 text-sm text-fg shadow-sm ring-1 ring-ink-600 placeholder:text-faint" />
    </label>
  )
}

export function SyntheticBanner({ synthetic }: { synthetic: boolean }) {
  if (!synthetic) return null
  return (
    <div className="flex items-center gap-2 rounded-2xl bg-amber-50 px-4 py-2.5 text-xs font-medium text-amber-800 ring-1 ring-amber-200">
      <AlertTriangle size={14} aria-hidden />
      Synthetic demo data. Results show how the pipeline behaves on designed scenarios — not real-world detection performance.
    </div>
  )
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-fg">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-muted">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}
