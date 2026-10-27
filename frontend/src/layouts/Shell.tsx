import {
  Activity, BarChart3, Database, FileDown, FlaskConical, LayoutDashboard, ListTree, Menu, Settings, ShieldAlert,
  Upload, X,
} from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import { api } from '../api/client'
import { cx } from '../components/ui'
import { useApp } from '../lib/app-context'

const NAV = [
  { to: '/', label: 'Overview', icon: LayoutDashboard, end: true },
  { to: '/incidents', label: 'Incidents', icon: ShieldAlert },
  { to: '/events', label: 'Raw events', icon: ListTree },
  { to: '/attack', label: 'ATT&CK', icon: BarChart3 },
  { to: '/evaluation', label: 'Evaluation', icon: FlaskConical },
  { to: '/ingestion', label: 'Ingestion', icon: Upload },
  { to: '/reports', label: 'Reports', icon: FileDown },
  { to: '/settings', label: 'Settings', icon: Settings },
]

function StatusPill({ ok, label }: { ok: boolean | null; label: string }) {
  return (
    <span title={label} className="inline-flex items-center gap-1.5 rounded-md bg-white px-2 py-1 text-[11px] font-medium text-muted ring-1 ring-ink-600">
      <span className={cx('h-1.5 w-1.5 rounded-full', ok === null ? 'bg-slate-400' : ok ? 'bg-emerald-500' : 'bg-rose-500')} aria-hidden />
      {label}
    </span>
  )
}

export function Shell({ children }: { children: ReactNode }) {
  const { health, dataset, datasets, refresh, notify, toasts, dismiss } = useApp()
  const [open, setOpen] = useState(false)
  const nav = useNavigate()
  const mode = health?.llm.mode ?? 'cached'

  const links = (vertical: boolean) => NAV.map(({ to, label, icon: Icon, end }) => (
    <NavLink key={to} to={to} end={end} onClick={() => setOpen(false)}
      className={({ isActive }) => cx('flex items-center gap-2 rounded-md px-3 py-1.5 text-[13px] font-medium whitespace-nowrap',
        vertical && 'py-2.5',
        isActive ? 'bg-sky-600 text-white' : 'text-muted hover:bg-sky-50 hover:text-fg')}>
      <Icon size={15} aria-hidden />{label}
    </NavLink>
  ))

  return (
    <div className="flex h-full flex-col">
      <header className="sticky top-0 z-30 border-b border-ink-600 bg-white">
        <div className="mx-auto flex h-16 max-w-[1500px] items-center gap-4 px-4 sm:px-6">
          <button className="-ml-1 rounded-md p-2 text-muted hover:bg-sky-50 xl:hidden" onClick={() => setOpen(true)} aria-label="Open menu"><Menu size={20} /></button>
          <div className="flex shrink-0 items-center gap-2.5">
            <div className="grid h-9 w-9 place-items-center rounded-lg bg-sky-600 text-white"><Activity size={18} aria-hidden /></div>
            <div className="hidden leading-tight sm:block">
              <div className="text-sm font-bold tracking-tight text-fg">NTDCP</div>
              <div className="text-[10px] font-medium uppercase tracking-[0.14em] text-faint">Threat correlation</div>
            </div>
          </div>
          <nav aria-label="Main" className="hidden flex-1 items-center gap-0.5 overflow-x-auto xl:flex">{links(false)}</nav>
        </div>
        <div className="border-t border-ink-700 bg-ink-800">
          <div className="mx-auto flex max-w-[1500px] flex-wrap items-center gap-2 px-4 py-2 sm:px-6">
            <Database size={14} className="text-sky-600" aria-hidden />
            <label className="sr-only" htmlFor="ds-select">Active dataset</label>
            <select id="ds-select" value={dataset?.id ?? ''} onChange={async (e) => {
              try { await api.activateDataset(Number(e.target.value)); refresh(); notify('info', 'Dataset switched') } catch (err) { notify('error', (err as Error).message) }
            }} className="max-w-[16rem] truncate rounded-md border-0 bg-white px-2.5 py-1 text-xs font-medium ring-1 ring-ink-600">
              {!dataset && <option value="">No dataset loaded</option>}
              {datasets.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
            </select>
            {dataset && <span className="num text-xs text-faint">{dataset.event_count.toLocaleString()} events</span>}
            {!dataset && <button onClick={() => nav('/ingestion')} className="rounded-md bg-sky-600 px-3 py-1 text-xs font-semibold text-white">Load data</button>}
            <div className="ml-auto flex flex-wrap items-center gap-1.5">
              <StatusPill ok={health ? health.database : null} label="Database" />
              <span className="rounded-md bg-sky-100 px-2 py-1 text-[11px] font-medium text-sky-800">AI: {mode === 'off' ? 'Off' : mode === 'cached' ? 'Cached' : 'Live'}</span>
            </div>
          </div>
        </div>
      </header>

      {open && (
        <div className="fixed inset-0 z-40 xl:hidden">
          <button aria-label="Close menu" className="absolute inset-0 bg-slate-900/30" onClick={() => setOpen(false)} />
          <nav aria-label="Main" className="relative flex h-full w-72 flex-col gap-1 bg-ink-900 p-4 shadow-2xl">
            <button className="mb-2 self-end rounded-md p-1.5 text-muted hover:bg-white" onClick={() => setOpen(false)} aria-label="Close menu"><X size={18} /></button>
            {links(true)}
          </nav>
        </div>
      )}

      <main className="min-w-0 flex-1 overflow-y-auto">
        <div className="mx-auto max-w-[1500px] px-4 py-7 sm:px-6">{children}</div>
      </main>

      <div aria-live="polite" className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-80 flex-col gap-2">
        {toasts.map((t) => (
          <div key={t.id} className={cx('pointer-events-auto flex items-start gap-2 rounded-lg border px-4 py-3 text-sm shadow-lg',
            t.kind === 'success' ? 'border-emerald-200 bg-emerald-50 text-emerald-800' : t.kind === 'error' ? 'border-rose-200 bg-rose-50 text-rose-800' : 'border-sky-200 bg-white text-fg')}>
            <span className="flex-1">{t.text}</span>
            <button onClick={() => dismiss(t.id)} aria-label="Dismiss"><X size={14} /></button>
          </div>
        ))}
      </div>
    </div>
  )
}
