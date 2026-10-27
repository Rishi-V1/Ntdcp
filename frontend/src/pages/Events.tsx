import { AlertTriangle, Search } from 'lucide-react'
import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api } from '../api/client'
import { EventDrawer } from '../components/EventDrawer'
import { DataGate } from '../components/NoDataset'
import { Button, Card, cx, EmptyState, PageHeader, Pagination, SensorBadge, Spinner, SyntheticBanner } from '../components/ui'
import { useApp } from '../lib/app-context'
import { fmtTime, STAGE_LABELS, tzLabel } from '../lib/format'
import { useAsync, useDebounced } from '../lib/hooks'

export default function EventsPage() {
  const { version, dataset } = useApp()
  const [sp, setSp] = useSearchParams()
  const get = (k: string) => sp.get(k) ?? ''
  const [qInput, setQInput] = useState(get('q'))
  const q = useDebounced(qInput)
  const [open, setOpen] = useState<string | null>(null)
  const page = Number(get('page') || 1)
  const set = (patch: Record<string, string>) => {
    const n = new URLSearchParams(sp)
    Object.entries(patch).forEach(([k, v]) => (v ? n.set(k, v) : n.delete(k)))
    if (!('page' in patch)) n.delete('page')
    setSp(n, { replace: true })
  }
  const types = useAsync(() => api.eventTypes(), [version])
  const { data, error, loading, reload } = useAsync(() => api.events({
    q, sensor: get('sensor'), event_type: get('event_type'), ip: get('ip'), assigned: get('assigned'),
    tagged: get('tagged') || undefined, warnings: get('warnings') || undefined, incident_id: get('incident'), page, page_size: 50,
  }), [version, q, sp.toString()])

  if (error) return <><PageHeader title="Raw events" /><DataGate error={error} onRetry={reload} /></>
  const sel = 'rounded-xl border-0 bg-white shadow-sm ring-1 ring-ink-600 px-2 py-1.5 text-sm text-fg'
  return (
    <div className="space-y-4">
      <PageHeader title="Raw events" subtitle="Show me the underlying data. Every normalised record with its original payload." />
      <SyntheticBanner synthetic={!!dataset?.synthetic} />
      <Card bodyClass="p-3">
        <div className="flex flex-wrap items-end gap-3">
          <label className="relative min-w-[16rem] flex-1">
            <span className="sr-only">Search events</span>
            <Search size={14} className="absolute left-2.5 top-2.5 text-faint" aria-hidden />
            <input value={qInput} onChange={(e) => { setQInput(e.target.value); set({}) }} placeholder="Event ID, IP, signature, DNS query, host, user agent…"
              className="w-full rounded-xl border-0 bg-white shadow-sm ring-1 ring-ink-600 py-1.5 pl-8 pr-3 text-sm placeholder:text-faint" />
          </label>
          <label className="flex flex-col gap-1 text-xs text-muted">Sensor
            <select className={sel} value={get('sensor')} onChange={(e) => set({ sensor: e.target.value })}><option value="">Any</option><option value="suricata">Suricata</option><option value="zeek">Zeek</option></select></label>
          <label className="flex flex-col gap-1 text-xs text-muted">Event type
            <select className={sel} value={get('event_type')} onChange={(e) => set({ event_type: e.target.value })}>
              <option value="">Any</option>{types.data?.map((t) => <option key={t.event_type} value={t.event_type}>{t.event_type} ({t.count})</option>)}</select></label>
          <label className="flex flex-col gap-1 text-xs text-muted">IP address
            <input className={cx(sel, 'w-36')} value={get('ip')} onChange={(e) => set({ ip: e.target.value.trim() })} placeholder="10.10.0.20" /></label>
          <label className="flex flex-col gap-1 text-xs text-muted">Correlation
            <select className={sel} value={get('assigned')} onChange={(e) => set({ assigned: e.target.value })}>
              <option value="">All events</option><option value="yes">In an incident</option><option value="no">Not in any incident</option></select></label>
          <label className="flex flex-col gap-1 text-xs text-muted">Signal
            <select className={sel} value={get('tagged')} onChange={(e) => set({ tagged: e.target.value })}>
              <option value="">All</option><option value="true">Alert/detector tagged</option><option value="false">Context only</option></select></label>
          <label className="flex items-center gap-1.5 pb-1.5 text-xs text-muted"><input type="checkbox" checked={get('warnings') === 'true'} onChange={(e) => set({ warnings: e.target.checked ? 'true' : '' })} />Has parsing warnings</label>
          {get('incident') && <Button size="sm" variant="ghost" onClick={() => set({ incident: '' })}>Incident {get('incident')} ×</Button>}
        </div>
      </Card>
      <Card bodyClass="p-0">
        {loading && !data ? <Spinner /> : data && data.total === 0 ? <div className="p-6"><EmptyState title="No events match">Adjust the filters.</EmptyState></div> : data && (
          <div className={cx('overflow-x-auto', loading && 'opacity-60')}>
            <table className="w-full text-xs">
              <thead className="border-b border-ink-700 text-left text-muted"><tr>
                <th className="px-3 py-2 font-medium">Time ({tzLabel()})</th><th className="px-3 font-medium">Event ID</th><th className="px-3 font-medium">Sensor / type</th>
                <th className="px-3 font-medium">Source</th><th className="px-3 font-medium">Destination</th><th className="px-3 font-medium">Proto</th>
                <th className="px-3 font-medium">Sev</th><th className="px-3 font-medium">Detail</th><th className="px-3 font-medium">Tags</th><th className="px-3 font-medium">Incident</th>
              </tr></thead>
              <tbody className="divide-y divide-ink-700/60">
                {data.items.map((e) => (
                  <tr key={e.event_id} className="cursor-pointer hover:bg-ink-800/60" onClick={() => setOpen(e.event_id)} tabIndex={0} onKeyDown={(k) => { if (k.key === 'Enter') setOpen(e.event_id) }}>
                    <td className="num whitespace-nowrap px-3 py-1.5 text-muted">{fmtTime(e.timestamp_utc)}</td>
                    <td className="mono px-3 text-sky-700">{e.event_id}</td>
                    <td className="whitespace-nowrap px-3"><SensorBadge sensor={e.source_sensor} /> <span className="text-muted">{e.event_type}</span></td>
                    <td className="mono whitespace-nowrap px-3">{e.source_ip ?? '—'}{e.source_port !== null && `:${e.source_port}`}</td>
                    <td className="mono whitespace-nowrap px-3">{e.destination_ip ?? '—'}{e.destination_port !== null && `:${e.destination_port}`}</td>
                    <td className="px-3 text-muted">{e.transport_protocol ?? ''}{e.application_protocol ? `/${e.application_protocol}` : ''}</td>
                    <td className="num px-3">{e.sensor_severity ?? ''}</td>
                    <td className="max-w-[20rem] truncate px-3 text-muted" title={e.alert_signature ?? e.dns_query ?? ''}>
                      {e.normalization_warnings.length > 0 && <AlertTriangle size={11} className="mr-1 inline text-amber-600" aria-label="parsing warnings" />}
                      {e.alert_signature ?? e.dns_query ?? e.tls_server_name ?? e.http_host ?? e.connection_state ?? ''}
                    </td>
                    <td className="max-w-[12rem] truncate px-3 text-[11px] text-faint" title={e.detector_tags.join(', ')}>{e.detector_tags.join(', ')}</td>
                    <td className="px-3" onClick={(ev) => ev.stopPropagation()}>
                      {e.incident_ids.map((i) => <Link key={i} to={`/incidents/${i}`} className="mono text-sky-700 hover:underline">{i}</Link>)}
                      {e.incident_ids.length === 0 && <span className="text-faint">{e.detector_tags.length ? 'unassigned' : 'context'}</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {data && data.total > 0 && <div className="border-t border-ink-700 px-4 pb-3"><Pagination page={page} pageSize={50} total={data.total} onPage={(p) => set({ page: String(p) })} /></div>}
      </Card>
      <p className="text-xs text-faint">Stages: {Object.values(STAGE_LABELS).join(' · ')}. Click a row for the normalised record and the original payload.</p>
      <EventDrawer eventId={open} onClose={() => setOpen(null)} />
    </div>
  )
}
