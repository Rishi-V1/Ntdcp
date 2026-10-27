import { Activity, AlertOctagon, ArrowRight, Inbox, Layers, RefreshCw, Radar, ShieldAlert } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Bar, BarChart, CartesianGrid, ComposedChart, Legend, Line, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import { api } from '../api/client'
import { DataGate } from '../components/NoDataset'
import {
  Button, Card, HelpTip, PageHeader, SEV_COLOR, SeverityBadge, Spinner, Stat, StatusBadge,
} from '../components/ui'
import { useApp } from '../lib/app-context'
import { fmtDuration, fmtHour, fmtInt, fmtPct, fmtScore, fmtTime, STAGE_LABELS, STATUS_LABELS, tzLabel } from '../lib/format'
import { useAsync } from '../lib/hooks'

const tooltipStyle = { background: '#ffffff', border: '1px solid #24344f', borderRadius: 8, fontSize: 12 }

export default function OverviewPage() {
  const { version, refresh, notify } = useApp()
  const { data, error, loading, reload } = useAsync(() => api.overview(), [version])
  const [running, setRunning] = useState(false)

  if (loading && !data) return <Spinner />
  if (error) return <DataGate error={error} onRetry={reload} />
  if (!data) return null
  const t = data.totals
  const maxHeat = Math.max(1, ...data.heatmap.cells.map((c) => c.count))

  return (
    <div className="space-y-5">
      <PageHeader title="Overview" subtitle="What is happening right now?"
        actions={<Button disabled={running} onClick={async () => {
          setRunning(true)
          try { const r = await api.runCorrelation(); notify('success', `Correlation finished: ${r.n_incidents} incidents in ${fmtDuration(r.duration_ms)}`); refresh() }
          catch (e) { notify('error', (e as Error).message) } finally { setRunning(false) }
        }}><RefreshCw size={14} className={running ? 'animate-spin' : ''} aria-hidden />Re-run correlation</Button>} />

      <section aria-label="Main result" className="grid gap-5 rounded-lg bg-white p-5 shadow-sm ring-1 ring-ink-600 lg:grid-cols-[1.4fr_1fr]">
        <div>
          <div className="text-xs font-medium text-faint">Computed from the active dataset</div>
          <div className="mt-2 flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <span className="num text-3xl font-semibold text-fg">{fmtInt(t.raw_events)}</span><span className="text-base text-muted">raw events</span>
            <ArrowRight size={18} className="self-center text-faint" aria-hidden />
            <span className="num text-3xl font-semibold text-fg">{fmtInt(t.incidents)}</span><span className="text-base text-muted">incidents</span>
          </div>
          <p className="mt-3 max-w-2xl text-sm text-muted">
            {fmtInt(t.signal_events)} of the raw events carry an alert or detector tag. {fmtInt(t.events_in_incidents)} of them
            were grouped; {fmtInt(t.unassigned_signal_events)} alert-bearing events remain as individual items, so an analyst
            reviews <b className="text-fg">{fmtInt(t.triage_items)}</b> items instead of {fmtInt(t.signal_events)}.
          </p>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div className="rounded-md bg-ink-800 p-4">
            <div className="flex items-center gap-1 text-xs text-muted">Event→incident reduction <HelpTip text={data.definitions.reduction_pct} /></div>
            <div className="num mt-1 text-2xl font-semibold text-fg">{fmtPct(t.reduction_pct, 2)}</div>
          </div>
          <div className="rounded-md bg-ink-800 p-4">
            <div className="flex items-center gap-1 text-xs text-muted">Triage reduction <HelpTip text={data.definitions.triage_reduction_pct} /></div>
            <div className="num mt-1 text-2xl font-semibold text-fg">{fmtPct(t.triage_reduction_pct, 2)}</div>
          </div>
          <div className="col-span-2 text-xs text-faint">
            Latest ingestion {fmtTime(data.latest_ingestion)} {tzLabel()}
            {data.correlation_run && <> · correlation run #{data.correlation_run.id} took {fmtDuration(data.correlation_run.duration_ms)}</>}
          </div>
        </div>
      </section>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Stat label="Raw events" value={fmtInt(t.raw_events)} hint="normalised records" icon={<Layers size={18} />} accent="blue" />
        <Stat label="Incidents" value={fmtInt(t.incidents)} hint="correlated meta-alerts" tone="text-sky-700" icon={<ShieldAlert size={18} />} />
        <Stat label="Critical + High" value={fmtInt(t.critical_high)} hint="risk ≥ high threshold" tone={t.critical_high ? 'text-rose-700' : undefined} icon={<AlertOctagon size={18} />} accent="rose" />
        <Stat label="Open incidents" value={fmtInt(t.open_incidents)} hint="not resolved/closed" icon={<Inbox size={18} />} accent="violet" />
        <Stat label="Unassigned" value={fmtInt(t.unassigned_events)} hint={<span className="inline-flex items-center gap-1">{fmtInt(t.unassigned_signal_events)} with alerts <HelpTip text={data.definitions.unassigned_events} /></span>} icon={<Radar size={18} />} accent="amber" />
        <Stat label="Signal events" value={fmtInt(t.signal_events)} hint="alert / detector tagged" icon={<Activity size={18} />} accent="teal" />
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2" title="Activity over time" subtitle={`When did activity happen? Raw events per hour by sensor, with incident start times (${tzLabel()}).`}>
          <div className="h-64">
            <ResponsiveContainer>
              <ComposedChart data={data.timeline} margin={{ left: -10, right: 8, top: 4 }}>
                <CartesianGrid vertical={false} />
                <XAxis dataKey="hour" tickFormatter={fmtHour} minTickGap={24} />
                <YAxis yAxisId="ev" />
                <YAxis yAxisId="inc" orientation="right" allowDecimals={false} width={28} />
                <Tooltip contentStyle={tooltipStyle} labelFormatter={(v) => fmtTime(String(v))} />
                <Legend wrapperStyle={{ fontSize: 12 }} />
                <Bar yAxisId="ev" dataKey="suricata" name="Suricata" stackId="s" fill="#8b5cf6" />
                <Bar yAxisId="ev" dataKey="zeek" name="Zeek" stackId="s" fill="#14b8a6" radius={[3, 3, 0, 0]} />
                <Line yAxisId="inc" type="linear" dataKey="incidents_started" name="Incidents started" stroke="#f59e0b" strokeWidth={2} dot={{ r: 3 }} />
              </ComposedChart>
            </ResponsiveContainer>
          </div>
        </Card>
        <Card title="Severity distribution" subtitle="How severe are the incidents?">
          <div className="h-64">
            <ResponsiveContainer>
              <BarChart data={data.severity_distribution} layout="vertical" margin={{ left: 20 }}>
                <CartesianGrid horizontal={false} />
                <XAxis type="number" allowDecimals={false} />
                <YAxis type="category" dataKey="severity" width={90} />
                <Tooltip contentStyle={tooltipStyle} cursor={{ fill: 'rgba(2,132,199,0.06)' }} />
                <Bar dataKey="count" name="Incidents" radius={[0, 4, 4, 0]}
                  shape={(p: unknown) => {
                    const { x, y, width, height, payload } = p as { x: number; y: number; width: number; height: number; payload: { severity: string } }
                    return <rect x={x} y={y} width={width} height={height} rx={4} fill={SEV_COLOR[payload.severity]} />
                  }} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card title="Attack-stage distribution" subtitle="How far did activity progress? Incidents per stage, observed vs inferred.">
          <div className="h-60">
            <ResponsiveContainer>
              <BarChart data={data.stage_distribution.map((s) => ({ ...s, label: STAGE_LABELS[s.stage] }))} layout="vertical" margin={{ left: 30 }}>
                <CartesianGrid horizontal={false} />
                <XAxis type="number" allowDecimals={false} />
                <YAxis type="category" dataKey="label" width={120} />
                <Tooltip contentStyle={tooltipStyle} cursor={{ fill: 'rgba(2,132,199,0.06)' }} />
                <Legend wrapperStyle={{ fontSize: 12 }} />
                <Bar dataKey="OBSERVED" name="Observed" stackId="a" fill="#0ea5e9" />
                <Bar dataKey="INFERRED" name="Inferred (hypothesis)" stackId="a" fill="#f59e0b" fillOpacity={0.35} stroke="#f59e0b" strokeDasharray="4 2" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
        <Card title="Analyst workload" subtitle="Incident status distribution">
          <ul className="space-y-2.5">
            {data.status_distribution.map((s) => (
              <li key={s.status} className="flex items-center gap-3">
                <div className="w-24"><StatusBadge status={s.status} /></div>
                <div className="h-2 flex-1 overflow-hidden rounded-full bg-ink-700">
                  <div className="h-full rounded-full bg-violet-400" style={{ width: `${t.incidents ? (s.count / t.incidents) * 100 : 0}%` }} />
                </div>
                <span className="num w-8 text-right text-sm">{s.count}</span>
              </li>
            ))}
          </ul>
          <p className="mt-4 text-xs text-faint">{STATUS_LABELS.new} incidents have not been touched by an analyst yet.</p>
        </Card>
        <Card title="Sensor sources" subtitle="Which sensors contributed events?">
          <ul className="space-y-3">
            {data.sensor_distribution.map((s) => (
              <li key={s.sensor}>
                <div className="flex justify-between text-sm"><span className="capitalize">{s.sensor}</span><span className="num text-muted">{fmtInt(s.count)}</span></div>
                <div className="mt-1 h-2 overflow-hidden rounded-full bg-ink-700">
                  <div className="h-full rounded-full" style={{ width: `${(s.count / Math.max(1, t.raw_events)) * 100}%`, background: s.sensor === 'suricata' ? '#8b5cf6' : '#14b8a6' }} />
                </div>
              </li>
            ))}
          </ul>
          <p className="mt-4 text-xs text-faint">Zeek logs every connection (context); Suricata logs signature alerts and protocol events.</p>
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.3fr_1fr]">
        <Card title="Tactic × host matrix" subtitle="Which internal hosts are involved in which ATT&CK tactics? (count of incident mappings)">
          {data.heatmap.hosts.length === 0 ? <p className="text-sm text-muted">No ATT&CK mappings yet.</p> : (
            <div className="overflow-x-auto">
              <table className="w-full border-separate border-spacing-1 text-xs">
                <thead>
                  <tr><th className="text-left font-medium text-muted">Host</th>{data.heatmap.tactics.map((ta) => <th key={ta} className="px-1 text-center font-medium text-muted">{ta}</th>)}</tr>
                </thead>
                <tbody>
                  {data.heatmap.hosts.map((h) => (
                    <tr key={h}>
                      <td className="mono whitespace-nowrap pr-2 text-muted">{h}</td>
                      {data.heatmap.tactics.map((ta) => {
                        const c = data.heatmap.cells.find((x) => x.host === h && x.tactic === ta)?.count ?? 0
                        return <td key={ta} title={`${h} · ${ta}: ${c}`} className="num h-7 rounded text-center"
                          style={{ background: c ? `rgba(14,165,233,${0.12 + 0.6 * (c / maxHeat)})` : 'rgba(205,220,238,0.45)' }}>{c || ''}</td>
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
        <Card title="Highest-risk incidents" subtitle="Start here" actions={<Link to="/incidents" className="text-xs text-sky-700 hover:underline">All incidents</Link>}>
          <ul className="divide-y divide-ink-700">
            {data.top_incidents.map((i) => (
              <li key={i.id}>
                <Link to={`/incidents/${i.id}`} className="flex items-center gap-3 py-2.5 hover:bg-ink-800/50">
                  <SeverityBadge severity={i.severity} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm">{i.title}</div>
                    <div className="mono text-[11px] text-faint">{i.id} · {i.event_count} events · confidence {fmtScore(i.confidence)}</div>
                  </div>
                  <span className="num text-sm font-semibold">{i.risk_score.toFixed(0)}</span>
                </Link>
              </li>
            ))}
          </ul>
        </Card>
      </div>
    </div>
  )
}
