import { FileUp, Plus, Trash2 } from 'lucide-react'
import { useRef, useState } from 'react'
import { api } from '../api/client'
import type { Job } from '../api/types'
import { LoadDemoButton } from '../components/NoDataset'
import { Button, Card, Drawer, PageHeader, Spinner, SyntheticBanner } from '../components/ui'
import { useApp } from '../lib/app-context'
import { fmtDuration, fmtInt, fmtTime } from '../lib/format'
import { useAsync } from '../lib/hooks'

function RejectedDrawer({ job, onClose }: { job: Job | null; onClose: () => void }) {
  const { data, loading } = useAsync(() => (job ? api.rejected(job.id) : Promise.resolve([])), [job?.id])
  return (
    <Drawer open={!!job} onClose={onClose} wide title={job && `Rejected records — ${job.filename}`}>
      {loading ? <Spinner /> : data && data.length === 0 ? <p className="text-sm text-muted">No rejected records.</p> : (
        <ul className="space-y-2">
          {data?.map((r) => (
            <li key={r.line_number} className="rounded-lg border border-ink-700 p-3 text-xs">
              <div className="flex gap-2"><span className="num text-faint">line {r.line_number}</span><span className="text-rose-700">{r.reason}</span></div>
              <pre className="mono mt-1 overflow-x-auto whitespace-pre-wrap break-all text-[11px] text-muted">{r.raw_excerpt}</pre>
            </li>
          ))}
        </ul>
      )}
    </Drawer>
  )
}

export default function IngestionPage() {
  const { version, refresh, notify, dataset, datasets } = useApp()
  const jobs = useAsync(() => api.jobs().catch(() => [] as Job[]), [version])
  const schema = useAsync(() => api.schema(), [])
  const [file, setFile] = useState<File | null>(null)
  const [sensor, setSensor] = useState('auto')
  const [correlate, setCorrelate] = useState(true)
  const [busy, setBusy] = useState(false)
  const [progress, setProgress] = useState('')
  const [lastResult, setLastResult] = useState<string | null>(null)
  const [rejectedFor, setRejectedFor] = useState<Job | null>(null)
  const [newName, setNewName] = useState('')
  const inputRef = useRef<HTMLInputElement>(null)
  const maxMb = schema.data?.max_upload_mb ?? 50

  const upload = async () => {
    if (!file) return
    if (file.size > maxMb * 1024 * 1024) { notify('error', `File is larger than the ${maxMb} MB limit`); return }
    setBusy(true)
    setProgress(`Uploading and parsing ${file.name} (${(file.size / 1024).toFixed(0)} KB)…`)
    try {
      const r = await api.upload(file, sensor, correlate)
      const j = r.job
      setLastResult(`${j.filename}: ${j.accepted} accepted, ${j.rejected} rejected, ${j.duplicates} duplicates, ${j.with_warnings} with warnings` +
        (r.correlation ? ` · correlation: ${r.correlation.n_incidents} incidents from ${r.correlation.n_events} events in ${fmtDuration(r.correlation.duration_ms)}` : ''))
      notify(j.accepted ? 'success' : 'error', j.accepted ? 'Import finished' : 'No records were accepted')
      if (r.decode_warning) notify('info', r.decode_warning)
      setFile(null)
      if (inputRef.current) inputRef.current.value = ''
      refresh()
    } catch (e) { notify('error', (e as Error).message) } finally { setBusy(false); setProgress('') }
  }

  return (
    <div className="space-y-4">
      <PageHeader title="Data ingestion" subtitle="Load data and begin an investigation." />
      <SyntheticBanner synthetic={!!dataset?.synthetic} />
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Demo data" subtitle="Deterministic synthetic Suricata + Zeek telemetry (~8,200 events, scenarios A–G). Replaces any previous demo dataset and runs correlation.">
          <div className="space-y-3 text-sm text-muted">
            <p>Includes a multi-stage intrusion, a failed brute force, an authorised scan, unrelated alerts, DNS tunnelling with cross-sensor corroboration, ambiguous benign activity, malformed records and a prompt-injection string in a log field.</p>
            <LoadDemoButton label="Load demo data" />
          </div>
        </Card>
        <Card title="Upload sensor logs" subtitle={`Into the active dataset (${dataset?.name ?? 'a new dataset will be created'}). Max ${maxMb} MB per file; parsed in memory, never executed.`}>
          <div className="space-y-3">
            <label className="flex cursor-pointer flex-col items-center gap-2 rounded-xl border border-dashed border-ink-500 px-4 py-6 text-center text-sm text-muted hover:border-sky-400"
              onDragOver={(e) => e.preventDefault()} onDrop={(e) => { e.preventDefault(); if (e.dataTransfer.files[0]) setFile(e.dataTransfer.files[0]) }}>
              <FileUp aria-hidden />
              <span>{file ? <b className="text-fg">{file.name} ({(file.size / 1024).toFixed(0)} KB)</b> : 'Drop a file here or click to choose'}</span>
              <span className="text-xs text-faint">Suricata eve.json · Zeek conn/dns/http/ssl/ssh/notice/files (.log JSON or TSV)</span>
              <input ref={inputRef} type="file" className="sr-only" accept=".json,.log,.txt,.tsv,.ndjson" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
            </label>
            <div className="flex flex-wrap items-end gap-3">
              <label className="flex flex-col gap-1 text-xs text-muted">Sensor
                <select value={sensor} onChange={(e) => setSensor(e.target.value)} className="rounded-xl border-0 bg-white shadow-sm ring-1 ring-ink-600 px-2 py-1.5 text-sm text-fg">
                  <option value="auto">Auto-detect</option><option value="suricata">Suricata EVE JSON</option><option value="zeek">Zeek (JSON or TSV)</option>
                </select></label>
              <label className="flex items-center gap-1.5 pb-2 text-xs text-muted"><input type="checkbox" checked={correlate} onChange={(e) => setCorrelate(e.target.checked)} />Run correlation after import</label>
              <Button variant="primary" disabled={!file || busy} onClick={upload}>{busy ? 'Importing…' : 'Import'}</Button>
            </div>
            {progress && <div role="status" className="flex items-center gap-2 text-xs text-sky-700"><span className="h-2 w-2 animate-pulse rounded-full bg-sky-400" />{progress}</div>}
            {lastResult && <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-2 text-xs text-emerald-700">{lastResult}</div>}
          </div>
        </Card>
      </div>

      <Card title="Import history" subtitle={`Jobs for ${dataset?.name ?? 'the active dataset'}. Malformed records are never dropped silently.`}>
        {jobs.loading && !jobs.data ? <Spinner /> : jobs.data && jobs.data.length === 0 ? <p className="text-sm text-muted">No imports yet.</p> : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead className="border-b border-ink-700 text-left text-muted"><tr>
                <th className="py-2 pr-3 font-medium">File</th><th className="pr-3 font-medium">Format</th><th className="pr-3 font-medium">Status</th>
                <th className="pr-3 text-right font-medium">Records</th><th className="pr-3 text-right font-medium">Accepted</th><th className="pr-3 text-right font-medium">Rejected</th>
                <th className="pr-3 text-right font-medium">Duplicates</th><th className="pr-3 text-right font-medium">Warnings</th><th className="pr-3 font-medium">Finished</th><th />
              </tr></thead>
              <tbody className="divide-y divide-ink-700/60">
                {jobs.data?.map((j) => (
                  <tr key={j.id}>
                    <td className="mono py-2 pr-3">{j.filename}</td><td className="pr-3 text-muted">{j.file_format}</td>
                    <td className="pr-3">{j.status}</td>
                    <td className="num pr-3 text-right">{fmtInt(j.total_records)}</td><td className="num pr-3 text-right text-emerald-700">{fmtInt(j.accepted)}</td>
                    <td className="num pr-3 text-right text-rose-700">{fmtInt(j.rejected)}</td><td className="num pr-3 text-right">{fmtInt(j.duplicates)}</td>
                    <td className="num pr-3 text-right text-amber-700">{fmtInt(j.with_warnings)}</td><td className="pr-3 text-muted">{fmtTime(j.finished_at)}</td>
                    <td>{j.rejected > 0 && <Button size="sm" variant="ghost" onClick={() => setRejectedFor(j)}>Why rejected?</Button>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Datasets" subtitle="Each dataset is analysed independently; the active one drives every page.">
          <ul className="divide-y divide-ink-700">
            {datasets.map((d) => (
              <li key={d.id} className="flex items-center gap-3 py-2 text-sm">
                <div className="min-w-0 flex-1"><div className="truncate">{d.name} {d.is_active && <span className="ml-1 text-xs text-sky-700">(active)</span>}</div>
                  <div className="text-xs text-faint">{fmtInt(d.event_count)} events · {d.synthetic ? 'synthetic' : 'uploaded'}{d.has_labels ? ' · has evaluation labels' : ''}</div></div>
                {!d.is_active && <Button size="sm" onClick={async () => { await api.activateDataset(d.id); refresh() }}>Activate</Button>}
                <Button size="sm" variant="ghost" title="Delete dataset" onClick={async () => {
                  if (!window.confirm(`Delete dataset “${d.name}” and all its events and incidents?`)) return
                  try { await api.deleteDataset(d.id); notify('success', 'Dataset deleted'); refresh() } catch (e) { notify('error', (e as Error).message) }
                }}><Trash2 size={14} aria-label="Delete" /></Button>
              </li>
            ))}
          </ul>
          <form className="mt-3 flex gap-2" onSubmit={async (e) => {
            e.preventDefault()
            if (!newName.trim()) return
            try { await api.createDataset(newName.trim()); setNewName(''); notify('success', 'Empty dataset created and activated – upload files into it'); refresh() }
            catch (err) { notify('error', (err as Error).message) }
          }}>
            <input value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="New dataset name (e.g. Lab capture 21 Oct)" aria-label="New dataset name"
              className="flex-1 rounded-xl border-0 bg-white shadow-sm ring-1 ring-ink-600 px-2.5 py-1.5 text-sm placeholder:text-faint" />
            <Button type="submit" disabled={!newName.trim()}><Plus size={14} aria-hidden />Create</Button>
          </form>
        </Card>
        <Card title="Supported formats & common schema" subtitle={schema.data ? `Event schema v${schema.data.schema_version}` : undefined}>
          {schema.data && (
            <div className="space-y-3 text-xs">
              {Object.entries(schema.data.supported_inputs).map(([k, v]) => <p key={k}><b className="capitalize text-fg">{k}:</b> <span className="text-muted">{v}</span></p>)}
              <details><summary className="cursor-pointer text-sky-700">Field reference ({Object.keys(schema.data.fields).length} fields)</summary>
                <dl className="mt-2 grid grid-cols-[11rem_1fr] gap-x-3 gap-y-1">
                  {Object.entries(schema.data.fields).map(([k, v]) => [<dt key={k} className="mono text-sky-700">{k}</dt>, <dd key={k + 'd'} className="text-muted">{v}</dd>])}
                </dl>
              </details>
              <p className="text-faint">Unavailable values stay empty – users, hosts and DNS names are never invented. The original record is preserved for inspection.</p>
            </div>
          )}
        </Card>
      </div>
      <RejectedDrawer job={rejectedFor} onClose={() => setRejectedFor(null)} />
    </div>
  )
}
