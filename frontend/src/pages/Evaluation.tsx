import { CheckCircle2, FileDown, FlaskConical, Loader2, XCircle } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api } from '../api/client'
import type { EvaluationRun, PRF } from '../api/types'
import { DataGate } from '../components/NoDataset'
import { Button, Card, cx, EmptyState, ErrorState, HelpTip, PageHeader, SeverityBadge, Spinner, SyntheticBanner } from '../components/ui'
import { useApp } from '../lib/app-context'
import { fmtDuration, fmtInt, fmtTime, STAGE_SHORT } from '../lib/format'
import { useAsync } from '../lib/hooks'

const METHOD_LABEL: Record<string, string> = {
  A_independent_alerts: 'A · Independent alerts',
  B_rule_based_shared_ip: 'B · Shared IP + time window',
  proposed_evidence_aware: 'Proposed · Evidence-aware',
  C_tfidf_dbscan_semantic: 'C · TF-IDF + DBSCAN (semantic)',
}
const tooltipStyle = { background: '#ffffff', border: '1px solid #24344f', borderRadius: 8, fontSize: 12 }
const f = (x: number | null | undefined, d = 3) => (x === null || x === undefined ? '—' : x.toFixed(d))

function PrfCard({ title, prf, help }: { title: string; prf: PRF; help?: string }) {
  return (
    <div className="rounded-xl border border-ink-600/70 bg-ink-850 p-4">
      <div className="flex items-center gap-1 text-xs font-medium uppercase tracking-wider text-muted">{title}{help && <HelpTip text={help} />}</div>
      <div className="mt-2 grid grid-cols-3 gap-2 text-center">
        {(['precision', 'recall', 'f1'] as const).map((k) => (
          <div key={k}><div className="num text-xl font-semibold">{f(prf[k], 2)}</div><div className="text-[10px] uppercase text-faint">{k}</div></div>
        ))}
      </div>
      <div className="num mt-2 text-center text-[11px] text-faint">TP {prf.tp} · FP {prf.fp} · FN {prf.fn}</div>
      {prf.unit && <div className="mt-1 text-[11px] text-faint">{prf.unit}</div>}
    </div>
  )
}

function RunView({ run }: { run: EvaluationRun }) {
  const r = run.results!
  const methods = Object.values(r.methods)
  const sc = r.scenario_scores
  return (
    <div className="space-y-4">
      <SyntheticBanner synthetic={r.dataset.synthetic} />
      <Card title={`Run #${run.id} — ${r.dataset.name} v${r.dataset.version}`} subtitle={`${fmtTime(run.created_at)} · ${fmtDuration(run.duration_ms)} · engine ${r.engine_version} · ATT&CK ${r.attack_catalog}`}
        actions={<>
          <a className="inline-flex items-center gap-1 rounded-full bg-white px-3 py-1 text-xs shadow-sm ring-1 ring-ink-600 hover:bg-sky-50" href={api.evaluationExportUrl(run.id, 'md')}><FileDown size={12} aria-hidden />Markdown</a>
          <a className="inline-flex items-center gap-1 rounded-full bg-white px-3 py-1 text-xs shadow-sm ring-1 ring-ink-600 hover:bg-sky-50" href={api.evaluationExportUrl(run.id, 'json')}><FileDown size={12} aria-hidden />JSON</a></>}>
        <div className="grid gap-3 text-sm md:grid-cols-4">
          <div><div className="text-xs text-muted">Input events</div><div className="num text-lg font-semibold">{fmtInt(r.dataset.input_events)}</div></div>
          <div><div className="text-xs text-muted">Signal events</div><div className="num text-lg font-semibold">{fmtInt(r.dataset.signal_events)}</div></div>
          <div><div className="text-xs text-muted">Throughput</div><div className="num text-lg font-semibold">{fmtInt(Math.round(r.timings.throughput_events_per_s))} ev/s</div></div>
          <div><div className="text-xs text-muted">Ground truth</div><div className={cx('font-medium', r.ground_truth.available ? 'text-emerald-700' : 'text-amber-700')}>{r.ground_truth.available ? `labels v${r.ground_truth.version}` : 'not available'}</div></div>
        </div>
        <p className="mt-3 text-xs text-faint">{r.ground_truth.note} Timings: detectors {fmtDuration(r.timings.detectors_ms)}, correlation {fmtDuration(r.timings.correlation_ms)}, incident build {fmtDuration(r.timings.incident_build_ms)}.</p>
      </Card>

      <Card title="Correlation approaches compared" subtitle="Same dataset and detector output; only the grouping method differs. Triage items = incidents + alert-bearing events left outside any incident.">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="border-b border-ink-700 text-left text-xs text-muted"><tr>
              <th className="py-2 pr-3 font-medium">Method</th><th className="pr-3 text-right font-medium">Incidents</th><th className="pr-3 text-right font-medium">Triage items</th>
              <th className="pr-3 text-right font-medium">Reduction vs A</th><th className="pr-3 text-right font-medium">Largest incident</th>
              <th className="pr-3 text-right font-medium">Pairwise P</th><th className="pr-3 text-right font-medium">R</th><th className="pr-3 text-right font-medium">F1</th>
              <th className="pr-3 text-right font-medium">Unrelated merged <HelpTip text="Number of scenario-C 'unrelated single alert' groups that ended up inside an incident (should be 0)." /></th>
              <th className="text-right font-medium">Malicious events missed</th>
            </tr></thead>
            <tbody className="divide-y divide-ink-700/60">
              {methods.map((m) => (
                <tr key={m.method} className={cx(m.method === 'proposed_evidence_aware' && 'bg-sky-500/[0.06]')}>
                  <td className="py-2 pr-3 font-medium">{METHOD_LABEL[m.method] ?? m.method}</td>
                  <td className="num pr-3 text-right">{fmtInt(m.incidents)}</td>
                  <td className="num pr-3 text-right">{fmtInt(m.triage_items)}</td>
                  <td className="num pr-3 text-right">{m.triage_reduction_vs_independent_pct?.toFixed(2)}%</td>
                  <td className="num pr-3 text-right">{fmtInt(m.largest_incident)}</td>
                  <td className="num pr-3 text-right">{f(m.grouping?.precision)}</td>
                  <td className="num pr-3 text-right">{f(m.grouping?.recall)}</td>
                  <td className="num pr-3 text-right font-semibold">{f(m.grouping?.f1)}</td>
                  <td className={cx('num pr-3 text-right', (m.unrelated_singletons_merged ?? 0) > 0 && 'text-rose-700')}>{m.unrelated_singletons_merged ?? '—'}</td>
                  <td className="num text-right">{m.labelled_malicious_events_not_in_any_incident ?? '—'}{m.labelled_malicious_events ? <span className="text-faint"> / {fmtInt(m.labelled_malicious_events)}</span> : ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="mt-4 grid gap-4 lg:grid-cols-2">
          <div className="h-56">
            <ResponsiveContainer>
              <BarChart data={methods.map((m) => ({ name: (METHOD_LABEL[m.method] ?? m.method).split(' · ')[0], items: m.triage_items }))}>
                <CartesianGrid vertical={false} />
                <XAxis dataKey="name" /><YAxis scale="log" domain={[1, 'auto']} allowDataOverflow />
                <Tooltip contentStyle={tooltipStyle} />
                <Bar dataKey="items" name="Triage items (log scale)" fill="#0ea5e9" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="h-56">
            <ResponsiveContainer>
              <BarChart data={methods.filter((m) => m.grouping).map((m) => ({ name: (METHOD_LABEL[m.method] ?? m.method).split(' · ')[0], P: m.grouping?.precision ?? 0, R: m.grouping?.recall ?? 0, F1: m.grouping?.f1 ?? 0 }))}>
                <CartesianGrid vertical={false} />
                <XAxis dataKey="name" /><YAxis domain={[0, 1]} />
                <Tooltip contentStyle={tooltipStyle} /><Legend wrapperStyle={{ fontSize: 12 }} />
                <Bar dataKey="P" fill="#8b5cf6" /><Bar dataKey="R" fill="#14b8a6" /><Bar dataKey="F1" fill="#f59e0b" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
        <p className="mt-2 text-xs text-faint">Pairwise grouping metrics count unordered event pairs (same incident vs same labelled group). {r.semantic_experiment_note}</p>
      </Card>

      {sc ? (
        <>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <PrfCard title="Attack-chain stages" prf={sc.attack_chain_stages} />
            <PrfCard title="ATT&CK techniques" prf={sc.attack_techniques} help="Technique-level match (sub-techniques normalised to parent). A tactic match never counts as a technique match." />
            <PrfCard title="ATT&CK tactics" prf={sc.attack_tactics} />
            <div className="rounded-xl border border-ink-600/70 bg-ink-850 p-4">
              <div className="text-xs font-medium uppercase tracking-wider text-muted">Benign escalation</div>
              <div className="num mt-2 text-xl font-semibold">{sc.benign.escalated_to_high_or_critical} / {sc.benign.benign_groups_with_incident}</div>
              <div className="text-xs text-muted">benign groups escalated to High/Critical (FP rate {sc.benign.false_positive_rate ?? '—'})</div>
              <div className="mt-2 text-xs text-muted">Stage order correct: {sc.stage_order_correct.correct}/{sc.stage_order_correct.evaluated}</div>
              <div className="mt-1 text-[11px] text-faint">{sc.benign.note}</div>
            </div>
          </div>
          <Card title="Per-scenario results (proposed method)" subtitle="Each labelled group is matched to the incident with the largest event overlap.">
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead className="border-b border-ink-700 text-left text-muted"><tr>
                  <th className="py-2 pr-3 font-medium">Group</th><th className="pr-3 font-medium">Type</th><th className="pr-3 font-medium">Severity</th>
                  <th className="pr-3 font-medium">Expected stages</th><th className="pr-3 font-medium">Predicted stages</th><th className="pr-3 font-medium">Techniques (pred / exp)</th>
                  <th className="pr-3 text-right font-medium">Recall</th><th className="pr-3 text-right font-medium">Purity</th><th className="font-medium">Severity as expected</th>
                </tr></thead>
                <tbody className="divide-y divide-ink-700/60">
                  {sc.groups.map((g) => (
                    <tr key={g.group} className="align-top">
                      <td className="py-2 pr-3"><div className="mono font-semibold">{g.group}</div><div className="text-faint">{g.description}</div></td>
                      <td className="pr-3">{g.malicious ? <span className="text-rose-700">malicious</span> : <span className="text-emerald-700">benign</span>}</td>
                      <td className="pr-3">{g.incident_severity ? <SeverityBadge severity={g.incident_severity} /> : <span className="text-rose-700">not detected</span>}</td>
                      <td className="pr-3 text-muted">{g.expected_stages?.map((s) => STAGE_SHORT[s]).join(', ')}</td>
                      <td className="pr-3">{g.predicted_stages?.map((s) => STAGE_SHORT[s]).join(', ')}</td>
                      <td className="mono pr-3 text-[10px]">{g.predicted_techniques?.join(' ')}<div className="text-faint">{g.expected_techniques?.join(' ')}</div></td>
                      <td className="num pr-3 text-right">{f(g.group_recall, 3)}</td>
                      <td className="num pr-3 text-right">{f(g.incident_purity, 3)}</td>
                      <td>{g.severity_within_expectation === null || g.severity_within_expectation === undefined ? '—' : g.severity_within_expectation ? <CheckCircle2 size={14} className="text-emerald-600" aria-label="yes" /> : <XCircle size={14} className="text-rose-600" aria-label="no" />}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </>
      ) : <Card><p className="text-sm text-muted">No ground-truth labels for this dataset: precision, recall and F1 are not computed. Only the descriptive statistics above are valid.</p></Card>}

      <Card title="LLM evaluation" subtitle="Local models via Ollama on the highest-risk incidents; automated validator checks only.">
        {!r.llm.run ? <p className="text-sm text-muted">{r.llm.note}</p> : (
          <div className="space-y-3 text-sm">
            <p className="text-muted">Incidents evaluated: {r.llm.incidents_evaluated}. Deterministic fallback passes the validator for <b className="text-fg">{r.llm.fallback_valid_rate !== null && r.llm.fallback_valid_rate !== undefined ? `${(r.llm.fallback_valid_rate * 100).toFixed(0)}%` : '—'}</b> of them.</p>
            {r.llm.note && <p className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-2 text-xs text-amber-700">{r.llm.note}</p>}
            {r.llm.models && Object.keys(r.llm.models).length > 0 && (
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead className="border-b border-ink-700 text-left text-muted"><tr>
                    <th className="py-2 pr-3 font-medium">Model</th><th className="pr-3 font-medium">Status</th><th className="pr-3 text-right font-medium">Valid output</th>
                    <th className="pr-3 text-right font-medium">Mean attempts</th><th className="pr-3 text-right font-medium">Median latency</th><th className="pr-3 font-medium">Validator findings</th><th className="font-medium">Injection</th>
                  </tr></thead>
                  <tbody className="divide-y divide-ink-700/60">
                    {Object.entries(r.llm.models).map(([name, m]) => (
                      <tr key={name} className="align-top">
                        <td className="mono py-2 pr-3">{name}</td><td className="pr-3">{String(m.status)}</td>
                        <td className="num pr-3 text-right">{m.valid_structured_output_rate !== undefined ? `${((m.valid_structured_output_rate as number) * 100).toFixed(0)}%` : '—'}</td>
                        <td className="num pr-3 text-right">{String(m.mean_attempts ?? '—')}</td>
                        <td className="num pr-3 text-right">{m.latency_ms_median !== undefined ? fmtDuration(m.latency_ms_median as number) : '—'}</td>
                        <td className="pr-3 text-muted">{m.validation_error_types ? Object.entries(m.validation_error_types as Record<string, number>).map(([k, v]) => `${k} ×${v}`).join('; ') || 'none' : '—'}</td>
                        <td className="text-muted">{m.injection_incidents !== undefined ? `${m.injection_outputs_without_compliance}/${m.injection_incidents} without compliance` : '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </Card>
    </div>
  )
}

export default function EvaluationPage() {
  const { version, health, notify, dataset } = useApp()
  const runs = useAsync(() => api.evaluationRuns(), [version])
  const [selected, setSelected] = useState<number | null>(null)
  const [includeLlm, setIncludeLlm] = useState(false)
  const [starting, setStarting] = useState(false)
  const current = runs.data?.find((r) => r.id === selected) ?? runs.data?.[0]
  const detail = useAsync(() => (current && current.status === 'completed' ? api.evaluationRun(current.id) : Promise.resolve(null)), [current?.id, current?.status])
  const running = runs.data?.some((r) => r.status === 'running')
  useEffect(() => {
    if (!running) return
    const t = setInterval(runs.reload, 2000)
    return () => clearInterval(t)
  }, [running, runs.reload])

  if (runs.error) return <><PageHeader title="Evaluation laboratory" /><DataGate error={runs.error} onRetry={runs.reload} /></>
  return (
    <div className="space-y-4">
      <PageHeader title="Evaluation laboratory" subtitle="Does the platform actually work? Every number here comes from an executed run on the active dataset."
        actions={<>
          <label className="flex items-center gap-1.5 text-xs text-muted" title={health?.llm.available ? '' : 'Ollama unavailable: only the deterministic fallback will be validated'}>
            <input type="checkbox" checked={includeLlm} onChange={(e) => setIncludeLlm(e.target.checked)} />Include local LLM evaluation
          </label>
          <Button variant="primary" disabled={starting || running || !dataset} onClick={async () => {
            setStarting(true)
            try { const r = await api.startEvaluation(includeLlm); setSelected(r.id); runs.reload(); notify('info', 'Evaluation started') }
            catch (e) { notify('error', (e as Error).message) } finally { setStarting(false) }
          }}>{running ? <Loader2 size={14} className="animate-spin" aria-hidden /> : <FlaskConical size={14} aria-hidden />}{running ? 'Running…' : 'Run evaluation'}</Button>
        </>} />
      <div className="grid gap-4 xl:grid-cols-[16rem_1fr]">
        <Card title="Runs" bodyClass="p-2">
          {runs.loading && !runs.data ? <Spinner /> : runs.data?.length === 0 ? <p className="p-2 text-xs text-muted">No runs yet. Parameters used are stored with each run, so results can be reproduced.</p> : (
            <ul className="space-y-1">
              {runs.data?.map((r) => (
                <li key={r.id}>
                  <button onClick={() => setSelected(r.id)} className={cx('w-full rounded-lg px-2.5 py-2 text-left text-xs', current?.id === r.id ? 'bg-sky-500/10 ring-1 ring-sky-500/30' : 'hover:bg-ink-800')}>
                    <div className="flex justify-between"><span className="font-medium">Run #{r.id}</span>
                      <span className={r.status === 'completed' ? 'text-emerald-700' : r.status === 'failed' ? 'text-rose-700' : 'text-amber-700'}>{r.status}</span></div>
                    <div className="text-faint">{fmtTime(r.created_at)}</div>
                    {r.summary && <div className="num text-muted">{r.summary.incidents} incidents · F1 {r.summary.f1 ?? '—'}{r.summary.llm ? ' · LLM' : ''}</div>}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Card>
        <div className="min-w-0">
          {!current ? <EmptyState title="Run the first evaluation" icon={<FlaskConical aria-hidden />}>Compares independent alerts, a shared-IP rule baseline, the proposed evidence-aware correlation and a TF-IDF + DBSCAN experiment, and scores them against ground-truth labels when the dataset has them.</EmptyState>
            : current.status === 'running' ? <Spinner label="Evaluation running…" />
              : current.status === 'failed' ? <ErrorState error={current.message || 'Evaluation failed'} />
                : detail.loading ? <Spinner /> : detail.error ? <ErrorState error={detail.error} /> : detail.data?.results && <RunView run={detail.data} />}
        </div>
      </div>
    </div>
  )
}
