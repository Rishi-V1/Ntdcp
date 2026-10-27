import { ExternalLink } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import type { MatrixTechnique } from '../api/types'
import { DataGate } from '../components/NoDataset'
import { Card, cx, Drawer, EvidenceBadge, PageHeader, Spinner, SyntheticBanner } from '../components/ui'
import { useApp } from '../lib/app-context'
import { useAsync } from '../lib/hooks'

export default function AttackPage() {
  const { version, dataset } = useApp()
  const { data, error, loading, reload } = useAsync(() => api.matrix(), [version])
  const [showEmpty, setShowEmpty] = useState(false)
  const [sel, setSel] = useState<{ tactic: string; t: MatrixTechnique } | null>(null)
  if (loading && !data) return <Spinner />
  if (error) return <><PageHeader title="MITRE ATT&CK explorer" /><DataGate error={error} onRetry={reload} /></>
  if (!data) return null
  const tactics = showEmpty ? data.tactics : data.tactics.filter((t) => t.count > 0)
  const max = Math.max(1, ...data.tactics.flatMap((t) => t.techniques.map((x) => x.count)))
  return (
    <div className="space-y-4">
      <PageHeader title="MITRE ATT&CK explorer" subtitle="Technique coverage across incidents in the active dataset." />
      <SyntheticBanner synthetic={!!dataset?.synthetic} />
      <div className="flex flex-wrap items-center gap-3 rounded-lg border border-ink-700 bg-ink-850 px-3 py-2 text-xs text-muted">
        <span>Catalog <b className="mono text-fg">{data.version}</b></span>
        <span className="text-amber-700">{data.coverage_note}</span>
        <label className="ml-auto flex items-center gap-1.5"><input type="checkbox" checked={showEmpty} onChange={(e) => setShowEmpty(e.target.checked)} />Show tactics without mappings</label>
        <span className="flex items-center gap-2">Legend: <EvidenceBadge status="OBSERVED" small /> <EvidenceBadge status="INFERRED" small /></span>
      </div>
      {tactics.length === 0 ? <Card><p className="text-sm text-muted">No incidents have ATT&CK mappings yet.</p></Card> : (
        <div className="overflow-x-auto pb-2">
          <div className="grid min-w-max auto-cols-[13rem] grid-flow-col gap-3">
            {tactics.map((ta) => (
              <section key={ta.id} aria-label={ta.name} className="flex flex-col gap-2">
                <header className="rounded-xl border-0 bg-white shadow-sm ring-1 ring-ink-600 px-3 py-2">
                  <div className="text-sm font-semibold">{ta.name}</div>
                  <div className="mono text-[11px] text-faint">{ta.id} · {ta.count} mapping{ta.count === 1 ? '' : 's'}</div>
                </header>
                {ta.techniques.filter((t) => showEmpty || t.count > 0).map((t) => {
                  const onlyInferred = t.count > 0 && t.observed === 0
                  return (
                    <button key={t.id} onClick={() => t.count && setSel({ tactic: ta.name, t })} disabled={!t.count}
                      className={cx('rounded-lg border px-3 py-2 text-left transition-colors', t.count ? 'hover:border-sky-400' : 'cursor-default opacity-40',
                        onlyInferred ? 'inferred-outline border-inferred/60' : t.count ? 'border-observed/40' : 'border-ink-700')}
                      style={{ background: t.count ? `rgba(${onlyInferred ? '245,158,11' : '56,189,248'},${0.06 + 0.22 * (t.count / max)})` : undefined }}>
                      <div className="mono text-[11px] text-sky-700">{t.id}</div>
                      <div className="text-xs leading-snug">{t.name}</div>
                      {t.count > 0 && (
                        <div className="mt-1.5 flex flex-wrap items-center gap-x-2 text-[10px] text-muted">
                          <span className="num font-semibold text-fg">{t.count} incident{t.count === 1 ? '' : 's'}</span>
                          {t.observed > 0 && <span>{t.observed} observed</span>}
                          {t.inferred > 0 && <span className="italic text-amber-700">{t.inferred} inferred</span>}
                          <span>max conf {t.max_confidence?.toFixed(2)}</span>
                        </div>
                      )}
                    </button>
                  )
                })}
              </section>
            ))}
          </div>
        </div>
      )}
      <Drawer open={!!sel} onClose={() => setSel(null)} title={sel && <span><span className="mono text-sky-700">{sel.t.id}</span> {sel.t.name}</span>}>
        {sel && (
          <div className="space-y-4 text-sm">
            <p className="text-muted">Tactic: {sel.tactic}. Mapping methods: {sel.t.methods.join(', ')}. {sel.t.evidence_events} evidence references.</p>
            <div className="flex gap-2"><EvidenceBadge status="OBSERVED" /> ×{sel.t.observed} <EvidenceBadge status="INFERRED" /> ×{sel.t.inferred}</div>
            <a className="inline-flex items-center gap-1 text-sky-700 hover:underline" href={sel.t.url} target="_blank" rel="noreferrer noopener">ATT&CK reference <ExternalLink size={12} aria-hidden /></a>
            <div>
              <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted">Associated incidents</h3>
              <ul className="space-y-1">{sel.t.incidents.map((i) => <li key={i}><Link className="mono text-sky-700 hover:underline" to={`/incidents/${i}`}>{i}</Link></li>)}</ul>
            </div>
            <Link to={`/incidents?technique=${encodeURIComponent(sel.t.id)}`} className="inline-block rounded-lg bg-sky-600 px-3 py-1.5 text-xs font-semibold text-white">Open in incident list</Link>
          </div>
        )}
      </Drawer>
    </div>
  )
}
