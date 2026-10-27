import { Database, Play } from 'lucide-react'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, ApiError } from '../api/client'
import { useApp } from '../lib/app-context'
import { Button, EmptyState, ErrorState } from './ui'

export function isNoDataset(e: Error | null): boolean {
  return e instanceof ApiError && e.status === 404 && /No dataset/i.test(e.message)
}

export function LoadDemoButton({ label = 'Load demo data' }: { label?: string }) {
  const { refresh, notify } = useApp()
  const [busy, setBusy] = useState(false)
  return (
    <Button variant="primary" disabled={busy} onClick={async () => {
      setBusy(true)
      try {
        const r = await api.loadDemo()
        notify('success', `Demo loaded: ${r.correlation.n_events.toLocaleString()} events → ${r.correlation.n_incidents} incidents`)
        refresh()
      } catch (e) {
        notify('error', (e as Error).message)
      } finally {
        setBusy(false)
      }
    }}>
      <Play size={14} aria-hidden />{busy ? 'Loading & correlating…' : label}
    </Button>
  )
}

export function DataGate({ error, onRetry }: { error: Error; onRetry: () => void }) {
  const nav = useNavigate()
  if (isNoDataset(error))
    return (
      <EmptyState title="No telemetry loaded yet" icon={<Database aria-hidden />}>
        <p className="mb-4">Load the deterministic synthetic demo (Suricata + Zeek, scenarios A–G) or upload your own EVE JSON / Zeek logs.</p>
        <div className="flex justify-center gap-2">
          <LoadDemoButton />
          <Button onClick={() => nav('/ingestion')}>Upload logs</Button>
        </div>
      </EmptyState>
    )
  return <ErrorState error={error} onRetry={onRetry} />
}
