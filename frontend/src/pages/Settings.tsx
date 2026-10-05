import { useState } from 'react';
import { Badge, State } from '../components/Common';
import { useData } from '../hooks/useData';
import { api } from '../lib/api';
import { type Row } from '../types';
import { Intelligence } from './Advanced';

function RuleEditor({ rule, onSaved }: { rule: Row; onSaved: () => void }) {
  const [config, setConfig] = useState(JSON.stringify(rule.config, null, 2));
  const [enabled, setEnabled] = useState(Boolean(rule.enabled));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  async function save() {
    try {
      setBusy(true); setError('');
      const parsed: unknown = JSON.parse(config);
      await api(`/rules/${rule.id}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled, config: parsed }) });
      onSaved();
    } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  }
  return <details className="rule"><summary>{String(rule.name)} <Badge value={rule.enabled ? 'Enabled' : 'Disabled'} /></summary>
    <p>{String(rule.description)}</p><p className="footnote">{String(rule.logic)}</p>
    <label className="check"><input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} />Enabled for future analyses</label>
    <label>Threshold configuration (JSON)<textarea className="mono" rows={8} value={config} onChange={e => setConfig(e.target.value)} /></label>
    {error && <p className="error" role="alert">{error}</p>}<button disabled={busy} onClick={() => void save()}>{busy ? 'Saving…' : 'Save rule'}</button>
  </details>;
}
export default function Settings() {
  const [refresh, setRefresh] = useState(0);
  const [message, setMessage] = useState('');
  const { data, loading, error } = useData<Row[]>('/rules', refresh);
  return <>
    <Intelligence />
    <section className="panel padded"><h2>Local analysis boundaries</h2>
      <p>128 MiB per capture · 250,000 packets · 30,000 flows · 256 KiB reconstruction per direction · 10 minutes per job.</p>
      <p className="footnote">A threshold is a rule condition, not a maliciousness score. Saved changes apply to future analyses. Existing findings retain their original rule configuration and evidence.</p>
    </section>
    {message && <p className="notice" role="status">{message}</p>}
    <State loading={loading} error={error} />
    <section className="panel"><div className="section-heading"><h2>Deterministic detection rules</h2><span>{data?.length || 0} rules</span></div>
      {data?.map(rule => <RuleEditor key={`${rule.id}/${refresh}`} rule={rule} onSaved={() => { setRefresh(n => n + 1); setMessage('Rule saved. Existing evidence has not been changed.'); }} />)}</section>
  </>;
}
