import { useState } from 'react';
import { Empty, State, Table } from '../components/Common';
import { useData } from '../hooks/useData';
import { api, post } from '../lib/api';
import { type Capture, type Page, type Row } from '../types';
import { inspect } from './Explore';
import { useReadOnly } from '../hooks/useReadOnly';

export function Files({ captureId }: { captureId: string }) {
  const readOnly = useReadOnly();
  const [refresh, setRefresh] = useState(0);
  const candidates = useData<Row[]>(`/captures/${captureId}/file-candidates`, refresh);
  const extracted = useData<Page>(`/captures/${captureId}/files`, refresh);
  const [ack, setAck] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [failed, setFailed] = useState(false);
  async function extract(id: string) {
    try { setBusy(true); setFailed(false); setMessage(''); await post(`/http/${id}/extract`, { acknowledge_untrusted: ack }); setRefresh(n => n + 1); setMessage('Complete HTTP body stored as untrusted evidence. Nothing was executed.'); }
    catch (e) { setFailed(true); setMessage((e as Error).message); } finally { setBusy(false); }
  }
  return <>
    <section className="panel padded"><h2>Explicit file extraction</h2><p>Only complete, unambiguous HTTP/1 response bodies can be extracted. Content stays untrusted, is not decompressed, and is never executed.</p>
      {readOnly ? <p className="footnote">Complete benign text bodies were extracted during demo setup and are available below. New extraction is disabled in this shared preview.</p> :
        <label className="check"><input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)} />I understand extracted content is untrusted evidence.</label>}
      {message && <p role={failed ? 'alert' : 'status'} className={failed ? 'error' : 'notice'}>{message}</p>}
    </section>
    <State loading={candidates.loading} error={candidates.error || extracted.error} />
    <section className="panel"><div className="section-heading"><h2>Complete HTTP bodies</h2><span>Up to 200 candidates</span></div>
      {candidates.data?.length ? <div className="table-scroll"><table><thead><tr><th>Request</th><th>Bytes</th><th>Content type</th><th>Action</th></tr></thead><tbody>
        {candidates.data.map(row => <tr key={row.id}><td><a href={`#/inspect/http/${row.id}`}>{String(row.host || 'Response only')}{String(row.uri || '')}</a></td><td>{String(row.body_size)}</td><td>{String(row.content_type || 'Not observed')}</td>
          <td>{readOnly ? <span className="muted">Read-only demo</span> : <button disabled={!ack || busy} onClick={() => void extract(row.id)}>Extract safely</button>}</td></tr>)}</tbody></table></div> :
        <Empty title="No complete extractable bodies">Encrypted, truncated, ambiguous and over-limit streams are not eligible.</Empty>}</section>
    {!!extracted.data?.items.length && <section className="panel"><div className="section-heading"><h2>Extracted evidence</h2></div>
      <Table rows={extracted.data.items} columns={['filename', 'size', 'sha256', 'mime_type']} onSelect={row => inspect(row, 'files')} />
      <div className="padded">{extracted.data.items.map(row => <div className="file-actions" key={row.id}><span>{String(row.filename)}</span>
        <a className="button" href={`/api/files/${row.id}/download`}>Download untrusted evidence</a>
        <a className="button" href={`/api/files/${row.id}/reversescope`} download={`hash-${row.id}.json`}>ReverseScope hash handoff</a></div>)}</div>
    </section>}
  </>;
}

interface Difference { count: number; values: string[]; limited: boolean }
export function Compare() {
  const { data: captures, loading, error } = useData<Capture[]>('/captures');
  const [a, setA] = useState('');
  const [b, setB] = useState('');
  const [result, setResult] = useState<{ differences: Record<string, Record<string, Difference>>; semantics: string }>();
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  return <><State loading={loading} error={error} />
    <form className="panel toolbar" onSubmit={e => { e.preventDefault(); setBusy(true); setMessage('');
      void api<typeof result>(`/comparison?${new URLSearchParams({ baseline_id: a, comparison_id: b })}`).then(setResult)
        .catch((e: Error) => setMessage(e.message)).finally(() => setBusy(false)); }}>
      {([['Baseline capture', a, setA], ['Comparison capture', b, setB]] as const).map(([label, value, set]) =>
        <label className="grow" key={label}>{label}<select value={value} onChange={e => set(e.target.value)}>
          <option value="">Choose completed capture</option>{captures?.filter(c => c.analysis_status === 'completed').map(c => <option key={c.id} value={c.id}>{c.original_filename}</option>)}</select></label>)}
      <button className="primary" disabled={!a || !b || busy}>Compare captures</button></form>
    {message && <p className="error" role="alert">{message}</p>}
    {result && <><p className="footnote">{result.semantics}</p>{Object.entries(result.differences).map(([kind, diff]) => <section className="panel" key={kind}>
      <div className="section-heading"><h2>{kind}</h2></div><div className="comparison-columns">{Object.entries(diff).map(([key, value]) => <div key={key}>
        <h3>{key} · {value.count}</h3>{value.values.length ? <ul>{value.values.map(v => <li key={v}>{v}</li>)}</ul> : <p className="muted">None observed</p>}
        {value.limited && <p className="warning">First 200 values shown.</p>}</div>)}</div></section>)}</>}
  </>;
}

interface Provider { name: string; configured: boolean; enabled: boolean; types: string[] }
export function Intelligence({ iocId }: { iocId?: string }) {
  const readOnly = useReadOnly();
  const [refresh, setRefresh] = useState(0);
  const providers = useData<{ external_enabled: boolean; providers: Provider[]; notice: string }>('/intelligence/providers');
  const results = useData<Row[]>(iocId ? `/iocs/${iocId}/intelligence` : null, refresh);
  const [provider, setProvider] = useState('rdap');
  const [consent, setConsent] = useState(false);
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  return <section className="panel padded"><h2>Optional external intelligence</h2>
    <State loading={providers.loading} error={providers.error || results.error} />
    <p>{providers.data?.notice}</p>
    {!providers.data?.external_enabled && <p className="notice">{readOnly ? 'External intelligence is unavailable in the synthetic demo. No indicator is shared and no reputation results are fabricated.' : 'External intelligence is off. No indicator is shared. Enable with PACKETSCOPE_EXTERNAL_ENABLED=true only after reviewing the security documentation.'}</p>}
    {providers.data && <p className="footnote">{providers.data.providers.map(p => `${p.name}: ${p.configured ? 'available if enabled' : 'not configured'}`).join(' · ')}</p>}
    {iocId && providers.data?.external_enabled && <form onSubmit={e => { e.preventDefault(); setBusy(true); setMessage('');
      void post(`/iocs/${iocId}/lookup`, { provider, consent_to_share_indicator: consent }).then(() => { setRefresh(n => n + 1); setMessage('Provider response recorded.'); })
        .catch((e: Error) => { setMessage(e.message); setRefresh(n => n + 1); }).finally(() => setBusy(false)); }}>
      <label>Provider<select value={provider} onChange={e => setProvider(e.target.value)}>{providers.data.providers.map(p => <option disabled={!p.configured} key={p.name}>{p.name}</option>)}</select></label>
      <label className="check"><input type="checkbox" checked={consent} onChange={e => setConsent(e.target.checked)} />Send this indicator to the selected external provider.</label>
      <button disabled={!consent || busy}>Look up indicator</button></form>}
    {message && <p role="status">{message}</p>}
    {results.data?.map(row => <details className="rule" key={row.id}><summary>{String(row.provider)} · {String(row.status)}</summary><pre>{JSON.stringify(row.result, null, 2)}</pre></details>)}
  </section>;
}
