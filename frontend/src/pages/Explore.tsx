import { useEffect, useState } from 'react';
import { Badge, Empty, FieldTree, format, State, Table } from '../components/Common';
import { useData } from '../hooks/useData';
import { api, bytes, date, post } from '../lib/api';
import { type Capture, type Dashboard, type Page, type Row } from '../types';
import { AttachToCase } from './Cases';
import { Intelligence } from './Advanced';

export const columns: Record<string, string[]> = {
  packets: ['frame_number', 'timestamp', 'source_ip', 'destination_ip', 'protocol', 'length'],
  hosts: ['ip', 'mac', 'hostname', 'connections', 'bytes_sent', 'bytes_received', 'protocols'],
  flows: ['source_ip', 'destination_ip', 'destination_port', 'application', 'state', 'duration', 'bytes_sent', 'bytes_received'],
  sessions: ['protocol', 'timestamp', 'frame_number', 'status'],
  dns: ['timestamp', 'source_ip', 'name', 'query_type', 'response_code'],
  http: ['timestamp', 'method', 'host', 'uri', 'status_code', 'content_type'],
  tls: ['timestamp', 'source_ip', 'destination_ip', 'sni', 'version', 'ja3'],
  answers: ['name', 'type', 'value', 'ttl', 'frame_number'],
  certificates: ['subject', 'issuer', 'valid_from', 'valid_until', 'sha256'],
  iocs: ['type', 'value', 'source', 'first_seen', 'last_seen'],
  findings: ['severity', 'title', 'source_ip', 'confidence', 'evidence_count'],
  timeline: ['timestamp', 'kind', 'summary', 'host', 'protocol', 'severity'],
  files: ['filename', 'size', 'sha256', 'mime_type', 'timestamp'],
};
export function inspect(row: Row, collection: string) {
  if (collection === 'timeline') {
    if (row.finding_id) { location.hash = `/inspect/findings/${row.finding_id}`; return; }
    if (row.ioc_id) { location.hash = `/inspect/iocs/${row.ioc_id}`; return; }
    collection = 'packets';
  }
  location.hash = collection === 'packets' ? `/packet/${row.capture_id}/${row.frame_number}` :
    `/inspect/${collection}/${row.id}`;
}
export function Resource({ collection, captureId, initialQuery = '' }: {
  collection: string; captureId?: string; initialQuery?: string;
}) {
  const [query, setQuery] = useState(initialQuery);
  const [draft, setDraft] = useState(initialQuery);
  const [offset, setOffset] = useState(0);
  const [start, setStart] = useState('');
  const [end, setEnd] = useState('');
  const [refresh, setRefresh] = useState(0);
  const params = new URLSearchParams({ q: query, offset: String(offset) });
  if (start) params.set('start', String(new Date(start).getTime() / 1000));
  if (end) params.set('end', String(new Date(end).getTime() / 1000));
  const { data, loading, error } = useData<Page>(
    `${captureId ? `/captures/${captureId}` : '/evidence'}/${collection}?${params}`, refresh);
  return <section className="panel">
    {collection === 'iocs' && captureId && <div className="export-bar"><span>Export observed indicators</span>
      {['txt', 'csv', 'json', 'stix'].map(f => <a key={f} className="button" href={`/api/captures/${captureId}/iocs/export?format=${f}`}>{f.toUpperCase()}</a>)}</div>}
    <form className="toolbar" onSubmit={e => { e.preventDefault(); setQuery(draft); setOffset(0); }}>
      <label className="grow">Evidence filter<input value={draft} onChange={e => setDraft(e.target.value)}
        placeholder="host:10.0.0.10 port:443 protocol:tls" /></label>
      <button type="submit">Apply filter</button><button type="button" onClick={() => setRefresh(x => x + 1)}>Refresh</button>
      {captureId && <details className="time-filter"><summary>Time range</summary><div>
        <label>From (local time)<input type="datetime-local" value={start} onChange={e => { setStart(e.target.value); setOffset(0); }} /></label>
        <label>Until (local time)<input type="datetime-local" value={end} onChange={e => { setEnd(e.target.value); setOffset(0); }} /></label>
      </div></details>}
    </form>
    <State loading={loading} error={error} />
    {!loading && !error && data && <>
      {data.items.length ? <Table rows={data.items} columns={columns[collection] || ['id']}
        onSelect={row => inspect(row, collection)} /> :
        <Empty title="No matching observations">Analyze a capture or adjust the filter. Absence in a capture does not prove absence on the network.</Empty>}
      <footer className="pagination"><span>{data.total.toLocaleString()} observations · {offset + (data.total ? 1 : 0)}–{Math.min(offset + 50, data.total)}</span>
        <div><button disabled={offset === 0} onClick={() => setOffset(x => Math.max(0, x - 50))}>Previous</button>
          <button disabled={offset + 50 >= data.total} onClick={() => setOffset(x => x + 50)}>Next</button></div></footer>
    </>}
  </section>;
}

export function Overview({ captureId }: { captureId?: string }) {
  const { data, loading, error } = useData<Dashboard & { byte_accounting: string; ip_versions: Record<string, number>; transports: { protocol: string; packets: number }[] }>(
    captureId ? `/captures/${captureId}/overview` : '/dashboard');
  if (!data) return <State loading={loading} error={error} />;
  const protocols = data.protocols || [];
  const max = Math.max(1, ...protocols.map(p => p.packets));
  const metrics = captureId ? ['hosts', 'flows', 'dns', 'http', 'tls', 'iocs', 'findings'] : ['analyzed', 'hosts', 'flows', 'iocs', 'findings', 'cases'];
  return <>
    <div className="metrics">{metrics.map(key =>
      <div key={key}><span>{key === 'analyzed' ? 'Captures analyzed' : ['iocs', 'dns', 'http', 'tls'].includes(key) ? key.toUpperCase() : key}</span><strong>{data.counts[key].toLocaleString()}</strong></div>)}</div>
    <div className="overview-grid">
      <section className="panel"><div className="section-heading"><h2>Observed protocols</h2><span>Packets</span></div>
        {protocols.length ? <div className="bars">{protocols.map(p => <div key={p.protocol}>
          <span>{p.protocol}</span><div className="bar-track"><div style={{ width: `${p.packets / max * 100}%` }} /></div>
          <strong>{p.packets.toLocaleString()}</strong></div>)}</div> : <Empty title="No protocol evidence yet">Import and analyze a capture to see its composition.</Empty>}
      </section>
      <section className="panel"><div className="section-heading"><h2>Top senders</h2><span>Per-capture wire bytes</span></div>
        {data.top_talkers?.length ? <Table rows={data.top_talkers} columns={captureId ? ['ip', 'bytes_sent', 'connections'] : ['ip', 'capture_name', 'bytes_sent', 'connections']} onSelect={row => inspect(row, 'hosts')} /> :
          <Empty title="No hosts observed">Only endpoints present in analyzed captures appear here.</Empty>}</section>
    </div>
    {!!data.top_destinations?.length && <section className="panel"><div className="section-heading"><h2>Top destinations</h2></div>
      <Table rows={data.top_destinations} columns={['destination_ip', 'bytes', 'connections']} /></section>}
    <div className="protocol-summary">{Object.entries(data.ip_versions).map(([version, count]) =>
      <span key={version}>{version === 'None' ? 'Non-IP / unavailable' : `IPv${version}`}: {count.toLocaleString()} packets</span>)}
      {data.transports.map(t => <span key={t.protocol}>{t.protocol}: {t.packets.toLocaleString()} packets</span>)}</div>
    {data.byte_accounting && <p className="footnote">{data.byte_accounting}</p>}
  </>;
}

export const tabs = ['Overview', 'Packets', 'Hosts', 'Flows', 'DNS', 'HTTP', 'TLS', 'IOCs', 'Findings', 'Timeline', 'Topology', 'ATT&CK', 'Graph', 'Files', 'Report'];
export function CaptureHeader({ captureId, tab, onCompleted }: { captureId: string; tab: string; onCompleted: () => void }) {
  const [tick, setTick] = useState(0);
  const [error, setError] = useState('');
  const [confirmDelete, setConfirmDelete] = useState(false);
  const { data, loading, error: loadError } = useData<Capture>(`/captures/${captureId}`, tick);
  useEffect(() => {
    if (data && ['queued', 'parsing', 'processing'].includes(data.analysis_status)) {
      const timer = setTimeout(() => setTick(n => n + 1), 1200);
      return () => clearTimeout(timer);
    }
  }, [data, tick]);
  useEffect(() => { if (data?.analysis_status === 'completed') onCompleted(); }, [data?.analysis_status]);
  async function analyze() {
    try { setError(''); await post(`/captures/${captureId}/analyze`); setTick(n => n + 1); }
    catch (e) { setError((e as Error).message); }
  }
  return <>
    <State loading={!data && loading} error={loadError || error} />
    {data && <>
      <div className="capture-heading"><div><h1>{data.original_filename}</h1>
        <p>{data.file_type.toUpperCase()} · {bytes(data.file_size)} · {data.packet_count.toLocaleString()} packets · {data.duration.toFixed(3)}s</p></div>
        <Badge value={data.analysis_status} />
        {['stored', 'failed'].includes(data.analysis_status) && <button className="primary" onClick={() => void analyze()}>{data.analysis_status === 'failed' ? 'Retry analysis' : 'Analyze capture'}</button>}
      </div>
      <details className="identity"><summary>Capture identity and visibility</summary>
        <dl><dt>SHA-256</dt><dd className="mono">{data.sha256}</dd><dt>Capture ID</dt><dd>{data.id}</dd>
          <dt>First packet</dt><dd>{date(data.start_time)}</dd><dt>Last packet</dt><dd>{date(data.end_time)}</dd>
          <dt>Link types</dt><dd>{data.link_types.join(', ') || 'Awaiting analysis'}</dd></dl>
        <p>Original evidence is immutable. All timestamps are displayed in UTC.</p>
        {!['queued', 'parsing', 'processing'].includes(data.analysis_status) && <>
          <button onClick={() => setConfirmDelete(v => !v)}>Remove capture</button>
          {confirmDelete && <div className="warning"><p>Delete this capture and its analysis permanently? Linked cases or reports prevent deletion.</p>
            <button onClick={() => { void api(`/captures/${captureId}`, { method: 'DELETE' })
              .then(() => { location.hash = '/captures'; }).catch((e: Error) => setError(e.message)); }}>Confirm permanent removal</button>
            <button onClick={() => setConfirmDelete(false)}>Cancel</button></div>}</>}
      </details>
      {data.analysis_status !== 'completed' && <div className="job-status" role="status">
        <progress max={100} value={data.progress} aria-label="Analysis progress" /><span>{data.stage} · {data.progress}%</span>
      </div>}
      {data.error && <p className="error" role="alert">{data.error}</p>}
      {!!data.warnings.length && <details className="warning"><summary>{data.warnings.length} visibility notices</summary><ul>{data.warnings.map(w => <li key={w}>{w}</li>)}</ul></details>}
    </>}
    <nav className="tabs" aria-label="Capture investigation">{tabs.map(name => {
      const slug = name === 'ATT&CK' ? 'attack' : name.toLowerCase();
      return <a key={name} href={`#/captures/${captureId}/${slug}`} aria-current={tab === slug ? 'page' : undefined}>{name}</a>;
    })}</nav>
  </>;
}

export function Inspector({ collection, id, captureId }: { collection: string; id: string; captureId?: string }) {
  const [hex, setHex] = useState(false);
  const path = captureId ? `/captures/${captureId}/packets/${id}?hex_view=${hex}` : `/entities/${collection}/${id}`;
  const { data, loading, error } = useData<{ entity?: Row; [key: string]: unknown }>(path);
  const entity = data?.entity || data;
  return <><State loading={loading} error={error} />
    {entity && <section className="panel"><div className="section-heading"><h2>{captureId ? `Frame ${id}` : `${collection} evidence`}</h2>
      <a href={`#/captures/${entity.capture_id}/overview`}>Open capture</a></div>
      <dl className="detail-grid">{Object.entries(entity).filter(([key]) => !['hex', 'entity'].includes(key)).map(([key, value]) =>
        <div key={key}><dt>{key.replaceAll('_', ' ')}</dt><dd>{typeof value === 'object' && value !== null ?
          <FieldTree value={value} /> : format(value, key)}
          {key === 'flow_id' && value != null && <a className="inline-link" href={`#/inspect/flows/${value}`}>Inspect flow</a>}
          {key === 'frame_number' && value != null && <a className="inline-link" href={`#/packet/${entity.capture_id}/${value}`}>Open frame</a>}
        </dd></div>)}</dl>
      {captureId && <div className="padded"><label className="check"><input type="checkbox" checked={hex} onChange={e => setHex(e.target.checked)} />Show raw hexadecimal evidence (up to 4 KiB)</label>
        {hex && <pre className="hex">{String(data?.hex || '')}</pre>}</div>}
    </section>}
    {!captureId && ['hosts', 'iocs', 'findings'].includes(collection) && <AttachToCase kind={{ hosts: 'host', iocs: 'ioc', findings: 'finding' }[collection]!} entityId={id} />}
    {collection === 'iocs' && <Intelligence iocId={id} />}
    {data && !captureId && Object.entries(data).filter(([key]) => key !== 'entity').map(([key, value]) => {
      if (typeof value !== 'object' || value === null) return null;
      const rows = Array.isArray(value) ? value : 'items' in value ? (value as Page).items : [];
      if (!rows.length) return null;
      return <section className="panel" key={key}><div className="section-heading"><h2>{key.replaceAll('_', ' ')}</h2></div>
        <Table rows={rows} columns={columns[key] || ['frame_number', 'timestamp', 'description']}
          onSelect={row => inspect({ ...row, capture_id: row.capture_id || entity?.capture_id },
            ['evidence', 'answers'].includes(key) ? 'packets' : key)} /></section>;
    })}
  </>;
}
