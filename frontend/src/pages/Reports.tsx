import { useState } from 'react';
import { State, Empty } from '../components/Common';
import { useData } from '../hooks/useData';
import { date, post } from '../lib/api';
import { type Row } from '../types';

export default function Reports({ captureId }: { captureId?: string }) {
  const [refresh, setRefresh] = useState(0);
  const reports = useData<Row[]>(`/reports${captureId ? `?capture_id=${captureId}` : ''}`, refresh);
  const cases = useData<Row[]>('/cases');
  const [format, setFormat] = useState('pdf');
  const [caseId, setCaseId] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  return <>
    {captureId && <section className="panel padded"><h2>Export an evidence-backed investigation</h2>
      <p>Reports preserve capture identity, observations, findings, evidence references, visibility limits and your selected case assessment.</p>
      <form onSubmit={e => { e.preventDefault(); setBusy(true); setError('');
        void post('/reports', { capture_id: captureId, format, case_id: caseId || null })
          .then(() => setRefresh(n => n + 1)).catch((e: Error) => setError(e.message)).finally(() => setBusy(false)); }}>
        <div className="form-row"><label>Report format<select value={format} onChange={e => setFormat(e.target.value)}>
          <option value="pdf">PDF — forensic report</option><option value="markdown">Markdown — technical report</option>
          <option value="json">JSON — all indexed entities</option><option value="stix">STIX — observed intelligence</option></select></label>
          <label>Analyst case (must link this capture)<select value={caseId} onChange={e => setCaseId(e.target.value)}><option value="">No case assessment</option>
            {cases.data?.map(c => <option key={c.id} value={c.id}>{String(c.title)}</option>)}</select></label></div>
        <button className="primary" disabled={busy}>{busy ? 'Generating report…' : 'Generate report'}</button>
      </form>
      <p className="footnote">PDF/Markdown show up to 250 rows per section with exact totals. JSON streams the full normalized entity set. All formats cap at 64 MiB. No original packet payloads are embedded.</p>
    </section>}
    <State loading={reports.loading} error={error || reports.error} />
    <section className="panel"><div className="section-heading"><h2>Saved reports</h2><span>Immutable exported snapshots</span></div>
      {reports.data?.length ? <div className="table-scroll"><table><thead><tr><th>Format</th><th>Created (UTC)</th><th>SHA-256</th><th>Download</th></tr></thead><tbody>{reports.data.map(r =>
        <tr key={r.id}><td>{String(r.format).toUpperCase()}</td><td>{date(r.created_at as number)}</td><td className="mono">{String(r.sha256)}</td>
          <td><a className="button" href={`/api/reports/${r.id}/download`}>Download {String(r.format).toUpperCase()}</a></td></tr>)}</tbody></table></div> :
        <Empty title="No reports generated yet">Open a capture’s Report tab, optionally select a linked analyst case, and choose an export format.</Empty>}
    </section>
  </>;
}
