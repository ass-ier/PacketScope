import { useState } from 'react';
import { Empty, State, Table } from '../components/Common';
import { useData } from '../hooks/useData';
import { api, date, post } from '../lib/api';
import { type Capture, type Row } from '../types';
import { columns, inspect } from './Explore';

interface CaseData { case: Row; captures: Row[]; hosts: Row[]; iocs: Row[]; findings: Row[]; notes: Row[] }
export function AttachToCase({ kind, entityId }: { kind: string; entityId: string }) {
  const { data } = useData<Row[]>('/cases');
  const [caseId, setCaseId] = useState('');
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  async function attach() {
    try { setBusy(true); await post(`/cases/${caseId}/links`, { kind, entity_id: entityId }); setMessage('Evidence attached to case.'); }
    catch (e) { setMessage((e as Error).message); } finally { setBusy(false); }
  }
  return <div className="attach-case"><label>Attach to investigation<select value={caseId} onChange={e => setCaseId(e.target.value)}>
    <option value="">Select a case</option>{data?.map(c => <option key={c.id} value={c.id}>{String(c.title)}</option>)}</select></label>
    <button disabled={!caseId || busy} onClick={() => void attach()}>Attach evidence</button>
    {!data?.length && <a href="#/cases">Create a case first</a>}{message && <span role="status">{message}</span>}</div>;
}

function Assessment({ data, saved }: { data: Row; saved: () => void }) {
  const [status, setStatus] = useState(String(data.status));
  const [verdict, setVerdict] = useState(String(data.verdict));
  const [confidence, setConfidence] = useState(String(data.confidence));
  const [reasoning, setReasoning] = useState(String(data.reasoning));
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  async function save() {
    try { setBusy(true); await api(`/cases/${data.id}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ status, verdict, confidence, reasoning }) }); saved(); setMessage('Analyst assessment saved.'); }
    catch (e) { setMessage((e as Error).message); } finally { setBusy(false); }
  }
  return <section className="panel padded"><h2>Analyst assessment</h2><p className="footnote">Your judgment, separate from automated observations. Linked findings and notes preserve supporting evidence.</p>
    <div className="form-row">
      <label>Case status<select value={status} onChange={e => setStatus(e.target.value)}>{['Open', 'Investigating', 'Contained', 'Closed', 'False Positive'].map(v => <option key={v}>{v}</option>)}</select></label>
      <label>Verdict<select value={verdict} onChange={e => setVerdict(e.target.value)}>{['Unknown', 'Benign', 'Suspicious', 'Malicious'].map(v => <option key={v}>{v}</option>)}</select></label>
      <label>Confidence<select value={confidence} onChange={e => setConfidence(e.target.value)}>{['Low', 'Medium', 'High'].map(v => <option key={v}>{v}</option>)}</select></label>
    </div>
    <label>Reasoning<textarea value={reasoning} maxLength={20000} onChange={e => setReasoning(e.target.value)} placeholder="Explain the assessment, cite evidence, and acknowledge uncertainty." /></label>
    <div className="form-actions"><button className="primary" disabled={busy} onClick={() => void save()}>Save assessment</button>
      <span role="status">{message}</span><span className="muted">Last assessment: {date(data.assessed_at as number | null)}</span></div>
  </section>;
}

export default function Cases({ id }: { id?: string }) {
  const [refresh, setRefresh] = useState(0);
  const [title, setTitle] = useState('');
  const [note, setNote] = useState('');
  const [evidenceIds, setEvidenceIds] = useState('');
  const [captureId, setCaptureId] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const list = useData<Row[]>('/cases', refresh);
  const detail = useData<CaseData>(id ? `/cases/${id}` : null, refresh);
  const captures = useData<Capture[]>('/captures');
  async function action(work: () => Promise<unknown>) {
    try { setBusy(true); setError(''); await work(); setRefresh(n => n + 1); }
    catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  }
  if (!id) return <>
    <form className="panel toolbar" onSubmit={e => { e.preventDefault(); void action(async () => {
      const created = await post<Row>('/cases', { title }); location.hash = `/cases/${created.id}`; setTitle('');
    }); }}><label className="grow">New investigation title<input required maxLength={200} value={title} onChange={e => setTitle(e.target.value)} placeholder="Name the question you are investigating" /></label>
      <button className="primary" disabled={busy}>Create case</button></form>
    <State loading={list.loading} error={error || list.error} />
    {list.data && <section className="panel">{list.data.length ? <Table rows={list.data} columns={['title', 'status', 'verdict', 'confidence', 'updated_at']}
      onSelect={row => { location.hash = `/cases/${row.id}`; }} /> : <Empty title="No investigations yet">Create a case, attach captures or findings, and record your assessment.</Empty>}</section>}
  </>;
  const data = detail.data;
  return <><State loading={detail.loading} error={error || detail.error} />{data && <>
    <h2 className="case-title">{String(data.case.title)}</h2>
    <Assessment key={id} data={data.case} saved={() => setRefresh(n => n + 1)} />
    <section className="panel"><div className="section-heading"><h2>Linked evidence</h2></div>
      <form className="toolbar" onSubmit={e => { e.preventDefault(); void action(() => post(`/cases/${id}/links`, { kind: 'capture', entity_id: captureId })); }}>
        <label className="grow">Completed capture<select value={captureId} onChange={e => setCaptureId(e.target.value)}><option value="">Choose a capture</option>
          {captures.data?.filter(c => c.analysis_status === 'completed').map(c => <option key={c.id} value={c.id}>{c.original_filename}</option>)}</select></label>
        <button disabled={!captureId || busy}>Attach capture</button></form>
      {data.captures.length ? <Table rows={data.captures} columns={['original_filename', 'sha256', 'packet_count']} onSelect={row => { location.hash = `/captures/${row.id}/overview`; }} /> :
        <Empty title="Attach your evidence">Add a completed capture, or attach an individual host, IOC or finding from its evidence page.</Empty>}
      {(['hosts', 'iocs', 'findings'] as const).map(key => !!data[key].length && <div key={key}><div className="section-heading"><h3>{key}</h3></div>
        <Table rows={data[key]} columns={columns[key]} onSelect={row => inspect(row, key)} /></div>)}
    </section>
    <section className="panel padded"><h2>Analyst notes</h2>
      <form onSubmit={e => { e.preventDefault(); void action(async () => {
        await post(`/cases/${id}/notes`, { text: note, evidence_ids: evidenceIds.split(',').map(s => s.trim()).filter(Boolean) }); setNote(''); setEvidenceIds('');
      }); }}>
        <label>Note<textarea required maxLength={20000} value={note} onChange={e => setNote(e.target.value)} /></label>
        <label>Evidence IDs (optional, comma-separated)<input value={evidenceIds} onChange={e => setEvidenceIds(e.target.value)} /></label>
        <button disabled={busy} className="primary">Add note</button>
      </form>
      {data.notes.map(n => <article className="note" key={n.id}><time>{date(n.created_at as number)}</time><p>{String(n.text)}</p>
        {Array.isArray(n.evidence_ids) && n.evidence_ids.map((eid: string) => <a key={eid} href={`#/inspect/evidence/${eid}`}>Evidence {eid.slice(0, 8)} </a>)}</article>)}
    </section>
  </>}</>;
}
