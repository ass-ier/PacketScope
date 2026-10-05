import { Badge, Empty, State } from '../components/Common';
import { useData } from '../hooks/useData';
import { type Row } from '../types';

interface Mapping extends Row { technique: Row; source_detection: Row; evidence: Row[] }
export default function Attack({ captureId }: { captureId: string }) {
  const { data, loading, error } = useData<{ mappings: Mapping[]; caveat: string }>(`/captures/${captureId}/attack`);
  const tactics = [...new Set(data?.mappings.map(m => String(m.technique.tactic)) || [])];
  return <><State loading={loading} error={error} />{data && <>
    <p className="warning">{data.caveat}</p>
    {tactics.length ? <div className="attack-matrix">{tactics.map(tactic => <section className="panel" key={tactic}>
      <div className="section-heading"><h2>{tactic}</h2><span>Evidence-supported candidates</span></div>
      {data.mappings.filter(m => m.technique.tactic === tactic).map(mapping => <article className="mapping" key={mapping.id}>
        <h3>{String(mapping.technique.id)} · {String(mapping.technique.name)}</h3>
        <Badge value={mapping.confidence} /><p>{String(mapping.rationale)}</p>
        <a className="button" href={`#/inspect/findings/${mapping.finding_id}`}>Inspect {mapping.evidence.length} supporting observations</a>
        <p className="footnote">Source: {String(mapping.source_detection.title)}</p>
        <a href={String(mapping.technique.url)} target="_blank" rel="noreferrer">MITRE reference (external)</a>
      </article>)}</section>)}</div> : <section className="panel"><Empty title="No supported technique mappings">No observed finding meets the configured mapping criteria. This does not prove that the traffic is benign.</Empty></section>}
  </>}</>;
}
