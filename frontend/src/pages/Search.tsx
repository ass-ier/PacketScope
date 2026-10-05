import { Empty, State } from '../components/Common';
import { useData } from '../hooks/useData';
import { type Row } from '../types';

export default function Search({ query }: { query: string }) {
  const { data, loading, error } = useData<{ results: { kind: string; entity: Row }[] }>(`/search?q=${encodeURIComponent(query)}`);
  return <><State loading={loading} error={error} />
    {data && <section className="panel"><div className="section-heading"><h2>Results for “{query}”</h2><span>Up to 20 matches per entity type</span></div>
      {data.results.length ? <ul className="search-results">{data.results.map(({ kind, entity }) => <li key={`${kind}/${entity.id}`}>
        <a href={kind === 'captures' ? `#/captures/${entity.id}/overview` : kind === 'cases' ? `#/cases/${entity.id}` : `#/inspect/${kind}/${entity.id}`}>
          <span>{kind}</span><strong>{String(entity.value || entity.title || entity.original_filename || entity.name || entity.ip || entity.sni || `${entity.source_ip} → ${entity.destination_ip}`)}</strong>
          <small>{String(entity.id)}</small></a></li>)}</ul> : <Empty title="No matching evidence">Try an IP, domain, MAC address, port, protocol, case title or finding.</Empty>}
    </section>}</>;
}
