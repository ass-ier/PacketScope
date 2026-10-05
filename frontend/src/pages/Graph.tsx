import { useState } from 'react';
import { Background, Controls, ReactFlow, type Edge, type Node, MarkerType } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { useData } from '../hooks/useData';
import { Empty, State } from '../components/Common';

interface GraphData { nodes: Node[]; edges: Edge<{ flow_ids: string[]; count: number }>[]; total_flows: number; shown_flows: number; limited: boolean; limits: string }
export default function Graph({ captureId, topology = false }: { captureId: string; topology?: boolean }) {
  const [draft, setDraft] = useState('');
  const [query, setQuery] = useState('');
  const [start, setStart] = useState('');
  const [end, setEnd] = useState('');
  const [selected, setSelected] = useState<Node | Edge<{ flow_ids: string[]; count: number }>>();
  const params = new URLSearchParams({ q: query, topology: String(topology) });
  if (start) params.set('start', String(new Date(start).getTime() / 1000));
  if (end) params.set('end', String(new Date(end).getTime() / 1000));
  const { data, error, loading } = useData<GraphData>(`/captures/${captureId}/graph?${params}`);
  return <section className="panel">
    <form className="toolbar" onSubmit={e => { e.preventDefault(); setQuery(draft); setSelected(undefined); }}>
      <label className="grow">Focus graph<input value={draft} onChange={e => setDraft(e.target.value)} placeholder="host:10.0.0.10 protocol:dns" /></label>
      <button>Apply filter</button>
      <label>From (local)<input type="datetime-local" value={start} onChange={e => setStart(e.target.value)} /></label>
      <label>Until (local)<input type="datetime-local" value={end} onChange={e => setEnd(e.target.value)} /></label>
    </form>
    <State loading={loading} error={error} />
    {data && !loading && <>
      <p className="graph-caption">{data.shown_flows} of {data.total_flows} flows. Drag to pan, scroll to zoom. Select a node or connection to inspect evidence.</p>
      {data.nodes.length ? <div className="graph-layout"><div className="graph-canvas">
        <ReactFlow key={`${query}/${start}/${end}/${topology}`} defaultNodes={data.nodes} defaultEdges={data.edges.map(e => ({ ...e, markerEnd: { type: MarkerType.ArrowClosed, color: '#7c919d' } }))}
          fitView fitViewOptions={{ maxZoom: 1, padding: 0.15 }} minZoom={0.15} maxZoom={2} onNodeClick={(_, node) => setSelected(node)}
          onEdgeClick={(_, edge) => setSelected(edge)} nodesDraggable nodesConnectable={false}
          onNodeDragStop={(_, node) => setSelected(node)} aria-label="Evidence relationship graph">
          <Background gap={24} color="#dce4e8" /><Controls showInteractive={false} />
        </ReactFlow></div>
        <aside className="graph-detail"><h3>Selected evidence</h3>
          {!selected ? <p className="muted">Choose a node or an edge. Internal addresses use RFC1918 or IPv6 ULA ranges.</p> :
            'source' in selected ? <><p>{String(selected.label)} · {selected.data?.count} observations</p>
              <h3>Underlying flows</h3><ul>{selected.data?.flow_ids.map(id => <li key={id}><a href={`#/inspect/flows/${id}`}>{id.slice(0, 8)} — inspect flow</a></li>)}</ul></> :
              <><p>{String(selected.data.label)}</p><p className="muted">{String(selected.data.kind)}</p>
                {selected.data.entity_id ? <a className="button" href={`#/inspect/${selected.data.collection}/${selected.data.entity_id}`}>Inspect evidence</a> : null}</>}
        </aside></div> : <Empty title="No graph relationships in this selection">Choose an analyzed capture or broaden the filters.</Empty>}
      <p className="graph-caption">{data.limits}{data.limited && ' Results are limited; refine the filter.'}</p>
    </>}
  </section>;
}
