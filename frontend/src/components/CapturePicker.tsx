import { useState, type ReactNode } from 'react';
import { useData } from '../hooks/useData';
import { Empty, State } from './Common';
import { type Capture } from '../types';

export default function CapturePicker({ children }: { children: (id: string) => ReactNode }) {
  const { data, error, loading } = useData<Capture[]>('/captures');
  const [id, setId] = useState('');
  const captures = data?.filter(c => c.analysis_status === 'completed') || [];
  return <><State loading={loading} error={error} />
    {captures.length ? <><label className="capture-picker">Investigation capture<select value={id} onChange={e => setId(e.target.value)}>
      <option value="">Choose a completed capture</option>{captures.map(c => <option key={c.id} value={c.id}>{c.original_filename}</option>)}</select></label>
      {id ? children(id) : <Empty title="Choose your evidence">Select an analyzed capture above to open this investigation view.</Empty>}</> :
      !loading && <Empty title="Analyze a capture first">This view uses real capture observations. Import and analyze a PCAP to begin.</Empty>}</>;
}
