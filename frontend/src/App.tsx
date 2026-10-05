import { useEffect, useState } from 'react';
import { api } from './lib/api';
import { useData } from './hooks/useData';
import { Empty, State, Table } from './components/Common';
import { type Capture, type Dashboard, type Row } from './types';
import { CaptureHeader, Inspector, Overview, Resource } from './pages/Explore';
import Search from './pages/Search';
import Settings from './pages/Settings';
import Graph from './pages/Graph';
import Cases from './pages/Cases';
import CapturePicker from './components/CapturePicker';
import Attack from './pages/Attack';
import { Compare, Files } from './pages/Advanced';
import Reports from './pages/Reports';
import { ReadOnlyContext } from './hooks/useReadOnly';

const navigation = ['Dashboard', 'Captures', 'Hosts', 'Flows', 'DNS', 'HTTP', 'TLS', 'IOCs', 'Findings', 'Timeline', 'Network Graph', 'Cases', 'ATT&CK', 'Compare', 'Reports', 'Settings'];
const slugFor = (name: string) => name === 'ATT&CK' ? 'attack' : name.toLowerCase().replaceAll(' ', '-');
export default function App() {
  const [route, setRoute] = useState(location.hash.slice(2) || 'dashboard');
  const [refresh, setRefresh] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [analysisRefresh, setAnalysisRefresh] = useState(0);
  const runtime = useData<{ external_enabled: boolean; demo_mode: boolean; read_only: boolean }>('/settings');
  const readOnly = runtime.data?.read_only ?? true;
  const { data, loading, error: loadError } = useData<Dashboard>('/dashboard', refresh);
  useEffect(() => {
    const change = () => setRoute(location.hash.slice(2) || 'dashboard');
    window.addEventListener('hashchange', change);
    return () => window.removeEventListener('hashchange', change);
  }, []);
  useEffect(() => { if (route === 'dashboard' || route === 'captures') setRefresh(n => n + 1); }, [route]);
  async function upload(file?: File) {
    if (!file) return;
    setBusy(true); setError('');
    const body = new FormData(); body.append('file', file);
    try { const capture = await api<Capture>('/captures', { method: 'POST', body }); setRefresh(x => x + 1); location.hash = `/captures/${capture.id}/overview`; }
    catch (e) { setError((e as Error).message); }
    finally { setBusy(false); }
  }
  const [section, id, tab = 'overview'] = route.split('/');
  const isCapture = section === 'captures' && !!id;
  const title = navigation.find(n => slugFor(n) === section) || 'Evidence inspection';
  return <ReadOnlyContext.Provider value={readOnly}><div className="app">
    <a className="skip" href="#main" onClick={e => { e.preventDefault(); document.getElementById('main')?.focus(); }}>Skip to investigation</a>
    <aside className="sidebar">
      <a className="brand" href="#/dashboard"><svg viewBox="0 0 28 28" aria-hidden="true"><path d="M3 14h6l3-8 5 16 3-8h5" /></svg>PacketScope</a>
      <p className="workspace-label">Investigation workspace</p>
      <nav aria-label="Main navigation">{navigation.map(name => {
        const slug = slugFor(name);
        return <a key={name} href={`#/${slug}`} aria-current={route.split('/')[0] === slug ? 'page' : undefined}>{name}</a>;
      })}</nav>
      <div className="local-state"><span className="dot" />{runtime.data?.demo_mode ? 'Synthetic sample evidence' : 'Local evidence storage'}<small>{runtime.data?.external_enabled ? 'External lookups opt-in' : 'External integrations off'}</small></div>
    </aside>
    <main id="main" tabIndex={-1}>
      <header className="topbar"><span>Network forensics / {route.split('/')[0]}</span>
        <form className="global-search" onSubmit={e => { e.preventDefault(); if (search.trim()) location.hash = `/search/${encodeURIComponent(search.trim())}`; }}>
          <input aria-label="Search all evidence" placeholder="Search IP, domain, port, case…" value={search} onChange={e => setSearch(e.target.value)} />
          <button>Search</button></form></header>
      <div className="page">
        {runtime.data?.demo_mode && <div className="notice" role="note"><strong>Read-only live demo · synthetic data</strong>
          <p>Explore real analysis of generated captures, example cases, graphs and reports. Uploads, edits and external lookups are disabled. Run PacketScope locally for the full workflow.</p></div>}
        {runtime.error && <p role="alert" className="error">Cannot load API settings: {runtime.error}. Check the deployment API connection.</p>}
        {!isCapture && <div className="page-heading"><div><h1>{route === 'dashboard' ? 'Investigation overview' : title}</h1>
          <p>Start with the traffic. Follow the evidence.</p></div>
          {!readOnly && <label className={`button primary ${busy ? 'disabled' : ''}`}>{busy ? 'Importing…' : 'Import capture'}
            <input type="file" accept=".pcap,.pcapng" disabled={busy} onChange={e => void upload(e.target.files?.[0])} /></label>}</div>}
        {error && <p role="alert" className="error">{error}</p>}
        {(section === 'dashboard' || (section === 'captures' && !id)) && <><State loading={loading} error={loadError} />
        {data && <>
          {route === 'dashboard' && <Overview key={refresh} />}
          {route === 'dashboard' && <section className="panel"><div className="section-heading"><h2>Recent findings</h2><span>Observed indicators, not verdicts</span></div>
            {data.recent_findings.length ? <Table rows={data.recent_findings} columns={['severity', 'title', 'source_ip', 'confidence']}
              onSelect={row => { location.hash = `/inspect/findings/${row.id}`; }} /> :
              <Empty title="No findings in analyzed captures">No configured rule has matched observed traffic. This does not prove that all activity is benign.</Empty>}</section>}
          <section className="panel"><div className="section-heading"><h2>Capture register</h2><span>{data.recent_captures.length} captures</span></div>
            {data.recent_captures.length ? <Table rows={data.recent_captures}
              columns={['original_filename', 'file_type', 'file_size', 'analysis_status', 'packet_count']}
              onSelect={row => { location.hash = `/captures/${row.id}/overview`; }} /> :
              <Empty title="Your investigation starts with a capture">Import a PCAP or PCAPNG file. PacketScope checks its content and records a SHA-256 identity before analysis. Nothing leaves this workstation.</Empty>}
          </section>
        </>}</>}
        {isCapture && <><CaptureHeader key={id} captureId={id} tab={tab} onCompleted={() => { setAnalysisRefresh(n => n + 1); setRefresh(n => n + 1); }} />
          {tab === 'overview' ? <Overview key={`${id}/${analysisRefresh}`} captureId={id} /> : tab === 'report' ? <Reports captureId={id} /> : tab === 'files' ? <Files captureId={id} /> : tab === 'attack' ? <Attack captureId={id} /> : ['topology', 'graph'].includes(tab) ?
            <Graph key={`${id}/${tab}`} captureId={id} topology={tab === 'topology'} /> :
            <Resource key={`${id}/${tab}/${analysisRefresh}`} collection={tab} captureId={id} />}</>}
        {['hosts', 'flows', 'dns', 'http', 'tls', 'iocs', 'findings', 'timeline'].includes(section) && <Resource key={section} collection={section} />}
        {section === 'inspect' && <Inspector key={route} collection={id} id={tab} />}
        {section === 'packet' && <Inspector key={route} collection="packets" captureId={id} id={tab} />}
        {section === 'search' && <Search key={route} query={decodeURIComponent(id || '')} />}
        {section === 'settings' && <Settings />}
        {section === 'network-graph' && <CapturePicker>{cid => <Graph captureId={cid} />}</CapturePicker>}
        {section === 'cases' && <Cases key={id || 'list'} id={id} />}
        {section === 'attack' && <CapturePicker>{cid => <Attack captureId={cid} />}</CapturePicker>}
        {section === 'compare' && <Compare />}
        {section === 'reports' && <><CapturePicker>{cid => <Reports captureId={cid} />}</CapturePicker><Reports /></>}
      </div>
    </main>
  </div></ReadOnlyContext.Provider>;
}
