import { type ReactNode } from 'react';
import { bytes, date } from '../lib/api';
import { type Row } from '../types';

export function Empty({ title, children }: { title: string; children: ReactNode }) {
  return <div className="empty"><h3>{title}</h3><p>{children}</p></div>;
}
export function State({ loading, error }: { loading: boolean; error: string }) {
  if (error) return <p className="error" role="alert">{error}</p>;
  if (loading) return <div className="loading" role="status">Loading evidence…</div>;
  return null;
}
export function Badge({ value }: { value: unknown }) {
  return <span className={`badge ${String(value).toLowerCase().replaceAll(' ', '-')}`}>{String(value)}</span>;
}
export function FieldTree({ value }: { value: unknown }) {
  if (typeof value !== 'object' || value === null) return <>{format(value)}</>;
  return <div className="field-tree">{Object.entries(value).map(([key, item]) => {
    const nested = typeof item === 'object' && item !== null;
    return nested ? <details key={key}><summary>{key.replaceAll('_', ' ')} ({Object.keys(item).length})</summary>
      <FieldTree value={item} /></details> : <div key={key}><span className="muted">{key.replaceAll('_', ' ')}: </span>{format(item, key)}</div>;
  })}</div>;
}
export function format(value: unknown, key = ''): ReactNode {
  if (value == null || value === '') return <span className="muted">Not observed</span>;
  if (['timestamp', 'first_seen', 'last_seen', 'start_time', 'end_time', 'created_at'].includes(key) && typeof value === 'number') return date(value);
  if ((key.includes('bytes') || key === 'file_size') && typeof value === 'number') return bytes(value);
  if (key === 'severity' || key === 'analysis_status' || key === 'confidence') return <Badge value={value} />;
  if (typeof value === 'object') return JSON.stringify(value);
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  return String(value);
}
export function Table({ rows, columns, onSelect }: {
  rows: Row[]; columns: string[]; onSelect?: (row: Row) => void;
}) {
  return <div className="table-scroll"><table><thead><tr>{columns.map(c => <th key={c}>{c.replaceAll('_', ' ')}</th>)}
    {onSelect && <th>Evidence</th>}</tr></thead><tbody>{rows.map((row, i) =>
    <tr key={row.id || i}>{columns.map(c => <td key={c} data-column={c}>{format(row[c], c)}
      {['protocol', 'application'].includes(c) && (row.identification === 'port hint' ||
        (typeof row.metadata_fields === 'object' && row.metadata_fields !== null &&
          'identification' in row.metadata_fields && row.metadata_fields.identification === 'port hint')) &&
        <small className="muted"> (port hint)</small>}
    </td>)}
      {onSelect && <td><button className="text-button" onClick={() => onSelect(row)}>Inspect<span className="sr-only"> row {i + 1}</span></button></td>}
    </tr>)}</tbody></table></div>;
}
