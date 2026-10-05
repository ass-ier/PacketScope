export async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`/api${path}`, options);
  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: `HTTP ${response.status}` }));
    throw new Error(typeof error.detail === 'string' ? error.detail : JSON.stringify(error.detail));
  }
  return response.json() as Promise<T>;
}
export const post = <T,>(path: string, body: unknown = {}) =>
  api<T>(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

export const bytes = (n: number) => n >= 1048576 ? `${(n / 1048576).toFixed(2)} MiB` :
  n >= 1024 ? `${(n / 1024).toFixed(1)} KiB` : `${n} B`;
export const date = (n: number | null) => n == null ? 'Not observed' : new Date(n * 1000).toISOString().replace('T', ' ').replace('Z', ' UTC');
