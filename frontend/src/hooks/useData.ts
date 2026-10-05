import { useEffect, useState } from 'react';
import { api } from '../lib/api';

export function useData<T>(path: string | null, refresh = 0) {
  const [data, setData] = useState<T>();
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let active = true;
    if (!path) { setLoading(false); return; }
    setLoading(true); setError('');
    api<T>(path).then(value => { if (active) setData(value); })
      .catch((e: Error) => { if (active) setError(e.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [path, refresh]);
  return { data, error, loading };
}
