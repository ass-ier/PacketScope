export interface Capture extends Row {
  id: string; original_filename: string; sha256: string; file_size: number; file_type: string;
  analysis_status: string; packet_count: number; progress: number; stage: string; error: string | null;
  start_time: number | null; end_time: number | null; duration: number; created_at: number;
  warnings: string[]; link_types: number[];
}
export type Row = { id: string; [key: string]: unknown };
export interface Page { items: Row[]; total: number; offset: number; limit: number }
export interface Dashboard {
  counts: Record<string, number>; recent_captures: Capture[]; recent_findings: Row[];
  protocols?: { protocol: string; packets: number; bytes: number }[];
  top_talkers?: Row[]; top_destinations?: Row[];
}
