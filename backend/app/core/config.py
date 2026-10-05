import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    data_dir: Path = Path(os.environ.get("PACKETSCOPE_DATA", "data")).resolve()
    max_upload_bytes: int = 128 * 1024 * 1024
    max_packets: int = 250_000
    max_flows: int = 30_000
    max_hosts: int = 20_000
    max_frame_bytes: int = 262_144
    max_stream_bytes: int = 262_144
    max_stream_segments: int = 2048
    analysis_timeout: int = 600
    max_pending_jobs: int = 4
    max_captures: int = 200
    max_storage_bytes: int = 2 * 1024 * 1024 * 1024
    max_total_packets: int = 1_000_000
    max_derived_records: int = 200_000
    allowed_hosts: tuple[str, ...] = ("localhost", "127.0.0.1", "testserver")


VERSION = "1.0.0"
