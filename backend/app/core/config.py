import os
from dataclasses import dataclass, field
from pathlib import Path


def configured_hosts():
    hosts = [host.strip() for host in os.environ.get("PACKETSCOPE_ALLOWED_HOSTS",
                                                     "localhost,127.0.0.1,testserver").split(",") if host.strip()]
    if os.environ.get("RENDER_EXTERNAL_HOSTNAME"):
        hosts.append(os.environ["RENDER_EXTERNAL_HOSTNAME"])
    return tuple(dict.fromkeys(hosts))


@dataclass(frozen=True)
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(os.environ.get(
        "PACKETSCOPE_DATA", "demo-data" if os.environ.get("PACKETSCOPE_DEMO") == "true" else "data")).resolve())
    demo_mode: bool = field(default_factory=lambda: os.environ.get("PACKETSCOPE_DEMO") == "true")
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
    allowed_hosts: tuple[str, ...] = field(default_factory=configured_hosts)

    def __post_init__(self):
        if not self.allowed_hosts:
            raise ValueError("PACKETSCOPE_ALLOWED_HOSTS must contain at least one hostname")
        if self.demo_mode and os.environ.get("PACKETSCOPE_EXTERNAL_ENABLED") == "true":
            raise ValueError("External intelligence cannot be enabled in the public demo")


VERSION = "1.0.0"
