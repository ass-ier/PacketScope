"""Offline benchmark: streamed benign fixture, isolated database, measured analysis."""
import argparse
import importlib.util
import json
import os
import platform
import resource
import tempfile
import time
from pathlib import Path

import dpkt
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app

spec = importlib.util.spec_from_file_location("fixtures", Path(__file__).parents[1] / "fixtures/generate.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def run(count):
    with tempfile.TemporaryDirectory(prefix="packetscope-benchmark-") as temporary:
        folder = Path(temporary)
        path = folder / "benchmark.pcap"
        with path.open("wb") as handle:
            writer = dpkt.pcap.Writer(handle)
            for index in range(count):
                writer.writepkt(fixture.packet(src=f"10.0.0.{1 + index % 64}", sport=40000 + index % 512,
                                                dport=9000, udp=True, payload=b"synthetic benchmark observation"),
                                ts=fixture.EPOCH + index * .001)
        size = path.stat().st_size
        with TestClient(create_app(Settings(data_dir=folder / "data"))) as client:
            with path.open("rb") as handle:
                capture = client.post("/api/captures", files={"file":("benchmark.pcap", handle)}).json()
            started = time.monotonic()
            client.post(f"/api/captures/{capture['id']}/analyze")
            while True:
                result = client.get(f"/api/captures/{capture['id']}").json()
                if result["analysis_status"] in ("completed", "failed"):
                    break
                time.sleep(.05)
            elapsed = time.monotonic() - started
            assert result["analysis_status"] == "completed", result
            assert result["packet_count"] == count
            counts = client.get(f"/api/captures/{capture['id']}/overview").json()["counts"]
            peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            return {"packets": count, "capture_bytes": size, "analysis_seconds": round(elapsed, 3),
                    "packets_per_second": round(count / elapsed), "peak_process_rss_bytes": peak if platform.system() == "Darwin" else peak * 1024,
                    "database_bytes": sum(p.stat().st_size for p in (folder / "data").glob("*.sqlite*")),
                    "counts": counts, "platform": platform.platform(), "python": platform.python_version(),
                    "cpu_count": os.cpu_count(), "scope": "UDP workload, 512 flows; process peak includes framework and fixture setup, not parser alone"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--packets", type=int, default=10000)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run(args.packets)
    text = json.dumps(result, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n")
    print(text)
