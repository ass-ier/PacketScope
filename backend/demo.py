"""Launch the seeded read-only preview. Never enables uploads or external lookups."""
import os

import uvicorn


def main():
    os.environ["PACKETSCOPE_DEMO"] = "true"
    if os.environ.get("PACKETSCOPE_EXTERNAL_ENABLED") == "true":
        raise SystemExit("Unset PACKETSCOPE_EXTERNAL_ENABLED before starting a demo")
    port = int(os.environ.get("PORT", "8765"))
    if not 1 <= port <= 65535:
        raise SystemExit("PORT must be between 1 and 65535")
    uvicorn.run("app.main:app", host=os.environ.get("PACKETSCOPE_BIND", "127.0.0.1"),
                port=port, workers=1, limit_concurrency=16, timeout_keep_alive=5,
                proxy_headers=False)


if __name__ == "__main__":
    main()
