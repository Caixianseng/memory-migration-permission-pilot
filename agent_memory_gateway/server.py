"""Run the gateway on loopback only."""

from __future__ import annotations

import argparse
import os
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the local Agent Memory Gateway.")
    parser.add_argument("--data-dir", default=".agent-memory-gateway")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    token = os.environ.get("AGENT_MEMORY_GATEWAY_TOKEN", "")
    if len(token) < 32:
        raise SystemExit(
            "Set AGENT_MEMORY_GATEWAY_TOKEN to a random value of at least 32 characters."
        )
    if not 1 <= args.port <= 65535:
        raise SystemExit("Port must be between 1 and 65535.")

    try:
        import uvicorn
    except ImportError:
        raise SystemExit(
            "Install the gateway runtime first: python -m pip install -r requirements-gateway.txt"
        ) from None

    from .api import create_app

    app = create_app(Path(args.data_dir), token)
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")
    return 0
