"""Allow running the proxy with: python -m drako.proxy."""

from __future__ import annotations

import os

from drako.proxy.proxy_server import run_server

if __name__ == "__main__":
    host = os.environ.get("DRAKO_PROXY_HOST", "127.0.0.1")
    port = int(os.environ.get("DRAKO_PROXY_PORT", "8990"))
    config_path = os.environ.get("DRAKO_CONFIG_PATH", ".drako.yaml")
    run_server(port=port, host=host, config_path=config_path)
