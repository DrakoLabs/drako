"""Allow running the proxy with: python -m drako.proxy"""

import os
from drako.proxy.proxy_server import run_server

if __name__ == "__main__":
    port = int(os.environ.get("DRAKO_PROXY_PORT", "8990"))
    run_server(port=port)
