FROM python:3.12-slim

LABEL maintainer="angelnicolasc"
LABEL org.opencontainers.image.source="https://github.com/angelnicolasc/drako-scan"

RUN pip install --no-cache-dir drako requests && \
    apt-get update && apt-get install -y --no-install-recommends jq && \
    rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
COPY pr_comment.py /pr_comment.py

RUN chmod +x /entrypoint.sh && \
    useradd -m -s /bin/bash drako

USER drako

ENTRYPOINT ["/entrypoint.sh"]
