FROM python:3.12-slim

LABEL maintainer="DrakoLabs"
LABEL org.opencontainers.image.source="https://github.com/DrakoLabs/drako"

RUN pip install --no-cache-dir drako requests && \
    apt-get update && apt-get install -y --no-install-recommends curl jq && \
    rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
COPY pr_comment.py /pr_comment.py

RUN chmod +x /entrypoint.sh && \
    useradd -m -s /bin/bash drako

USER drako

ENTRYPOINT ["/entrypoint.sh"]
