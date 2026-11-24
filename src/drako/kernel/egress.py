"""Egress guard — anti-SSRF single chokepoint (P1-1 / ADR-0001).

Every outbound fetch to a server- or agent-controlled URL MUST pass through
`assert_public_url()` BEFORE the first byte leaves, and re-validate EVERY
redirect hop (ToolHive CVE-2026-58196 lesson: the 302 to metadata is the
attack, not the initial URL).

Honest residual limitation (documented in docs/known-limitations.md):
DNS-rebinding TOCTOU is racy by nature between resolve and connect.
Mitigations applied: per-hop revalidation, no credentials forwarded across
redirects, short timeouts. Full fix requires an OS/network egress proxy with
DNS pinning.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
from urllib.parse import urljoin, urlparse

logger = logging.getLogger("drako.kernel.egress")

_BLOCKED_NETS = [
    ipaddress.ip_network(c)
    for c in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
]

_MAX_REDIRECTS = 3


class EgressViolation(Exception):
    """Raised when an outbound URL fails the egress policy. Fail-closed."""

    def __init__(self, url: str, reason: str):
        self.url_host = (urlparse(url).hostname or "?")[:120]
        self.reason = reason
        super().__init__(f"Egress blocked ({reason}): host={self.url_host}")


def _ip_blocked(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    ):
        return True
    return any(addr in net for net in _BLOCKED_NETS)


def _resolve_all(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(
            host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )
    except socket.gaierror as e:
        raise EgressViolation(host, f"dns-failed: {e}") from e
    return sorted({info[4][0] for info in infos})


def assert_public_url(
    url: str,
    *,
    allow_private: bool = False,
    allowed_schemes: tuple[str, ...] = ("https",),
    allowlist: list[str] | None = None,
) -> str:
    """Validate an outbound URL. Returns the URL unchanged or raises EgressViolation."""
    if allow_private or os.environ.get("DRAKO_ALLOW_PRIVATE_EGRESS") == "1":
        logger.warning(
            "AUDIT egress-escape-hatch used: DRAKO_ALLOW_PRIVATE_EGRESS=1 "
            "bypassed SSRF checks for host=%s (emergency only; authorize via "
            ".drako.yaml -> egress.allowed_domains)",
            (urlparse(url).hostname or "?")[:120],
        )
        return url

    p = urlparse(url)
    if p.scheme not in allowed_schemes:
        raise EgressViolation(
            url,
            f"scheme {p.scheme!r} not in {list(allowed_schemes)} — LAN/http "
            "targets are blocked by design; configure egress.allowed_domains in .drako.yaml",
        )
    host = p.hostname or ""
    if not host:
        raise EgressViolation(url, "empty hostname")

    if allowlist is not None and host not in allowlist and not any(
        host.endswith("." + d) for d in allowlist
    ):
        raise EgressViolation(
            url,
            "not in domain allowlist — authorize this host in .drako.yaml -> egress.allowed_domains",
        )

    try:
        ipaddress.ip_address(host)
        is_literal = True
    except ValueError:
        is_literal = False

    if is_literal:
        if _ip_blocked(host):
            raise EgressViolation(
                url,
                "literal IP in blocked range (private/link-local/metadata)",
            )
        return url

    for ip in _resolve_all(host):
        if _ip_blocked(ip):
            raise EgressViolation(
                url,
                f"resolves to blocked IP {ip} (private/link-local/metadata)",
            )
    return url


def resolve_redirect(
    current_url: str,
    location: str,
    hop: int,
    *,
    allowlist: list[str] | None = None,
) -> str:
    """Re-validate a redirect target. Raises EgressViolation on abuse."""
    if hop >= _MAX_REDIRECTS:
        raise EgressViolation(current_url, "too many redirects")
    nxt = urljoin(current_url, location)
    return assert_public_url(nxt, allowlist=allowlist)
