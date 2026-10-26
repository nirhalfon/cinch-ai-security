"""SSRF guard for behavioural probes.

The behavioural probe family is the only part of Cinch that makes outbound
HTTP requests, and ``--authorized`` is self-asserted — so the collector must
refuse, by construction, to POST into internal networks: the cloud metadata
service, loopback, link-local and private ranges. Checks run after DNS
resolution (so a hostname that resolves to a blocked address is caught) and
before any socket is opened.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

# The cloud metadata address is refused unconditionally — no legitimate
# agent-under-test ever lives on it, and it mints instance credentials.
_ALWAYS_BLOCKED = ipaddress.ip_network("169.254.169.254/32")

# Private / reserved ranges refused unless allow_private is set.
_PRIVATE_NETS = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)


def _ip(addr: str) -> ipaddress._BaseAddress:
    """Normalize IPv4-mapped IPv6 addresses so they match IPv4 net checks."""
    ip = ipaddress.ip_address(addr)
    mapped = getattr(ip, "ipv4_mapped", None)
    return mapped or ip


def assert_safe_endpoint(url: str, allow_private: bool = False) -> None:
    """Raise ValueError unless ``url`` is an http(s) URL that is safe to POST to.

    Refuses: non-http(s) schemes, hosts that do not resolve, the cloud metadata
    address (always), and private/loopback/link-local addresses (unless
    ``allow_private`` is set, for local test deployments).
    """
    parts = urlparse(url)
    if parts.scheme not in ("http", "https"):
        raise ValueError(f"endpoint must be an http(s) URL, got {url!r}")
    host = parts.hostname
    port = None
    if host is not None:
        try:
            port = parts.port
        except ValueError as exc:
            raise ValueError(f"endpoint URL has an invalid port: {url!r}") from exc
    else:
        # urlparse cannot see an unbracketed IPv6 literal (http://::1/): recover
        # it from the raw netloc so loopback/private addresses are still caught.
        try:
            host = ipaddress.ip_address(parts.netloc).compressed
        except ValueError:
            raise ValueError(f"endpoint URL has no host: {url!r}") from None
    if not host:
        raise ValueError(f"endpoint URL has no host: {url!r}")
    port = port or (443 if parts.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"endpoint host does not resolve: {parts.hostname!r}") from exc
    addrs = {info[4][0] for info in infos}
    always = sorted(a for a in addrs if _ip(a) in _ALWAYS_BLOCKED)
    if always:
        raise ValueError(
            "endpoint resolves to the cloud metadata address 169.254.169.254 — refused "
            "unconditionally; an agent-under-test never lives on the metadata service"
        )
    if allow_private:
        return
    private = sorted(a for a in addrs if any(_ip(a) in net for net in _PRIVATE_NETS))
    if private:
        raise ValueError(
            "endpoint resolves to a private/loopback/link-local address: "
            + ", ".join(private)
            + ". Refusing to POST into an internal network — pass --allow-private (CLI) "
            "or allow_private=true (MCP) to test a local deployment."
        )
