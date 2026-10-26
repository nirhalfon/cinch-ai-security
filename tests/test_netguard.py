"""Tests for the SSRF guard that protects behavioural probing."""

import pytest

from cinch.probes import netguard


@pytest.mark.parametrize(
    "host",
    [
        "169.254.169.254",          # cloud metadata — always refused
        "127.0.0.1",
        "10.0.0.5",
        "192.168.1.10",
        "172.16.0.1",
        "100.64.0.1",
        "::1",
        "localhost",                # resolves to loopback
    ],
)
def test_private_and_metadata_hosts_are_refused(host):
    with pytest.raises(ValueError, match="169.254.169.254|private"):
        netguard.assert_safe_endpoint(f"http://{host}/", allow_private=False)


def test_metadata_ip_refused_even_with_allow_private():
    with pytest.raises(ValueError, match="metadata"):
        netguard.assert_safe_endpoint("http://169.254.169.254/latest/meta-data/", allow_private=True)


def test_private_host_allowed_when_opt_in():
    netguard.assert_safe_endpoint("http://127.0.0.1:8000/", allow_private=True)


def test_public_host_allowed(monkeypatch):
    monkeypatch.setattr(
        netguard.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 80))]
    )
    netguard.assert_safe_endpoint("https://example.com/", allow_private=False)


def test_non_http_scheme_refused():
    with pytest.raises(ValueError, match="http"):
        netguard.assert_safe_endpoint("ftp://example.com/")


def test_unresolvable_host_refused(monkeypatch):
    def boom(*a, **k):
        raise netguard.socket.gaierror("no such host")

    monkeypatch.setattr(netguard.socket, "getaddrinfo", boom)
    with pytest.raises(ValueError, match="does not resolve"):
        netguard.assert_safe_endpoint("http://no-such-host.invalid/")
