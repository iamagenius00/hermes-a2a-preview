"""Tests for plugin/ssrf.py — design doc §7.1, §7.2, §7.3, §7.4, §7.6.

§7.5 (friend-add + outbound-uses-record tests) is deferred to P1.3 because
it extends `test_friends_store.py` next to the frozen `friends.py`.
§7.7 (trigger-webhook bypass regression) is deferred to P1.3 because it
needs a plugin code touchpoint to assert against. §7.8 is acceptance-criteria
mapping (a checklist), not test code.
"""

from __future__ import annotations

import http.client
import io
import socket
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from plugin import ssrf  # noqa: E402


# ---------- helpers ----------

def _gai_returning(*ips, family=socket.AF_INET):
    """Build a fake socket.getaddrinfo that returns the given IPs.

    Each call increments the captured counter so tests can assert how many
    DNS lookups happened.
    """
    counter = {"calls": 0}

    def fake(host, port, *args, **kwargs):
        counter["calls"] += 1
        return [
            (family, socket.SOCK_STREAM, 0, "", (ip, port))
            for ip in ips
        ]

    fake.counter = counter
    return fake


def _gai_mixed(public_ip, private_ip):
    """getaddrinfo returning both v4 results in declared order (public then private)."""
    counter = {"calls": 0}

    def fake(host, port, *args, **kwargs):
        counter["calls"] += 1
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", (public_ip, port)),
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", (private_ip, port)),
        ]

    fake.counter = counter
    return fake


# =====================================================================
# §7.1 — Direct IP literal cases
# =====================================================================

@pytest.mark.parametrize("url", [
    "http://127.0.0.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://10.0.0.1/",
    "http://100.64.0.1/",
    "http://198.18.0.1/",
    "http://[::1]/",
    "http://[::ffff:127.0.0.1]/",     # IPv4-mapped IPv6 → normalized to v4 (D8)
    "http://[64:ff9b::1]/",            # NAT64 explicit block
    "http://[fe80::1]/",               # IPv6 link-local
    "http://[fc00::1]/",               # IPv6 ULA
    "http://[::]/",                    # IPv6 unspecified
    "http://0.0.0.0/",                 # IPv4 unspecified
    "http://255.255.255.255/",         # IPv4 limited broadcast
    "http://224.0.0.1/",               # IPv4 multicast
    "http://[ff00::1]/",               # IPv6 multicast
    "http://240.0.0.1/",               # IPv4 reserved
])
def test_71_blocked_ip_literals_raise_ssrf_blocked(url):
    with pytest.raises(ssrf.SSRFBlocked):
        ssrf.validate_outbound_url(url, allow_unconfigured=True)


@pytest.mark.parametrize("url", [
    "http://0177.0.0.1/",     # octal first octet → 127.0.0.1
    "http://0x7f.0.0.1/",     # hex first octet → 127.0.0.1
    "http://2130706433/",     # 32-bit integer → 127.0.0.1
    "http://127.1/",           # short-form IPv4 → 127.0.0.1
])
def test_71_ipv4_canonicalization_blocks_loopback_in_disguise(url):
    """Validator must canonicalize IPv4 forms before blocklist."""
    with pytest.raises(ssrf.SSRFBlocked):
        ssrf.validate_outbound_url(url, allow_unconfigured=True)


def test_71_public_ip_literal_passes():
    target = ssrf.validate_outbound_url(
        "http://93.184.216.34/", allow_unconfigured=True
    )
    assert target.pinned_ip == "93.184.216.34"
    assert target.scheme == "http"
    assert target.port == 80
    assert target.is_ipv6 is False


def test_71_unsupported_scheme_raises():
    with pytest.raises(ssrf.SSRFBlocked):
        ssrf.validate_outbound_url("file:///etc/passwd", allow_unconfigured=True)


def test_71_missing_host_raises():
    with pytest.raises(ssrf.SSRFBlocked):
        ssrf.validate_outbound_url("http:///path", allow_unconfigured=True)


@pytest.mark.parametrize("url", [
    "http://[::1",                   # unclosed bracket
    "http://[::ffff:999.1.1.1]/",    # invalid v6 contents (octet > 255)
    "http://[not-an-ip]/",           # garbage in brackets
    "http://[]/",                    # empty brackets
    "http://[::g]/",                 # invalid v6 chars
])
def test_71_malformed_bracketed_ipv6_rejected(url):
    """urlparse / .hostname raise ValueError on malformed
    bracketed IPv6 in Python 3.11+. Validator must convert to SSRFBlocked
    so callers see a single rejection type for unusable URLs."""
    with pytest.raises(ssrf.SSRFBlocked):
        ssrf.validate_outbound_url(url, allow_unconfigured=True)


def test_71_userinfo_url_rejected_before_dns(monkeypatch):
    """Validator rejects user:pass@host before any DNS lookup,
    so credentials never enter canonical_url, logs, or exception messages."""
    fake = _gai_returning("93.184.216.34")
    monkeypatch.setattr(socket, "getaddrinfo", fake)
    with pytest.raises(ssrf.SSRFBlocked):
        ssrf.validate_outbound_url(
            "http://user:pass@example.com/", allow_unconfigured=True
        )
    assert fake.counter["calls"] == 0


def test_71_userinfo_user_only_rejected():
    with pytest.raises(ssrf.SSRFBlocked):
        ssrf.validate_outbound_url(
            "http://user@example.com/", allow_unconfigured=True
        )


# =====================================================================
# §7.2 — Hostname resolution
# =====================================================================

def test_72_hostname_resolves_to_private_blocked(monkeypatch):
    fake = _gai_returning("10.0.0.5")
    monkeypatch.setattr(socket, "getaddrinfo", fake)
    with pytest.raises(ssrf.SSRFBlocked):
        ssrf.validate_outbound_url(
            "http://internal.example.com/", allow_unconfigured=True
        )
    assert fake.counter["calls"] == 1


def test_72_hostname_resolves_to_mixed_blocked(monkeypatch):
    """Any blocked address in the resolved set rejects the URL."""
    fake = _gai_mixed("93.184.216.34", "10.0.0.5")
    monkeypatch.setattr(socket, "getaddrinfo", fake)
    with pytest.raises(ssrf.SSRFBlocked):
        ssrf.validate_outbound_url(
            "http://mixed.example.com/", allow_unconfigured=True
        )


def test_72_hostname_resolves_to_public_succeeds(monkeypatch):
    fake = _gai_returning("93.184.216.34")
    monkeypatch.setattr(socket, "getaddrinfo", fake)
    target = ssrf.validate_outbound_url(
        "http://example.com/", allow_unconfigured=True
    )
    assert target.hostname == "example.com"
    assert target.pinned_ip == "93.184.216.34"
    assert fake.counter["calls"] == 1


def test_72_gaierror_raises_dns_resolution_failed(monkeypatch):
    def fake(*args, **kwargs):
        raise socket.gaierror("[Errno -2] Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    with pytest.raises(ssrf.DNSResolutionFailed):
        ssrf.validate_outbound_url(
            "http://nope.invalid/", allow_unconfigured=True
        )


def test_72_idn_hostname_idna_encodes_then_resolves(monkeypatch):
    """IDN should be IDNA-encoded, then resolution proceeds normally (D9)."""
    seen_hosts = []

    def fake(host, port, *args, **kwargs):
        seen_hosts.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    target = ssrf.validate_outbound_url(
        "http://пример.рф/", allow_unconfigured=True
    )
    # Validator must hand getaddrinfo the punycode form, not raw Unicode
    assert seen_hosts == ["xn--e1afmkfd.xn--p1ai"]
    assert target.hostname == "xn--e1afmkfd.xn--p1ai"


def test_72_unconfigured_hostname_does_not_dns_resolve(monkeypatch):
    """Unconfigured hostnames must fail before getaddrinfo to
    close the DNS-egress side channel. Even an attacker-supplied hostname
    must produce zero outbound DNS lookups."""
    fake = _gai_returning("93.184.216.34")
    monkeypatch.setattr(socket, "getaddrinfo", fake)
    with pytest.raises(ssrf.UnconfiguredURL):
        ssrf.validate_outbound_url(
            "http://attacker.example.com/",
            allow_unconfigured=False,
            is_configured_friend=False,
        )
    assert fake.counter["calls"] == 0


def test_72_idn_canonical_url_is_punycode_ascii(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", _gai_returning("93.184.216.34")
    )
    target = ssrf.validate_outbound_url(
        "http://пример.рф/path?x=1", allow_unconfigured=True
    )
    assert target.canonical_url == "http://xn--e1afmkfd.xn--p1ai/path?x=1"
    target.canonical_url.encode("ascii")  # smoke: pure ASCII


def test_72_idn_canonical_url_dials_pinned_ip_and_preserves_sni(monkeypatch):
    """End-to-end: opener.open(target.canonical_url) on an IDN URL must
    dial the pinned IP without UnicodeEncodeError, and TLS SNI must be
    the punycode hostname (not the original Unicode)."""
    monkeypatch.setattr(
        socket, "getaddrinfo", _gai_returning("93.184.216.34")
    )

    captured = []

    def fake_create_connection(addr, *args, **kwargs):
        captured.append(addr)
        return MagicMock(spec=socket.socket)

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)

    fake_wrap = MagicMock(side_effect=OSError("stop after SNI"))
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", fake_wrap)

    target = ssrf.validate_outbound_url(
        "https://пример.рф/path?x=1", allow_unconfigured=True
    )
    assert target.canonical_url == "https://xn--e1afmkfd.xn--p1ai/path?x=1"

    opener = ssrf.build_ssrf_opener(target)
    with pytest.raises(urllib.error.URLError):
        opener.open(target.canonical_url)

    assert captured == [("93.184.216.34", 443)]
    assert fake_wrap.call_args.kwargs["server_hostname"] == "xn--e1afmkfd.xn--p1ai"


def test_72_idn_failing_idna_raises_ssrf_blocked():
    """A hostname that cannot IDNA-encode must be rejected (D9)."""
    # Trailing-dot label that is also otherwise invalid → IDNA failure.
    # Easier guaranteed failure: a label that exceeds 63 chars after encoding.
    # Use a hostname containing a NULL byte alternative — Python's idna codec
    # rejects empty labels. ".." gives empty middle label.
    with pytest.raises(ssrf.SSRFBlocked):
        ssrf.validate_outbound_url("http://..invalid/", allow_unconfigured=True)


# =====================================================================
# §7.3 — Override cases (allow_private, allow_unconfigured, env gate)
# =====================================================================

def test_73_private_ip_with_allow_private_succeeds():
    target = ssrf.validate_outbound_url(
        "http://10.0.0.5/",
        allow_private=True,
        is_configured_friend=True,
    )
    assert target.pinned_ip == "10.0.0.5"


def test_73_unconfigured_public_without_allow_unconfigured_raises():
    target_url = "http://93.184.216.34/"
    with pytest.raises(ssrf.UnconfiguredURL):
        ssrf.validate_outbound_url(
            target_url,
            allow_unconfigured=False,
            is_configured_friend=False,
        )


def test_73_unconfigured_public_with_allow_unconfigured_succeeds():
    target = ssrf.validate_outbound_url(
        "http://93.184.216.34/", allow_unconfigured=True
    )
    assert target.pinned_ip == "93.184.216.34"


def test_73_is_configured_friend_short_circuits_unconfigured_check():
    target = ssrf.validate_outbound_url(
        "http://93.184.216.34/",
        allow_unconfigured=False,
        is_configured_friend=True,
    )
    assert target.pinned_ip == "93.184.216.34"


def test_73_allow_private_with_hostname_rejected_before_dns(monkeypatch):
    """Explicit per-friend `allow_private=True` is IP-literal-only
    at the validator API. Hostname inputs must be rejected before any DNS
    lookup, regardless of whether the resolved address would be private."""
    fake = _gai_returning("10.0.0.5")
    monkeypatch.setattr(socket, "getaddrinfo", fake)
    with pytest.raises(ssrf.SSRFBlocked):
        ssrf.validate_outbound_url(
            "http://internal.example.com/",
            allow_private=True,
            allow_unconfigured=True,
        )
    assert fake.counter["calls"] == 0


def test_73_unconfigured_check_runs_after_block_check():
    """SSRFBlocked takes priority over UnconfiguredURL for private literals."""
    with pytest.raises(ssrf.SSRFBlocked):
        ssrf.validate_outbound_url(
            "http://10.0.0.5/",
            allow_private=False,
            allow_unconfigured=False,
            is_configured_friend=False,
        )


# --- env gate matrix ---

def test_73_env_set_no_dev_gate_rejects(monkeypatch):
    monkeypatch.setenv("A2A_ALLOW_PRIVATE_NETWORKS", "true")
    monkeypatch.delenv("A2A_ENV", raising=False)
    with pytest.raises(ssrf.SSRFBlocked):
        ssrf.validate_outbound_url(
            "http://10.0.0.5/", allow_unconfigured=True
        )


def test_73_env_set_production_a2aenv_rejects(monkeypatch):
    monkeypatch.setenv("A2A_ALLOW_PRIVATE_NETWORKS", "true")
    monkeypatch.setenv("A2A_ENV", "production")
    with pytest.raises(ssrf.SSRFBlocked):
        ssrf.validate_outbound_url(
            "http://10.0.0.5/", allow_unconfigured=True
        )


def test_73_env_set_dev_a2aenv_succeeds(monkeypatch):
    monkeypatch.setenv("A2A_ALLOW_PRIVATE_NETWORKS", "true")
    monkeypatch.setenv("A2A_ENV", "dev")
    target = ssrf.validate_outbound_url(
        "http://10.0.0.5/", allow_unconfigured=True
    )
    assert target.pinned_ip == "10.0.0.5"


def test_73_env_set_test_a2aenv_succeeds(monkeypatch):
    monkeypatch.setenv("A2A_ALLOW_PRIVATE_NETWORKS", "true")
    monkeypatch.setenv("A2A_ENV", "test")
    target = ssrf.validate_outbound_url(
        "http://10.0.0.5/", allow_unconfigured=True
    )
    assert target.pinned_ip == "10.0.0.5"


def test_73_env_unset_dev_a2aenv_rejects(monkeypatch):
    """A2A_ENV alone, without the var, does nothing."""
    monkeypatch.delenv("A2A_ALLOW_PRIVATE_NETWORKS", raising=False)
    monkeypatch.setenv("A2A_ENV", "dev")
    with pytest.raises(ssrf.SSRFBlocked):
        ssrf.validate_outbound_url(
            "http://10.0.0.5/", allow_unconfigured=True
        )


def test_73_log_env_state_warns_in_dev(monkeypatch, caplog):
    monkeypatch.setenv("A2A_ALLOW_PRIVATE_NETWORKS", "true")
    monkeypatch.setenv("A2A_ENV", "dev")
    with caplog.at_level("WARNING", logger="plugin.ssrf"):
        ssrf.log_env_state()
    assert any("effective" in r.message for r in caplog.records)
    assert all(r.levelname == "WARNING" for r in caplog.records)


def test_73_log_env_state_errors_in_prod(monkeypatch, caplog):
    monkeypatch.setenv("A2A_ALLOW_PRIVATE_NETWORKS", "true")
    monkeypatch.setenv("A2A_ENV", "production")
    with caplog.at_level("ERROR", logger="plugin.ssrf"):
        ssrf.log_env_state()
    assert any("IGNORED" in r.message for r in caplog.records)
    assert all(r.levelname == "ERROR" for r in caplog.records)


def test_73_log_env_state_silent_when_unset(monkeypatch, caplog):
    monkeypatch.delenv("A2A_ALLOW_PRIVATE_NETWORKS", raising=False)
    with caplog.at_level("WARNING", logger="plugin.ssrf"):
        ssrf.log_env_state()
    assert caplog.records == []


# =====================================================================
# §7.4 — DNS pin: rebinding + integration + proxy bypass
# =====================================================================

def test_74_pinning_freezes_first_resolved_ip(monkeypatch):
    """Two getaddrinfo calls in sequence return different IPs; the validator
    pins the first; second resolution would be unsafe but never happens at
    connect because the connection class uses the pinned IP, not getaddrinfo."""
    call_log = []

    def fake_gai(host, port, *args, **kwargs):
        call_log.append(host)
        if len(call_log) == 1:
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", port))]
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("169.254.169.254", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_gai)

    target = ssrf.validate_outbound_url(
        "http://example.com/", allow_unconfigured=True
    )
    assert target.pinned_ip == "93.184.216.34"

    create_connection_addrs = []

    def fake_create_connection(addr, *args, **kwargs):
        create_connection_addrs.append(addr)
        # Return a fake socket; we are not running the rest of the request.
        return MagicMock()

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)

    conn = ssrf._PinnedHTTPConnection(
        target.hostname, port=target.port, pinned_ip=target.pinned_ip
    )
    conn.connect()

    assert create_connection_addrs == [("93.184.216.34", 80)]
    # Crucial: connect() did NOT trigger another getaddrinfo
    assert call_log == ["example.com"]


def test_74_https_connect_uses_pinned_ip_and_preserves_sni(monkeypatch):
    """D2 gates a + b, asserted directly on the HTTPS connection class."""
    captured = {}

    def fake_create_connection(addr, *args, **kwargs):
        captured["create_addr"] = addr
        return MagicMock(spec=socket.socket)

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)

    fake_context = MagicMock(spec=ssl.SSLContext)
    fake_context.wrap_socket.return_value = MagicMock(spec=ssl.SSLSocket)

    conn = ssrf._PinnedHTTPSConnection(
        "example.com",
        port=443,
        pinned_ip="93.184.216.34",
        context=fake_context,
    )
    conn.connect()

    # D2 gate (a): create_connection dialed pinned IP, not hostname
    assert captured["create_addr"] == ("93.184.216.34", 443)
    # D2 gate (b): wrap_socket was given original hostname for SNI
    assert fake_context.wrap_socket.call_args.kwargs["server_hostname"] == "example.com"


def test_74_opener_routes_to_pinned_ip_via_create_connection(monkeypatch):
    """Integration: opener.open() actually goes through our PinnedConnection."""
    monkeypatch.setattr(
        socket, "getaddrinfo", _gai_returning("93.184.216.34")
    )

    create_addrs = []

    def fake_create_connection(addr, *args, **kwargs):
        create_addrs.append(addr)
        raise OSError("test stop after capture")

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)

    target = ssrf.validate_outbound_url(
        "http://example.com/path", allow_unconfigured=True
    )
    opener = ssrf.build_ssrf_opener(target)

    with pytest.raises(urllib.error.URLError):
        opener.open("http://example.com/path")

    assert create_addrs == [("93.184.216.34", 80)]


def test_74_no_second_getaddrinfo_after_validation(monkeypatch):
    """D2 gate (c): zero DNS lookups happen between validate and connect."""
    gai_calls = {"n": 0}

    def fake_gai(host, port, *args, **kwargs):
        gai_calls["n"] += 1
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_gai)

    target = ssrf.validate_outbound_url(
        "http://example.com/", allow_unconfigured=True
    )
    assert gai_calls["n"] == 1

    monkeypatch.setattr(
        socket, "create_connection",
        lambda *a, **k: (_ for _ in ()).throw(OSError("stop")),
    )

    opener = ssrf.build_ssrf_opener(target)
    with pytest.raises(urllib.error.URLError):
        opener.open("http://example.com/")

    assert gai_calls["n"] == 1, "connect must NOT trigger a second getaddrinfo"


def test_74_https_proxy_env_does_not_reroute(monkeypatch):
    """ProxyHandler({}) must defeat env-var proxies.

    With HTTPS_PROXY set, default urllib would dial proxy.example.com:8080.
    Our opener must still dial the target's pinned IP.
    """
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example.com:8080")
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.example.com:8080")
    monkeypatch.setenv("NO_PROXY", "")

    monkeypatch.setattr(
        socket, "getaddrinfo", _gai_returning("93.184.216.34")
    )

    captured = []

    def fake_create_connection(addr, *args, **kwargs):
        captured.append(addr)
        return MagicMock(spec=socket.socket)

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)

    fake_wrap = MagicMock(side_effect=OSError("stop after SNI"))
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", fake_wrap)

    target = ssrf.validate_outbound_url(
        "https://example.com/", allow_unconfigured=True
    )
    opener = ssrf.build_ssrf_opener(target)

    with pytest.raises(urllib.error.URLError):
        opener.open("https://example.com/")

    assert captured == [("93.184.216.34", 443)], (
        f"connection went to {captured!r} — proxy bypass failed"
    )
    # SNI also preserved through the proxy-disabled opener
    assert fake_wrap.call_args.kwargs["server_hostname"] == "example.com"


def test_74_no_proxy_wildcard_irrelevant(monkeypatch):
    """Sanity: NO_PROXY=* should be moot once proxies are hard-disabled."""
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example.com:8080")
    monkeypatch.setenv("NO_PROXY", "*")
    monkeypatch.setattr(
        socket, "getaddrinfo", _gai_returning("93.184.216.34")
    )
    captured = []
    monkeypatch.setattr(
        socket, "create_connection",
        lambda addr, *a, **k: captured.append(addr) or MagicMock(spec=socket.socket),
    )
    monkeypatch.setattr(
        ssl.SSLContext, "wrap_socket",
        MagicMock(side_effect=OSError("stop")),
    )

    target = ssrf.validate_outbound_url(
        "https://example.com/", allow_unconfigured=True
    )
    opener = ssrf.build_ssrf_opener(target)
    with pytest.raises(urllib.error.URLError):
        opener.open("https://example.com/")
    assert captured == [("93.184.216.34", 443)]


# =====================================================================
# §7.6 — Redirect handler raises RedirectBlocked
# =====================================================================

@pytest.mark.parametrize("code,method", [
    (301, "http_error_301"),
    (302, "http_error_302"),
    (303, "http_error_303"),
    (307, "http_error_307"),
    (308, "http_error_308"),
])
def test_76_redirect_handler_raises_redirect_blocked(code, method):
    handler = ssrf._NoRedirectHandler()
    req = urllib.request.Request("http://example.com/")
    fp = io.BytesIO()
    headers = http.client.HTTPMessage()
    with pytest.raises(ssrf.RedirectBlocked):
        getattr(handler, method)(req, fp, code, "redirect", headers)


def test_76_opener_chain_includes_no_redirect_handler():
    """Sanity: build_ssrf_opener inserts our redirect handler.

    Per-status-code raise behavior is exhaustively covered by the parametrized
    test above. This test pins down opener composition so a future change that
    drops _NoRedirectHandler from the chain would fail loudly.
    """
    http_target = ssrf.PinnedTarget(
        hostname="example.com", port=80, scheme="http",
        pinned_ip="93.184.216.34", is_ipv6=False,
        canonical_url="http://example.com/",
    )
    https_target = ssrf.PinnedTarget(
        hostname="example.com", port=443, scheme="https",
        pinned_ip="93.184.216.34", is_ipv6=False,
        canonical_url="https://example.com/",
    )
    http_opener = ssrf.build_ssrf_opener(http_target)
    https_opener = ssrf.build_ssrf_opener(https_target)

    assert any(isinstance(h, ssrf._NoRedirectHandler) for h in http_opener.handlers)
    assert any(isinstance(h, ssrf._NoRedirectHandler) for h in https_opener.handlers)
    assert any(isinstance(h, ssrf._PinnedHTTPHandler) for h in http_opener.handlers)
    assert any(isinstance(h, ssrf._PinnedHTTPSHandler) for h in https_opener.handlers)
    # Proxy bypass: urllib's build_opener strips ProxyHandler({}) entirely
    # because empty-proxies registers no *_open methods. Net effect = no proxy
    # logic in the chain at all (proven by test_74_https_proxy_env_does_not_reroute).
    assert not any(
        isinstance(h, urllib.request.ProxyHandler) for h in http_opener.handlers
    )


# =====================================================================
# §7.9 — canonical_url contract
#
# P1.3 callsites MUST hand `target.canonical_url` to opener.open(); never
# the raw input URL. Form: scheme://host[:port]/path[?query] — punycode
# for IDN, brackets for IPv6 literals, default ports (80/443) elided,
# userinfo and fragment never present.
# =====================================================================

def test_79_canonical_url_ascii_hostname_default_port_elided(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", _gai_returning("93.184.216.34")
    )
    target = ssrf.validate_outbound_url(
        "https://example.com/", allow_unconfigured=True
    )
    assert target.canonical_url == "https://example.com/"


def test_79_canonical_url_keeps_non_default_port(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", _gai_returning("93.184.216.34")
    )
    target = ssrf.validate_outbound_url(
        "https://example.com:8443/p", allow_unconfigured=True
    )
    assert target.canonical_url == "https://example.com:8443/p"


def test_79_canonical_url_drops_fragment(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", _gai_returning("93.184.216.34")
    )
    target = ssrf.validate_outbound_url(
        "http://example.com/p?x=1#frag", allow_unconfigured=True
    )
    assert target.canonical_url == "http://example.com/p?x=1"
    assert "#" not in target.canonical_url


def test_79_canonical_url_empty_path_normalized_to_slash(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", _gai_returning("93.184.216.34")
    )
    target = ssrf.validate_outbound_url(
        "http://example.com", allow_unconfigured=True
    )
    assert target.canonical_url == "http://example.com/"


def test_79_canonical_url_ipv4_literal():
    target = ssrf.validate_outbound_url(
        "http://93.184.216.34/p?q=1", allow_unconfigured=True
    )
    assert target.canonical_url == "http://93.184.216.34/p?q=1"


def test_79_canonical_url_ipv6_literal_brackets():
    target = ssrf.validate_outbound_url(
        "https://[2606:4700:4700::1111]/p", allow_unconfigured=True
    )
    assert target.canonical_url == "https://[2606:4700:4700::1111]/p"


def test_79_canonical_url_ipv4_mapped_ipv6_normalized_to_v4():
    """IPv4-mapped IPv6 (`::ffff:a.b.c.d`) collapses to its IPv4 form (D8),
    so canonical_url has no brackets."""
    target = ssrf.validate_outbound_url(
        "http://[::ffff:8.8.8.8]/", allow_unconfigured=True
    )
    assert target.canonical_url == "http://8.8.8.8/"


def test_79_canonical_url_percent_encodes_unicode_path(monkeypatch):
    """Non-ASCII path must be percent-encoded so canonical_url
    is safe to hand to http.client / opener.open."""
    monkeypatch.setattr(
        socket, "getaddrinfo", _gai_returning("93.184.216.34")
    )
    target = ssrf.validate_outbound_url(
        "http://example.com/路径", allow_unconfigured=True
    )
    assert target.canonical_url == "http://example.com/%E8%B7%AF%E5%BE%84"
    target.canonical_url.encode("ascii")  # smoke


def test_79_canonical_url_percent_encodes_unicode_query(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", _gai_returning("93.184.216.34")
    )
    target = ssrf.validate_outbound_url(
        "http://example.com/p?x=é", allow_unconfigured=True
    )
    assert target.canonical_url == "http://example.com/p?x=%C3%A9"
    target.canonical_url.encode("ascii")


def test_79_canonical_url_preserves_existing_percent_encoding(monkeypatch):
    """Already-encoded inputs must not be double-encoded (`%20` stays `%20`,
    not `%2520`)."""
    monkeypatch.setattr(
        socket, "getaddrinfo", _gai_returning("93.184.216.34")
    )
    target = ssrf.validate_outbound_url(
        "http://example.com/foo%20bar?q=a%26b", allow_unconfigured=True
    )
    assert target.canonical_url == "http://example.com/foo%20bar?q=a%26b"


def test_79_canonical_url_unicode_path_opener_dials_pinned_ip(monkeypatch):
    """End-to-end: opener.open(target.canonical_url) on a URL with a
    Unicode path must succeed (no UnicodeEncodeError) and dial the pinned
    IP. Without percent-encoding, http.client raises during request line
    serialization."""
    monkeypatch.setattr(
        socket, "getaddrinfo", _gai_returning("93.184.216.34")
    )

    captured = []

    def fake_create_connection(addr, *args, **kwargs):
        captured.append(addr)
        raise OSError("stop after capture")

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)

    target = ssrf.validate_outbound_url(
        "http://example.com/路径?x=é", allow_unconfigured=True
    )
    opener = ssrf.build_ssrf_opener(target)
    with pytest.raises(urllib.error.URLError):
        opener.open(target.canonical_url)

    assert captured == [("93.184.216.34", 80)]
