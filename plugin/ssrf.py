"""SSRF validator + DNS-pinned outbound HTTP for the A2A plugin.

Public surface (consumed by P1.3 callsites in tools.py / friends.py):

    validate_outbound_url(url, *, allow_private, allow_unconfigured,
                          is_configured_friend) -> PinnedTarget

    build_ssrf_opener(target) -> urllib.request.OpenerDirector

    is_env_private_allowed() -> bool
    log_env_state() -> None

    PinnedTarget, SSRFBlocked, UnconfiguredURL,
    DNSResolutionFailed, RedirectBlocked

Implements the public-preview SSRF policy. Callsite wiring lives in the A2A
tool and friend-management paths.
"""

from __future__ import annotations

import http.client
import ipaddress
import logging
import os
import socket
import ssl
import urllib.request
from dataclasses import dataclass
from typing import Optional, Union
from urllib.parse import quote, urlparse

logger = logging.getLogger(__name__)

_PRIVATE_NETWORK_ENV = "A2A_ALLOW_PRIVATE_NETWORKS"
_DEV_ENV = "A2A_ENV"
_DEV_ENV_VALUES = frozenset({"dev", "test"})
_TRUE_VALUES = frozenset({"1", "true", "yes"})

# Explicit IPv6 blocks that Python's is_global misses (NAT64 reports
# is_global=True; multicast handled via is_multicast below).
_EXPLICIT_BLOCK_V6 = (ipaddress.ip_network("64:ff9b::/96"),)

_IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


# ---------- exceptions ----------

class SSRFBlocked(Exception):
    """Outbound URL targets a non-global / multicast / NAT64 / blocked IP."""


class UnconfiguredURL(Exception):
    """Caller did not assert allow_unconfigured / is_configured_friend."""


class DNSResolutionFailed(Exception):
    """Hostname could not be resolved."""


class RedirectBlocked(Exception):
    """3xx redirect attempted; redirects are not followed in v1 (D3)."""


# ---------- public dataclass ----------

@dataclass(frozen=True)
class PinnedTarget:
    """Resolved outbound target with its DNS pinned to a single IP.

    `hostname` is the post-IDNA ASCII form used for Host header + TLS SNI.
    `pinned_ip` is the address the connection layer must dial. When the
    URL was an IP literal, hostname and pinned_ip are the same string.

    `canonical_url` is the URL that callsites MUST hand to opener.open().
    It is the post-IDNA, userinfo-stripped, fragment-stripped form of the
    input URL — passing the original URL to opener.open() can desync
    SNI/Host from the validated host.
    """

    hostname: str
    port: int
    scheme: str
    pinned_ip: str
    is_ipv6: bool
    canonical_url: str


# ---------- env gate (§5) ----------

def _is_dev_env() -> bool:
    return os.getenv(_DEV_ENV, "").lower() in _DEV_ENV_VALUES


def is_env_private_allowed() -> bool:
    """True iff A2A_ALLOW_PRIVATE_NETWORKS is set AND the dev gate is satisfied.

    The env var is a dev/test escape hatch only; production cannot enable it.
    """
    if os.getenv(_PRIVATE_NETWORK_ENV, "").lower() not in _TRUE_VALUES:
        return False
    return _is_dev_env()


def log_env_state() -> None:
    """One-shot startup log per §5. Callers (plugin init in P1.3) invoke this once.

    - WARNING when env var is effective (dev/test gate satisfied).
    - ERROR when env var is set but the gate is not satisfied (production
      misconfig — the var is ignored but the operator should know).
    """
    raw = os.getenv(_PRIVATE_NETWORK_ENV, "")
    if raw.lower() not in _TRUE_VALUES:
        return
    if _is_dev_env():
        logger.warning(
            "%s=%s is effective (dev gate satisfied via %s=%s); private-network "
            "outbound will not be blocked. Do not set this in production.",
            _PRIVATE_NETWORK_ENV, raw, _DEV_ENV, os.getenv(_DEV_ENV, ""),
        )
    else:
        logger.error(
            "%s=%s is set but %s is not in {dev,test}; the env var is being IGNORED. "
            "Use the per-add `--allow-private-url --reason` flow instead.",
            _PRIVATE_NETWORK_ENV, raw, _DEV_ENV,
        )


# ---------- IP parsing + normalization ----------

def _normalize_addr(addr: _IPAddress) -> _IPAddress:
    """Collapse IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to its IPv4 form (D8)."""
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _build_canonical_url(
    *,
    scheme: str,
    canonical_host: str,
    port: int,
    is_ipv6: bool,
    path: str,
    query: str,
) -> str:
    """Return an opener-ready URL form.

    `scheme://host[:port]/path[?query]`. IPv6 hosts bracketed; default
    ports (80/443) elided; userinfo and fragment never present (validator
    rejects userinfo upstream; fragment is not sent on the wire and is
    dropped here so callsites cannot accidentally embed it in logs).
    """
    host_part = f"[{canonical_host}]" if is_ipv6 else canonical_host
    default_port = 443 if scheme == "https" else 80
    netloc = host_part if port == default_port else f"{host_part}:{port}"
    # Percent-encode non-ASCII / unsafe chars in path + query so the result
    # is pure ASCII. Without this, a URL like `http://example.com/路径?x=é`
    # produces a Unicode canonical_url that http.client cannot serialize.
    # `safe` keeps existing %xx escapes from being double-encoded, and
    # preserves the structural delimiters of each component.
    encoded_path = quote(path, safe="/%") if path else "/"
    url = f"{scheme}://{netloc}{encoded_path}"
    if query:
        url += f"?{quote(query, safe='=&%+')}"
    return url


def normalize_target_url(url: str) -> str:
    """Return the normalized scheme://host:port approval target for ``url``.

    This intentionally ignores path/query/fragment. It is used by P1.3
    callsites to bind a private-network approval to the exact transport
    target (scheme + host + port), separate from the request URL sent over
    HTTP.
    """
    try:
        parsed = urlparse(url)
        raw_host = parsed.hostname
    except ValueError as e:
        raise SSRFBlocked(f"malformed URL: {e}") from e
    if parsed.scheme not in ("http", "https"):
        raise SSRFBlocked(f"unsupported scheme: {parsed.scheme!r}")
    if not raw_host:
        raise SSRFBlocked("URL has no host")
    try:
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
    except ValueError as e:
        raise SSRFBlocked(f"port out of range: {e}") from e
    if not (1 <= port <= 65535):
        raise SSRFBlocked(f"port out of range: {port}")

    literal = _try_parse_ip_literal(raw_host)
    if literal is not None:
        normalized = _normalize_addr(literal)
        host = str(normalized)
        is_ipv6 = isinstance(normalized, ipaddress.IPv6Address)
    else:
        try:
            host = raw_host.encode("idna").decode("ascii")
        except UnicodeError as e:
            raise SSRFBlocked(f"IDNA encoding failed for {raw_host!r}: {e}") from e
        is_ipv6 = False
    host_part = f"[{host}]" if is_ipv6 else host
    return f"{parsed.scheme}://{host_part}:{port}"


def is_ip_literal_url(url: str) -> bool:
    """Whether ``url`` has an IP-literal host after parser normalization."""
    try:
        parsed = urlparse(url)
        raw_host = parsed.hostname
    except ValueError:
        return False
    return bool(raw_host and _try_parse_ip_literal(raw_host) is not None)


def _try_parse_ip_literal(host: str) -> Optional[_IPAddress]:
    """Return an IPAddress if `host` is an IP literal (any form), else None.

    Handles canonical IPv4 / IPv6, plus non-canonical IPv4 (octal `0177.0.0.1`,
    hex `0x7f.0.0.1`, 32-bit integer `2130706433`, short-form `127.1`) via
    socket.inet_aton — required by §3.3 IPv4 canonicalization.
    """
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    try:
        packed = socket.inet_aton(host)
    except OSError:
        return None
    return ipaddress.IPv4Address(packed)


def _is_blocked(addr: _IPAddress) -> bool:
    """Deny-by-default policy (§3.3).

    Block if any of:
    - `addr.is_global` is False (loopback, private, link-local, unspecified,
      reserved, CGNAT, benchmark — Python's is_global covers these),
    - the address is multicast (Python reports is_global=True for both
      IPv4 224.0.0.0/4 and IPv6 ff00::/8 even though they must not egress),
    - the address falls in an explicit deny range (NAT64 64:ff9b::/96 —
      Python reports is_global=True).
    """
    if not addr.is_global:
        return True
    if addr.is_multicast:
        return True
    if isinstance(addr, ipaddress.IPv6Address):
        if any(addr in net for net in _EXPLICIT_BLOCK_V6):
            return True
    return False


# ---------- main validator ----------

def validate_outbound_url(
    url: str,
    *,
    allow_private: bool = False,
    allow_unconfigured: bool = False,
    is_configured_friend: bool = False,
    allow_env_private: bool = True,
) -> PinnedTarget:
    """Validate `url` for SSRF and return a DNS-pinned target.

    Raises:
        SSRFBlocked: on non-global resolved IP (or all resolved IPs, when
            multiple) without `allow_private`. Also raised on bad scheme,
            missing host, port out of range, or IDNA failure.
        UnconfiguredURL: when neither `allow_unconfigured` nor
            `is_configured_friend` is true.
        DNSResolutionFailed: when hostname resolution fails.

    `allow_private=True` (per-friend approval) lifts the non-global block.
    `allow_env_private=True` additionally allows the dev/test env escape hatch
    for explicit direct-dev callsites only.
    """
    effective_allow_private = allow_private or (allow_env_private and is_env_private_allowed())

    # Step 1: parse + scheme + userinfo + port
    # Malformed bracketed IPv6 (`http://[::1`, `http://[::g]/`,
    # `http://[::ffff:999.1.1.1]/`, empty brackets) raises ValueError from
    # urlparse / .hostname on Python 3.11+. Normalize to SSRFBlocked so
    # callers see a single rejection type for unusable URLs.
    try:
        parsed = urlparse(url)
        raw_host = parsed.hostname
    except ValueError as e:
        raise SSRFBlocked(f"malformed URL: {e}") from e
    if parsed.scheme not in ("http", "https"):
        raise SSRFBlocked(f"unsupported scheme: {parsed.scheme!r}")
    if parsed.username is not None or parsed.password is not None:
        # A2A outbound does not support `user:pass@host` auth. Rejecting at
        # the validator keeps credentials out of canonical_url, logs, and
        # exception messages.
        raise SSRFBlocked("URL must not contain userinfo")
    if not raw_host:
        raise SSRFBlocked("URL has no host")
    try:
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
    except ValueError as e:
        raise SSRFBlocked(f"port out of range: {e}") from e
    if not (1 <= port <= 65535):
        raise SSRFBlocked(f"port out of range: {port}")

    # Step 2: detect IP literal vs hostname FIRST (avoid IDNA on IP literals)
    literal = _try_parse_ip_literal(raw_host)
    if literal is not None:
        return _validate_ip_literal(
            literal,
            scheme=parsed.scheme,
            port=port,
            path=parsed.path,
            query=parsed.query,
            effective_allow_private=effective_allow_private,
            allow_unconfigured=allow_unconfigured,
            is_configured_friend=is_configured_friend,
        )

    # Step 3: hostname path — explicit `allow_private=True` is IP-literal-only
    # (per-friend approvals only apply to IP literals). The dev/test env gate
    # is the only path through which a hostname is permitted to resolve to a
    # private address, and even then only because the operator has owned that
    # risk via env vars.
    if allow_private:
        raise SSRFBlocked(
            f"allow_private=True is only valid for IP-literal hosts; got hostname {raw_host!r}"
        )

    # Step 4: IDNA encode (D9)
    try:
        idna_host = raw_host.encode("idna").decode("ascii")
    except UnicodeError as e:
        # Per D9: IDNA failure → SSRFBlocked (cannot meaningfully validate)
        raise SSRFBlocked(f"IDNA encoding failed for {raw_host!r}: {e}") from e

    # Step 5: unconfigured guard BEFORE DNS — refusing to even
    # resolve unconfigured hostnames closes the DNS-egress side channel that
    # would otherwise leak attacker-supplied lookups.
    if not allow_unconfigured and not is_configured_friend:
        raise UnconfiguredURL(f"URL not configured: {url}")

    # Step 6: resolve and block-check
    try:
        results = socket.getaddrinfo(
            idna_host, port, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
    except socket.gaierror as e:
        raise DNSResolutionFailed(f"could not resolve {idna_host!r}: {e}") from e
    if not results:
        raise DNSResolutionFailed(f"no addresses for {idna_host!r}")

    resolved: list[tuple[int, _IPAddress, str]] = []
    for family, _socktype, _proto, _canonname, sockaddr in results:
        ip_str = sockaddr[0]
        try:
            addr = ipaddress.ip_address(ip_str.split("%", 1)[0])  # drop scope-id
        except ValueError:
            # Should not happen — getaddrinfo only returns valid IPs — but
            # defense in depth: refuse to proceed on unparseable resolution.
            raise SSRFBlocked(f"unparseable resolved address: {ip_str!r}")
        normalized = _normalize_addr(addr)
        if _is_blocked(normalized) and not effective_allow_private:
            raise SSRFBlocked(
                f"hostname {idna_host} resolves to blocked address {normalized}"
            )
        resolved.append((family, addr, ip_str))

    # Step 7: pick deterministic pinned IP — prefer IPv4 if available
    ipv4 = next((r for r in resolved if r[0] == socket.AF_INET), None)
    chosen = ipv4 if ipv4 else resolved[0]
    pinned_ip = chosen[2]
    is_ipv6 = chosen[0] == socket.AF_INET6

    return PinnedTarget(
        hostname=idna_host,
        port=port,
        scheme=parsed.scheme,
        pinned_ip=pinned_ip,
        is_ipv6=is_ipv6,
        canonical_url=_build_canonical_url(
            scheme=parsed.scheme,
            canonical_host=idna_host,
            port=port,
            is_ipv6=is_ipv6,
            path=parsed.path,
            query=parsed.query,
        ),
    )


def _validate_ip_literal(
    literal: _IPAddress,
    *,
    scheme: str,
    port: int,
    path: str,
    query: str,
    effective_allow_private: bool,
    allow_unconfigured: bool,
    is_configured_friend: bool,
) -> PinnedTarget:
    normalized = _normalize_addr(literal)
    # Block check stays ahead of unconfigured for IP literals: SSRFBlocked
    # has priority over UnconfiguredURL on private-literal inputs (§7.3).
    if _is_blocked(normalized) and not effective_allow_private:
        raise SSRFBlocked(f"target IP {normalized} is in blocked range")

    if not allow_unconfigured and not is_configured_friend:
        raise UnconfiguredURL(f"URL with literal IP {normalized} not configured")

    pinned_ip = str(normalized)
    is_ipv6 = isinstance(normalized, ipaddress.IPv6Address)
    # Hostname == pinned_ip for literals; Host header is the literal itself.
    return PinnedTarget(
        hostname=pinned_ip,
        port=port,
        scheme=scheme,
        pinned_ip=pinned_ip,
        is_ipv6=is_ipv6,
        canonical_url=_build_canonical_url(
            scheme=scheme,
            canonical_host=pinned_ip,
            port=port,
            is_ipv6=is_ipv6,
            path=path,
            query=query,
        ),
    )


# ---------- pinned http(s) connection classes (§3.4) ----------

class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection that dials a pre-pinned IP instead of re-resolving `host`."""

    def __init__(self, host: str, *args, pinned_ip: str, **kwargs):
        super().__init__(host, *args, **kwargs)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:  # type: ignore[override]
        self.sock = socket.create_connection(
            (self._pinned_ip, self.port),
            timeout=self.timeout,
            source_address=self.source_address,
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that dials pinned IP and keeps original hostname for SNI + Host."""

    def __init__(self, host: str, *args, pinned_ip: str, **kwargs):
        super().__init__(host, *args, **kwargs)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:  # type: ignore[override]
        sock = socket.create_connection(
            (self._pinned_ip, self.port),
            timeout=self.timeout,
            source_address=self.source_address,
        )
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
            sock = self.sock
        # D2 gate (b): server_hostname is the ORIGINAL hostname (self.host),
        # not the pinned IP — preserves TLS SNI + cert verification.
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


# ---------- urllib handlers (§3.4 + §3.5) ----------

class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, pinned_ip: str, debuglevel: int = 0):
        super().__init__(debuglevel=debuglevel)
        self._pinned_ip = pinned_ip

    def http_open(self, req):  # type: ignore[override]
        pinned_ip = self._pinned_ip

        def factory(host, **kwargs):
            return _PinnedHTTPConnection(host, pinned_ip=pinned_ip, **kwargs)

        return self.do_open(factory, req)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(
        self,
        pinned_ip: str,
        debuglevel: int = 0,
        context: Optional[ssl.SSLContext] = None,
    ):
        super().__init__(debuglevel=debuglevel, context=context)
        self._pinned_ip = pinned_ip

    def https_open(self, req):  # type: ignore[override]
        pinned_ip = self._pinned_ip

        def factory(host, **kwargs):
            return _PinnedHTTPSConnection(host, pinned_ip=pinned_ip, **kwargs)

        return self.do_open(factory, req, context=self._context)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse to follow 3xx (D3). Each handler turns redirects into RedirectBlocked."""

    def http_error_301(self, req, fp, code, msg, headers):  # type: ignore[override]
        raise RedirectBlocked(
            f"redirect {code} from {req.full_url!r} blocked (D3: redirects not followed in v1)"
        )

    http_error_302 = http_error_301
    http_error_303 = http_error_301
    http_error_307 = http_error_301
    http_error_308 = http_error_301


# ---------- opener factory ----------

def build_ssrf_opener(
    target: PinnedTarget,
    *,
    context: Optional[ssl.SSLContext] = None,
) -> urllib.request.OpenerDirector:
    """Build a urllib opener wired with:

    - `ProxyHandler({})` — disables HTTPS_PROXY / HTTP_PROXY / NO_PROXY env-var
      proxy resolution. Without this the default opener would route
      through `urllib.request.ProxyHandler`, which constructs its own
      HTTPConnection from the proxy URL and bypasses our pinned-IP subclass.
    - `_PinnedHTTPSHandler` / `_PinnedHTTPHandler` carrying `target.pinned_ip`.
    - `_NoRedirectHandler` — raises `RedirectBlocked` on 3xx (D3).

    Use `opener.open(url)` directly; do NOT call
    `urllib.request.install_opener(opener)` — leave the global default alone
    so non-A2A code paths are untouched.
    """
    handlers: list[urllib.request.BaseHandler] = [
        urllib.request.ProxyHandler({}),
        _NoRedirectHandler(),
    ]
    if target.scheme == "https":
        handlers.append(
            _PinnedHTTPSHandler(target.pinned_ip, context=context or ssl.create_default_context())
        )
    else:
        handlers.append(_PinnedHTTPHandler(target.pinned_ip))
    return urllib.request.build_opener(*handlers)
