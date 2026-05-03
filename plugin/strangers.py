"""A2A stranger request store.

P4.2.1 is store-only. This module models and persists metadata for inbound
requests that failed authentication; it does not read request bodies, fetch
Agent Cards, touch FriendsStore, or wire into server/UI callsites.
"""

from __future__ import annotations

import contextlib
import fcntl
import ipaddress
import json
import logging
import os
import secrets
import tempfile
import urllib.error
import urllib.request
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Mapping, Optional
from urllib.parse import quote, urlparse

from .paths import stranger_requests_path
from .provenance import audit_digest
from . import ssrf

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1

AUTH_NO_TOKEN = "no_token"
AUTH_MALFORMED_HEADER = "malformed_header"
AUTH_UNKNOWN_TOKEN = "unknown_token"
AUTH_FRIEND_PAUSED = "friend_paused"
AUTH_FRIEND_BLOCKED = "friend_blocked"
AUTH_FRIEND_EXPIRED = "friend_expired"
AUTH_FRIEND_REMOVED = "friend_removed"

VALID_AUTH_REASONS = {
    AUTH_NO_TOKEN,
    AUTH_MALFORMED_HEADER,
    AUTH_UNKNOWN_TOKEN,
    AUTH_FRIEND_PAUSED,
    AUTH_FRIEND_BLOCKED,
    AUTH_FRIEND_EXPIRED,
    AUTH_FRIEND_REMOVED,
}

STATUS_NEW = "new"
STATUS_REJECTED = "rejected"
STATUS_BLOCKED = "blocked"
STATUS_CONVERTED = "converted"
VALID_STATUSES = {STATUS_NEW, STATUS_REJECTED, STATUS_BLOCKED, STATUS_CONVERTED}

BLOCK_SCOPE_CARD_URL = "card_url"
BLOCK_SCOPE_IP_DIGEST = "ip_digest"
VALID_BLOCK_SCOPES = {BLOCK_SCOPE_CARD_URL, BLOCK_SCOPE_IP_DIGEST}

FETCH_STATUSES = {"none", "ok", "blocked", "invalid", "error", "skipped"}

AGENT_CARD_HEADER_MAX = 2048
AGENT_CARD_URL_MAX = 512
CLAIMED_NAME_MAX = 80
VERSION_MAX = 32
METHOD_MAX = 64
MAX_METHODS = 20
CLIENT_IP_DISPLAY_MAX = 64
AGENT_CARD_RESPONSE_MAX = 16_384
AGENT_CARD_FETCH_TIMEOUT = 5

DEFAULT_REQUEST_RETENTION_DAYS = 30
DEFAULT_BLOCK_RETENTION_DAYS = 90
DEFAULT_PER_IP_PER_HOUR = 5
DEFAULT_GLOBAL_VISIBLE_PER_DAY = 50
DEFAULT_BACKUP_KEEP = 3


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _isoformat(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _parse_time(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return datetime.fromtimestamp(0, tz=timezone.utc)


def _generate_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(4)}"


def _empty_store() -> dict[str, Any]:
    return {"schema_version": SCHEMA_VERSION, "requests": [], "blocked": []}


def _require_digest_key(key: bytes | str) -> bytes | str:
    if not key:
        raise ValueError("stranger digest key is required")
    return key


def _digest(value: str, key: bytes | str) -> str:
    return audit_digest(value, _require_digest_key(key), prefix_len=16)


def _safe_text(value: Any, limit: int) -> str:
    text = " ".join(str(value or "").split())
    return text[:limit]


def _ip_bucket_and_display(client_ip: str) -> tuple[str, str]:
    raw = _safe_text(client_ip, CLIENT_IP_DISPLAY_MAX)
    try:
        addr = ipaddress.ip_address(raw.split("%", 1)[0])
    except ValueError:
        return "unknown", raw
    if addr.is_loopback:
        bucket = "loopback"
    elif not addr.is_global:
        bucket = "private"
    else:
        bucket = "public"
    return bucket, str(addr)


def _build_url(scheme: str, host: str, port: int, path: str, *, is_ipv6: bool) -> str:
    default_port = 443 if scheme == "https" else 80
    host_part = f"[{host}]" if is_ipv6 else host
    netloc = host_part if port == default_port else f"{host_part}:{port}"
    encoded_path = quote(path or "/", safe="/%")
    return f"{scheme}://{netloc}{encoded_path}"


def canonical_agent_card_url(raw_url: str) -> str:
    """Return a safe no-query/no-fragment canonical Agent Card URL."""
    raw = str(raw_url or "").strip()
    if not raw or len(raw.encode("utf-8")) > AGENT_CARD_HEADER_MAX:
        return ""
    try:
        parsed = urlparse(raw)
        raw_host = parsed.hostname
    except ValueError:
        return ""
    if parsed.scheme not in ("http", "https") or not raw_host:
        return ""
    if parsed.username is not None or parsed.password is not None:
        return ""
    try:
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return ""
    if not (1 <= port <= 65535):
        return ""

    try:
        addr = ipaddress.ip_address(raw_host)
    except ValueError:
        try:
            host = raw_host.encode("idna").decode("ascii").lower()
        except UnicodeError:
            return ""
        is_ipv6 = False
    else:
        host = str(addr)
        is_ipv6 = isinstance(addr, ipaddress.IPv6Address)

    canonical = _build_url(parsed.scheme, host, port, parsed.path or "/", is_ipv6=is_ipv6)
    if len(canonical) > AGENT_CARD_URL_MAX:
        return ""
    return canonical


def normalize_agent_card_url(raw_url: str, digest_key: bytes | str) -> dict[str, str] | None:
    """Return a safe no-query/no-fragment Agent Card URL projection.

    The returned `agent_card_url_digest` is keyed over the canonical display URL,
    not over the attacker-supplied raw URL, so query/fragment material cannot be
    recovered through store/audit correlation.
    """
    canonical = canonical_agent_card_url(raw_url)
    if not canonical:
        return None
    return {
        "agent_card_url": canonical,
        "agent_card_url_digest": _digest(canonical, digest_key),
    }


def sanitize_agent_card_fetch(fetch: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return the narrow, display-safe Agent Card fetch projection."""
    if not isinstance(fetch, Mapping):
        return {"status": "none"}
    status = str(fetch.get("status") or "none")
    if status not in FETCH_STATUSES:
        status = "error"
    projected: dict[str, Any] = {"status": status}
    if status == "ok":
        projected["claimed_name"] = _safe_text(fetch.get("claimed_name", ""), CLAIMED_NAME_MAX)
        projected["protocol_version"] = _safe_text(fetch.get("protocol_version", ""), VERSION_MAX)
        projected["extension_version"] = _safe_text(fetch.get("extension_version", ""), VERSION_MAX)
        methods = fetch.get("supported_methods", [])
        if not isinstance(methods, (list, tuple)):
            methods = []
        projected["supported_methods"] = [
            _safe_text(method, METHOD_MAX)
            for method in methods[:MAX_METHODS]
            if _safe_text(method, METHOD_MAX)
        ]
    elif status in {"blocked", "invalid", "error", "skipped"}:
        projected["reason_class"] = _safe_text(fetch.get("reason_class", ""), VERSION_MAX)
    return projected


def _agent_card_methods(card: Mapping[str, Any]) -> list[Any]:
    for key in ("supported_methods", "supportedMethods", "methods"):
        value = card.get(key)
        if isinstance(value, (list, tuple)):
            return list(value)
    capabilities = card.get("capabilities", {})
    if isinstance(capabilities, Mapping):
        for key in ("supported_methods", "supportedMethods", "methods"):
            value = capabilities.get(key)
            if isinstance(value, (list, tuple)):
                return list(value)
    return []


def project_agent_card(card: Mapping[str, Any] | None) -> dict[str, Any]:
    """Project a fetched Agent Card to the narrow stranger-safe shape."""
    if not isinstance(card, Mapping):
        return sanitize_agent_card_fetch({"status": "invalid", "reason_class": "invalid_shape"})
    return sanitize_agent_card_fetch({
        "status": "ok",
        "claimed_name": card.get("name", ""),
        "protocol_version": (
            card.get("protocolVersion")
            or card.get("protocol_version")
            or card.get("version")
            or ""
        ),
        "extension_version": (
            card.get("extensionVersion")
            or card.get("extension_version")
            or card.get("x-hermes-a2a-extension-version")
            or ""
        ),
        "supported_methods": _agent_card_methods(card),
    })


def fetch_stranger_agent_card(
    raw_header_url: str,
    *,
    timeout: int = AGENT_CARD_FETCH_TIMEOUT,
    max_response_size: int = AGENT_CARD_RESPONSE_MAX,
) -> dict[str, Any]:
    """Fetch a stranger Agent Card through the strict SSRF-safe path.

    This helper intentionally does not reuse tools._http_request because
    stranger discovery must not inherit direct-dev env private-network escapes.
    It returns only a sanitized projection and never returns the raw card.
    """
    canonical_url = canonical_agent_card_url(raw_header_url)
    if not canonical_url:
        return sanitize_agent_card_fetch({"status": "invalid", "reason_class": "invalid_url"})

    try:
        target = ssrf.validate_outbound_url(
            canonical_url,
            allow_private=False,
            allow_unconfigured=True,
            is_configured_friend=False,
            allow_env_private=False,
        )
        req = urllib.request.Request(
            target.canonical_url,
            headers={"User-Agent": "Hermes-A2A/1.0"},
            method="GET",
        )
        opener = ssrf.build_ssrf_opener(target)
        with opener.open(req, timeout=timeout) as resp:
            data = resp.read(max_response_size + 1)
        if len(data) > max_response_size:
            return sanitize_agent_card_fetch({"status": "error", "reason_class": "response_too_large"})
        card = json.loads(data.decode("utf-8"))
    except (ssrf.SSRFBlocked, ssrf.DNSResolutionFailed, ssrf.RedirectBlocked, ssrf.UnconfiguredURL) as exc:
        return sanitize_agent_card_fetch({"status": "blocked", "reason_class": exc.__class__.__name__})
    except (UnicodeDecodeError, json.JSONDecodeError):
        return sanitize_agent_card_fetch({"status": "invalid", "reason_class": "invalid_json"})
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as exc:
        return sanitize_agent_card_fetch({"status": "error", "reason_class": exc.__class__.__name__})
    except Exception as exc:
        return sanitize_agent_card_fetch({"status": "error", "reason_class": exc.__class__.__name__})

    return project_agent_card(card)


def _coalesce_key(record: Mapping[str, Any]) -> tuple[str, str, str, str]:
    reason = str(record.get("auth_reason") or "")
    card = str(record.get("agent_card_url_digest") or "")
    friend_id = str(record.get("matched_friend_id") or "")
    if friend_id:
        return ("friend", friend_id, reason, card)
    return ("unknown", str(record.get("client_ip_digest") or ""), reason, card)


def build_request_record(
    *,
    client_ip: str,
    auth_reason: str,
    digest_key: bytes | str,
    agent_card_url_header: str = "",
    matched_friend_id: str = "",
    matched_friend_name: str = "",
    agent_card_fetch: Mapping[str, Any] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    if auth_reason not in VALID_AUTH_REASONS:
        raise ValueError(f"invalid auth_reason: {auth_reason}")
    timestamp = _isoformat(now or _now())
    ip_bucket, ip_display = _ip_bucket_and_display(client_ip)
    card = normalize_agent_card_url(agent_card_url_header, digest_key) if agent_card_url_header else None
    record = {
        "id": "",
        "status": STATUS_NEW,
        "first_seen_at": timestamp,
        "last_seen_at": timestamp,
        "count": 1,
        "suppressed_count": 0,
        "rate_window_started_at": timestamp,
        "rate_window_count": 1,
        "client_ip_digest": _digest(ip_display or client_ip, digest_key),
        "client_ip_display": ip_display,
        "ip_bucket": ip_bucket,
        "auth_reason": auth_reason,
        "agent_card_url": "",
        "agent_card_url_digest": "",
        "agent_card_fetch": sanitize_agent_card_fetch(agent_card_fetch),
        "matched_friend_id": _safe_text(matched_friend_id, 80),
        "matched_friend_name": _safe_text(matched_friend_name, 80) if matched_friend_id else "",
    }
    if card:
        record.update(card)
    return record


def to_audit_projection(record: Mapping[str, Any]) -> dict[str, Any]:
    fetch = record.get("agent_card_fetch", {})
    claimed = fetch.get("claimed_name", "") if isinstance(fetch, Mapping) else ""
    claimed_len = len(str(claimed))
    if claimed_len == 0:
        claimed_bucket = "0"
    elif claimed_len <= 20:
        claimed_bucket = "1-20"
    elif claimed_len <= 80:
        claimed_bucket = "21-80"
    else:
        claimed_bucket = "80+"
    return {
        "request_id": str(record.get("id") or ""),
        "status": str(record.get("status") or ""),
        "auth_reason": str(record.get("auth_reason") or ""),
        "ip_bucket": str(record.get("ip_bucket") or "unknown"),
        "client_ip_digest": str(record.get("client_ip_digest") or ""),
        "agent_card_url_digest": str(record.get("agent_card_url_digest") or ""),
        "agent_card_fetch_status": str(fetch.get("status") or "none") if isinstance(fetch, Mapping) else "none",
        "claimed_name_length_bucket": claimed_bucket,
        "matched_friend_id": str(record.get("matched_friend_id") or ""),
    }


class StrangerStore:
    def __init__(
        self,
        path: Optional[Path] = None,
        *,
        digest_key: bytes | str = "",
        request_retention_days: int = DEFAULT_REQUEST_RETENTION_DAYS,
        block_retention_days: int = DEFAULT_BLOCK_RETENTION_DAYS,
        per_ip_per_hour: int = DEFAULT_PER_IP_PER_HOUR,
        global_visible_per_day: int = DEFAULT_GLOBAL_VISIBLE_PER_DAY,
    ):
        self._path = path if path is not None else stranger_requests_path()
        self._digest_key = digest_key
        self.request_retention_days = request_retention_days
        self.block_retention_days = block_retention_days
        self.per_ip_per_hour = per_ip_per_hour
        self.global_visible_per_day = global_visible_per_day
        self._lock = Lock()

    @property
    def path(self) -> Path:
        return self._path

    @property
    def _lock_path(self) -> Path:
        return self._path.with_name(self._path.name + ".lock")

    @contextlib.contextmanager
    def _file_lock(self):
        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        f = open(self._lock_path, "w")
        try:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            f.close()

    def _read_unlocked(self) -> dict[str, Any]:
        if not self._path.exists():
            return _empty_store()
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("StrangerStore: %s is unreadable (%s); backing up", self._path, exc)
            self._backup_corrupt_unlocked()
            return _empty_store()
        if (
            not isinstance(data, dict)
            or not isinstance(data.get("requests"), list)
            or not isinstance(data.get("blocked"), list)
        ):
            logger.warning("StrangerStore: %s has wrong shape; backing up", self._path)
            self._backup_corrupt_unlocked()
            return _empty_store()
        data.setdefault("schema_version", SCHEMA_VERSION)
        return data

    def _backup_corrupt_unlocked(self) -> None:
        ts = _now().strftime("%Y%m%dT%H%M%S")
        backup = self._path.with_name(f"{self._path.name}.corrupt-{ts}")
        try:
            os.replace(self._path, backup)
        except OSError:
            try:
                self._path.unlink()
            except OSError:
                pass
            return
        backups = sorted(
            self._path.parent.glob(f"{self._path.name}.corrupt-*"),
            key=lambda p: p.stat().st_mtime,
        )
        while len(backups) > DEFAULT_BACKUP_KEEP:
            oldest = backups.pop(0)
            try:
                oldest.unlink()
            except OSError:
                pass

    def _write_unlocked(self, data: dict[str, Any]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path_str = tempfile.mkstemp(
            dir=str(self._path.parent),
            prefix=self._path.name + ".tmp.",
        )
        tmp_path = Path(tmp_path_str)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=False)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError:
                    pass
            try:
                os.chmod(tmp_path, 0o600)
            except OSError:
                pass
            os.replace(tmp_path, self._path)
            try:
                dir_fd = os.open(str(self._path.parent), os.O_DIRECTORY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass
        except BaseException:
            try:
                tmp_path.unlink()
            except OSError:
                pass
            raise

    def _prune_unlocked(self, data: dict[str, Any], now: datetime) -> bool:
        request_cutoff = now - timedelta(days=max(0, self.request_retention_days))
        block_cutoff = now - timedelta(days=max(0, self.block_retention_days))
        requests = [
            r for r in data.get("requests", [])
            if _parse_time(r.get("last_seen_at", "")) >= request_cutoff
        ]
        blocked = [
            b for b in data.get("blocked", [])
            if _parse_time(b.get("created_at", "")) >= block_cutoff
        ]
        changed = len(requests) != len(data.get("requests", [])) or len(blocked) != len(data.get("blocked", []))
        data["requests"] = requests
        data["blocked"] = blocked
        return changed

    def list_requests(self, *, include_terminal: bool = True) -> list[dict[str, Any]]:
        with self._lock, self._file_lock():
            data = self._read_unlocked()
            if self._prune_unlocked(data, _now()):
                self._write_unlocked(data)
            records = data.get("requests", [])
            if not include_terminal:
                records = [r for r in records if r.get("status") == STATUS_NEW]
            return deepcopy(records)

    def list_blocks(self) -> list[dict[str, Any]]:
        with self._lock, self._file_lock():
            data = self._read_unlocked()
            if self._prune_unlocked(data, _now()):
                self._write_unlocked(data)
            return deepcopy(data.get("blocked", []))

    def capture(
        self,
        *,
        client_ip: str,
        auth_reason: str,
        agent_card_url_header: str = "",
        matched_friend_id: str = "",
        matched_friend_name: str = "",
        agent_card_fetch: Mapping[str, Any] | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        event_time = now or _now()
        candidate = build_request_record(
            client_ip=client_ip,
            auth_reason=auth_reason,
            digest_key=self._digest_key,
            agent_card_url_header=agent_card_url_header,
            matched_friend_id=matched_friend_id,
            matched_friend_name=matched_friend_name,
            agent_card_fetch=agent_card_fetch,
            now=event_time,
        )
        with self._lock, self._file_lock():
            data = self._read_unlocked()
            self._prune_unlocked(data, event_time)
            blocked_by = self._blocked_by_unlocked(data, candidate)
            if blocked_by:
                self._increment_suppressed_unlocked(data, candidate)
                self._write_unlocked(data)
                return {"stored": False, "blocked": True, "rate_limited": False, "request": None, "blocked_by": blocked_by}

            if self._rate_limited_unlocked(data, candidate, event_time):
                self._increment_suppressed_unlocked(data, candidate)
                self._write_unlocked(data)
                return {"stored": False, "blocked": False, "rate_limited": True, "request": None}

            key = _coalesce_key(candidate)
            for existing in data["requests"]:
                if _coalesce_key(existing) == key:
                    self._mark_rate_attempt_unlocked(existing, event_time)
                    existing["last_seen_at"] = _isoformat(event_time)
                    existing["count"] = int(existing.get("count", 0)) + 1
                    self._write_unlocked(data)
                    return {"stored": True, "blocked": False, "rate_limited": False, "request": deepcopy(existing)}

            candidate["id"] = _generate_id("sr")
            data["requests"].append(candidate)
            self._write_unlocked(data)
            return {"stored": True, "blocked": False, "rate_limited": False, "request": deepcopy(candidate)}

    def reject(self, request_id: str) -> bool:
        return self._set_status(request_id, STATUS_REJECTED)

    def mark_converted(self, request_id: str) -> bool:
        return self._set_status(request_id, STATUS_CONVERTED)

    def block(self, request_id: str, *, scope: str, now: datetime | None = None) -> dict[str, Any] | None:
        if scope not in VALID_BLOCK_SCOPES:
            raise ValueError(f"invalid block scope: {scope}")
        event_time = now or _now()
        with self._lock, self._file_lock():
            data = self._read_unlocked()
            for record in data["requests"]:
                if record.get("id") != request_id:
                    continue
                if scope == BLOCK_SCOPE_CARD_URL:
                    value = record.get("agent_card_url_digest", "")
                    if not value:
                        raise ValueError("card_url block requires an agent_card_url_digest")
                else:
                    value = record.get("client_ip_digest", "")
                block = {
                    "id": _generate_id("sb"),
                    "scope": scope,
                    "value": value,
                    "created_at": _isoformat(event_time),
                }
                data["blocked"].append(block)
                record["status"] = STATUS_BLOCKED
                self._write_unlocked(data)
                return deepcopy(block)
        return None

    def audit_projection(self, request_id: str) -> dict[str, Any] | None:
        with self._lock, self._file_lock():
            for record in self._read_unlocked().get("requests", []):
                if record.get("id") == request_id:
                    return to_audit_projection(record)
        return None

    def update_agent_card_fetch(self, request_id: str, fetch: Mapping[str, Any] | None) -> dict[str, Any] | None:
        projected = sanitize_agent_card_fetch(fetch)
        with self._lock, self._file_lock():
            data = self._read_unlocked()
            for record in data["requests"]:
                if record.get("id") == request_id:
                    record["agent_card_fetch"] = projected
                    self._write_unlocked(data)
                    return deepcopy(record)
            return None

    def _set_status(self, request_id: str, status: str) -> bool:
        if status not in VALID_STATUSES:
            raise ValueError(f"invalid status: {status}")
        with self._lock, self._file_lock():
            data = self._read_unlocked()
            for record in data["requests"]:
                if record.get("id") == request_id:
                    record["status"] = status
                    self._write_unlocked(data)
                    return True
            return False

    def _blocked_by_unlocked(self, data: Mapping[str, Any], candidate: Mapping[str, Any]) -> str:
        card = candidate.get("agent_card_url_digest", "")
        ip = candidate.get("client_ip_digest", "")
        for block in data.get("blocked", []):
            scope = block.get("scope")
            value = block.get("value")
            if scope == BLOCK_SCOPE_CARD_URL and card and value == card:
                return str(block.get("id") or BLOCK_SCOPE_CARD_URL)
            if scope == BLOCK_SCOPE_IP_DIGEST and ip and value == ip:
                return str(block.get("id") or BLOCK_SCOPE_IP_DIGEST)
        return ""

    def _rate_limited_unlocked(self, data: Mapping[str, Any], candidate: Mapping[str, Any], now: datetime) -> bool:
        one_hour_ago = now - timedelta(hours=1)
        today = now.date()
        client_ip_digest = candidate.get("client_ip_digest", "")
        same_ip_recent_attempts = 0
        visible_today = 0
        for record in data.get("requests", []):
            first_seen = _parse_time(record.get("first_seen_at", ""))
            if record.get("client_ip_digest") == client_ip_digest:
                window_started = _parse_time(record.get("rate_window_started_at", record.get("last_seen_at", "")))
                if window_started >= one_hour_ago:
                    same_ip_recent_attempts += int(record.get("rate_window_count", record.get("count", 1)))
            if first_seen.date() == today:
                visible_today += 1
        return same_ip_recent_attempts >= self.per_ip_per_hour or visible_today >= self.global_visible_per_day

    def _mark_rate_attempt_unlocked(self, record: dict[str, Any], now: datetime) -> None:
        window_started = _parse_time(record.get("rate_window_started_at", record.get("last_seen_at", "")))
        if now - window_started >= timedelta(hours=1):
            record["rate_window_started_at"] = _isoformat(now)
            record["rate_window_count"] = 1
            return
        record["rate_window_count"] = int(record.get("rate_window_count", record.get("count", 0))) + 1

    def _increment_suppressed_unlocked(self, data: dict[str, Any], candidate: Mapping[str, Any]) -> None:
        latest: dict[str, Any] | None = None
        for record in data.get("requests", []):
            if record.get("client_ip_digest") != candidate.get("client_ip_digest"):
                continue
            if latest is None or _parse_time(record.get("last_seen_at", "")) > _parse_time(latest.get("last_seen_at", "")):
                latest = record
        if latest is not None:
            latest["suppressed_count"] = int(latest.get("suppressed_count", 0)) + 1
