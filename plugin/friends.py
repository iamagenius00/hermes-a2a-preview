"""A2A FriendsStore — JSON-backed contact store for the A2A plugin.

This module is the source of truth for who can talk to the agent and on what
terms. Issue 4 only builds the storage layer; inbound auth still uses the
legacy `A2A_AUTH_TOKEN` model. Issue 5 wires this store into the auth path.

Schema (v1) — one record per friend:

    {
      "schema_version": 1,
      "friends": [
        {
          "id": "f_abc12345",
          "name": "local-agent",
          "display_name": "Local Agent",
          "url": "http://127.0.0.1:8082",
          "inbound_token_hash": "sha256:...",   # only the hash is stored
          "outbound_token": "...",              # cleartext, needed to call
          "trust_level": "new",                 # trusted | normal | new
          "allow_inbound": true,
          "allow_initiate": false,
          "rate_limit_per_min": 20,
          "max_message_chars": 50000,
          "status": "pending",                  # see VALID_STATUSES
          "added_at": "2026-05-01T...",
          "last_contact": null,
          "expires_at": "2026-05-15T...",       # only matters for status=pending
          "notes": ""
        }
      ]
    }

Persistence is JSON at the path returned by ``paths.friends_path()`` (which
prefixes by plugin name, so `a2a` writes to `a2a_friends.json` and `a2a-dev`
writes to `a2a-dev_friends.json` — see Issue 0).

Storage hygiene:

- atomic write (tmp + fsync + rename)
- file mode 0600 where supported
- corrupt JSON is backed up to `*.corrupt-<ts>` and the store starts empty;
  at most ``DEFAULT_BACKUP_KEEP`` corrupt backups are retained
- raw inbound tokens are never written to disk; only their sha256 hash
- raw outbound tokens are stored in cleartext because we have to send them

Token compare uses ``hmac.compare_digest`` to avoid timing leaks.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import hmac
import json
import logging
import os
import secrets
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from typing import Optional

from .paths import friends_path
from .ssrf import (
    DNSResolutionFailed,
    FAKE_IP_ALLOW_SCOPE,
    RedirectBlocked,
    SSRFBlocked,
    UnconfiguredURL,
    is_ip_literal_url,
    normalize_target_url,
    tunnel_provider_for_url,
    validate_outbound_url,
)

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1

VALID_STATUSES = {"pending", "active", "paused", "blocked", "expired", "removed"}
VALID_TRUST_LEVELS = {"trusted", "normal", "new"}

DEFAULT_TRUST_LEVEL = "new"
DEFAULT_PENDING_DAYS = 14
DEFAULT_RATE_LIMIT_PER_MIN = 20
DEFAULT_MAX_MESSAGE_CHARS = 50_000
DEFAULT_BACKUP_KEEP = 3


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _isoformat(dt: datetime) -> str:
    return dt.isoformat()


def _generate_id() -> str:
    return f"f_{secrets.token_hex(4)}"


def _generate_token() -> str:
    return secrets.token_urlsafe(32)


def _hash_token(raw: str) -> str:
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _empty_store() -> dict:
    return {"schema_version": SCHEMA_VERSION, "friends": []}


def mask_token(token: str) -> str:
    """Return a redacted form of a raw token for display in logs/UI."""
    if not token:
        return ""
    if len(token) <= 4:
        return "***"
    return "***" + token[-4:]


def _private_reason_bucket(reason: str) -> str:
    length = len((reason or "").strip())
    if length <= 50:
        return "20-50"
    if length <= 100:
        return "51-100"
    return "100+"


def _audit_hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _is_http_url_shape(url: str) -> bool:
    from urllib.parse import urlparse

    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def _audit_ssrf_blocked(name: str, url: str, exc: Exception) -> None:
    try:
        from .security import audit

        audit.log("ssrf_blocked", {
            "friend_name": name,
            "target_repr": normalize_target_url(url) if _is_http_url_shape(url) else url,
            "exception_type": exc.__class__.__name__,
        })
    except Exception:
        logger.debug("Failed to write ssrf_blocked audit event", exc_info=True)


def _empty_origin_fields() -> dict:
    return {"allowed_origins": []}


def _origin_provider(url: str) -> str:
    return tunnel_provider_for_url(url) or "custom"


def _clear_legacy_tunnel_fields(friend: dict) -> None:
    for key in (
        "approved_tunnel_origin",
        "approved_tunnel_provider",
        "approved_tunnel_reason_hash",
        "approved_tunnel_reason_length_bucket",
        "approved_tunnel_expires_at",
    ):
        friend.pop(key, None)


def _normalize_origin_entry(entry: dict) -> Optional[dict]:
    if not isinstance(entry, dict):
        return None
    origin = (entry.get("origin") or "").strip()
    if not origin:
        return None
    scope = (entry.get("scope") or FAKE_IP_ALLOW_SCOPE).strip()
    if scope != FAKE_IP_ALLOW_SCOPE:
        return None
    normalized = {
        "origin": origin,
        "scope": FAKE_IP_ALLOW_SCOPE,
        "reason_hash": entry.get("reason_hash", ""),
        "reason_length_bucket": entry.get("reason_length_bucket", ""),
        "created_at": entry.get("created_at") or None,
        "expires_at": entry.get("expires_at") or None,
        "provider": entry.get("provider") or "custom",
    }
    return normalized


def _legacy_allowed_origin(friend: dict) -> Optional[dict]:
    origin = (friend or {}).get("approved_tunnel_origin", "")
    if not origin:
        return None
    return {
        "origin": origin,
        "scope": FAKE_IP_ALLOW_SCOPE,
        "reason_hash": (friend or {}).get("approved_tunnel_reason_hash", ""),
        "reason_length_bucket": (friend or {}).get("approved_tunnel_reason_length_bucket", ""),
        "created_at": None,
        "expires_at": (friend or {}).get("approved_tunnel_expires_at"),
        "provider": (friend or {}).get("approved_tunnel_provider") or "custom",
    }


def effective_allowed_origins(friend: dict) -> list[dict]:
    entries: list[dict] = []
    for entry in (friend or {}).get("allowed_origins") or []:
        normalized = _normalize_origin_entry(entry)
        if normalized:
            entries.append(normalized)
    legacy = _legacy_allowed_origin(friend)
    if legacy and not any(e.get("origin") == legacy["origin"] and e.get("scope") == legacy["scope"] for e in entries):
        entries.append(legacy)
    return entries


def _validate_origin_allow(url: str, reason: str, expires_at: Optional[str] = None) -> dict:
    if not url:
        raise ValueError("allow-origin requires a url")
    if len((reason or "").strip()) < 20:
        raise ValueError("allow-origin requires a reason of at least 20 characters")
    origin = normalize_target_url(url)
    entry = {
        "origin": origin,
        "scope": FAKE_IP_ALLOW_SCOPE,
        "reason_hash": _audit_hash((reason or "").strip()),
        "reason_length_bucket": _private_reason_bucket(reason),
        "created_at": _isoformat(_now()),
        "expires_at": expires_at,
        "provider": _origin_provider(url),
    }
    validate_outbound_url(
        url,
        allow_private=False,
        allow_unconfigured=True,
        is_configured_friend=True,
        allow_env_private=False,
        allowed_origins=[entry],
    )
    return entry


def _audit_origin_allowed(friend_id: str, entry: dict, reason: str) -> None:
    try:
        from .security import audit

        audit.log("friend_origin_allowed", {
            "friend_id": friend_id,
            "provider": entry.get("provider", "custom"),
            "scope": entry.get("scope", FAKE_IP_ALLOW_SCOPE),
            "target_origin_hash": _audit_hash(entry.get("origin", "")),
            "reason_present": bool((reason or "").strip()),
            "reason_length_bucket": entry.get("reason_length_bucket", ""),
        })
    except Exception:
        logger.debug("Failed to write origin allow audit event", exc_info=True)


def _audit_origin_revoked(friend_id: str, entry: dict) -> None:
    try:
        from .security import audit

        audit.log("friend_origin_revoked", {
            "friend_id": friend_id,
            "provider": entry.get("provider", "custom"),
            "scope": entry.get("scope", FAKE_IP_ALLOW_SCOPE),
            "target_origin_hash": _audit_hash(entry.get("origin", "")),
        })
    except Exception:
        logger.debug("Failed to write origin revoke audit event", exc_info=True)


class FriendsStore:
    def __init__(self, path: Optional[Path] = None):
        self._path = path if path is not None else friends_path()
        self._lock = Lock()
        # Sweep any orphan .tmp files left by a previous crashed writer.
        # Safe to call repeatedly; only deletes files older than 60s so a
        # concurrent writer's in-flight tmp is never touched.
        self._sweep_orphan_tmp_files()

    @property
    def path(self) -> Path:
        return self._path

    @property
    def _lock_path(self) -> Path:
        """Sidecar lock file used for cross-process serialisation.

        We lock a sidecar (rather than the data file itself) because
        ``os.replace`` on the data file invalidates any locks held on its
        old inode. Locking a stable sidecar inode keeps the critical
        section intact across the rename.
        """
        return self._path.with_name(self._path.name + ".lock")

    @contextlib.contextmanager
    def _file_lock(self, blocking: bool = True):
        """Cross-process exclusive lock via ``fcntl.flock``.

        Held for the duration of a read-modify-write cycle. Combined with
        ``self._lock`` (which serialises in-process threads), this gives
        full mutual exclusion across all writers — including a CLI / dev
        gateway / production gateway all touching the same friends.json.

        ``blocking=False`` returns immediately with ``BlockingIOError`` if
        another holder has the lock — used by best-effort cleanup paths
        (sweep) that must not interfere with a live writer.

        On platforms without ``fcntl`` (e.g. Windows) this would need a
        different primitive, but Hermes runs on macOS / Linux only.
        """
        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        f = open(self._lock_path, "w")
        try:
            flags = fcntl.LOCK_EX
            if not blocking:
                flags |= fcntl.LOCK_NB
            fcntl.flock(f.fileno(), flags)
            yield
        finally:
            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            f.close()

    def _sweep_orphan_tmp_files(self) -> None:
        """Remove ``.tmp.*`` files older than 60s (orphans from crashed writes).

        Each successful write uses a unique mkstemp name, so on success
        there's no orphan. But a writer killed mid-write leaves one behind.

        The sweep takes the file lock **non-blocking** so it never races
        with an in-flight writer's ``_write_unlocked`` (which holds the
        lock for the duration of mkstemp + dump + fsync + replace). If
        the lock is held when sweep runs, sweep is skipped — orphans
        will be cleaned up at the next ``__init__`` call after the
        writer releases. The 60s mtime threshold is a second-line defence
        in case lock-acquisition somehow misses an active writer.
        """
        try:
            with self._file_lock(blocking=False):
                now = datetime.now(timezone.utc).timestamp()
                for orphan in self._path.parent.glob(self._path.name + ".tmp.*"):
                    try:
                        if now - orphan.stat().st_mtime > 60:
                            orphan.unlink()
                    except OSError:
                        pass
        except BlockingIOError:
            # Live writer holds the lock; skip this sweep cycle.
            return
        except (OSError, AttributeError):
            return

    # ── disk IO ───────────────────────────────────────────────────────

    def _read_unlocked(self) -> dict:
        if not self._path.exists():
            return _empty_store()
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning(
                "FriendsStore: %s is unreadable (%s); backing up", self._path, exc
            )
            self._backup_corrupt_unlocked()
            return _empty_store()

        if (
            not isinstance(data, dict)
            or not isinstance(data.get("friends"), list)
        ):
            logger.warning(
                "FriendsStore: %s has wrong shape; backing up", self._path
            )
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

    def _write_unlocked(self, data: dict) -> None:
        """Atomically replace the friends file with ``data``.

        Uses ``tempfile.mkstemp`` for a unique tmp name (so concurrent
        writers from separate processes never collide on the tmp file).
        Cleans up the tmp on any exception so a failed write doesn't
        leave a stale orphan.

        After ``os.replace`` succeeds, the parent directory is also
        fsynced so the rename is durable across power loss (without it,
        the new file's content is on disk but the directory entry might
        not be — a crash could revert the rename).

        Caveat: SIGKILL between mkstemp and os.replace cannot be cleaned
        up by Python (no exception handler runs). The orphan is cleaned
        up by the next ``__init__``'s ``_sweep_orphan_tmp_files`` call.
        Tmp file mode is 0600 (mkstemp default + explicit chmod) so
        any orphan does not leak ``outbound_token`` content.
        """
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
            # Parent-directory fsync — ensures the rename's directory
            # entry is durable across power loss. Best-effort: not all
            # filesystems support O_DIRECTORY (e.g. some macOS network
            # mounts), so we swallow OSError.
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

    # ── queries ───────────────────────────────────────────────────────

    def list_friends(self) -> list[dict]:
        with self._lock, self._file_lock():
            data = self._read_unlocked()
            return [dict(f) for f in data["friends"]]

    def get_by_id(self, friend_id: str) -> Optional[dict]:
        with self._lock, self._file_lock():
            data = self._read_unlocked()
            for f in data["friends"]:
                if f.get("id") == friend_id:
                    return dict(f)
            return None

    def get_by_name(self, name: str) -> Optional[dict]:
        with self._lock, self._file_lock():
            data = self._read_unlocked()
            for f in data["friends"]:
                if f.get("name") == name:
                    return dict(f)
            return None

    def get_by_url(self, url: str) -> Optional[dict]:
        needle = (url or "").strip().rstrip("/")
        with self._lock, self._file_lock():
            data = self._read_unlocked()
            for f in data["friends"]:
                if (f.get("url") or "").strip().rstrip("/") == needle:
                    return dict(f)
            return None

    def get_by_token(self, raw_token: str) -> Optional[dict]:
        """Look up a friend by their raw inbound token.

        The candidate is hashed and compared against stored hashes with
        ``hmac.compare_digest``. Returns None if no match (also for empty
        input).
        """
        if not raw_token:
            return None
        candidate_hash = _hash_token(raw_token)
        with self._lock, self._file_lock():
            data = self._read_unlocked()
            for f in data["friends"]:
                stored = f.get("inbound_token_hash") or ""
                if stored and hmac.compare_digest(stored, candidate_hash):
                    return dict(f)
            return None

    # ── mutations ─────────────────────────────────────────────────────

    def add_friend(
        self,
        name: str,
        url: str = "",
        display_name: str = "",
        outbound_token: str = "",
        allow_private_url: bool = False,
        allow_private_reason: str = "",
        allow_origin: bool = False,
        allow_origin_reason: str = "",
        allow_origin_expires_at: Optional[str] = None,
        approve_tunnel: bool = False,
        approved_tunnel_reason: str = "",
        approved_tunnel_expires_at: Optional[str] = None,
        trust_level: str = DEFAULT_TRUST_LEVEL,
        rate_limit_per_min: int = DEFAULT_RATE_LIMIT_PER_MIN,
        max_message_chars: int = DEFAULT_MAX_MESSAGE_CHARS,
        notes: str = "",
        pending_days: int = DEFAULT_PENDING_DAYS,
    ) -> tuple[dict, str]:
        """Add a new friend and return ``(friend_record, raw_inbound_token)``.

        The raw inbound token is returned ONCE — only its hash is persisted.
        The caller is responsible for showing the raw token to the user
        immediately (with a copy-once UX) and then discarding it.
        """
        if not name:
            raise ValueError("name is required")
        if trust_level not in VALID_TRUST_LEVELS:
            raise ValueError(f"invalid trust_level: {trust_level}")
        if rate_limit_per_min <= 0:
            raise ValueError("rate_limit_per_min must be positive")
        if pending_days < 0:
            raise ValueError("pending_days must be non-negative")
        allow_private_target = ""
        allow_private_reason = allow_private_reason or ""
        allowed_origins: list[dict] = []
        effective_allow_origin = allow_origin or approve_tunnel
        effective_origin_reason = allow_origin_reason or approved_tunnel_reason
        effective_origin_expires_at = allow_origin_expires_at if allow_origin_expires_at is not None else approved_tunnel_expires_at
        if url:
            if allow_private_url:
                if not is_ip_literal_url(url):
                    raise ValueError("private-network approval requires an IP literal target in M2 v1")
                allow_private_target = normalize_target_url(url)
                if len(allow_private_reason.strip()) < 20:
                    raise ValueError("allow_private_url requires a reason of at least 20 characters")
            if effective_allow_origin:
                allowed_origins = [_validate_origin_allow(
                    url,
                    effective_origin_reason,
                    effective_origin_expires_at,
                )]
            try:
                validate_outbound_url(
                    url,
                    allow_private=bool(allow_private_target),
                    allow_unconfigured=True,
                    is_configured_friend=True,
                    allow_env_private=False,
                    allowed_origins=allowed_origins,
                )
            except (SSRFBlocked, UnconfiguredURL, DNSResolutionFailed, RedirectBlocked) as exc:
                _audit_ssrf_blocked(name, url, exc)
                raise
        elif allow_private_url:
            raise ValueError("allow_private_url requires a url")
        elif effective_allow_origin:
            raise ValueError("allow-origin requires a url")

        with self._lock, self._file_lock():
            data = self._read_unlocked()
            for existing in data["friends"]:
                if (
                    existing.get("name") == name
                    and existing.get("status") != "removed"
                ):
                    raise ValueError(f"friend with name {name!r} already exists")

            raw_token = _generate_token()
            now = _now()
            friend = {
                "id": _generate_id(),
                "name": name,
                "display_name": display_name or name,
                "url": url,
                "allow_private_target": allow_private_target,
                "allow_private_reason": allow_private_reason if allow_private_target else "",
                "allowed_origins": allowed_origins,
                "inbound_token_hash": _hash_token(raw_token),
                "outbound_token": outbound_token,
                "trust_level": trust_level,
                "allow_inbound": True,
                "allow_initiate": False,
                "rate_limit_per_min": rate_limit_per_min,
                "max_message_chars": max_message_chars,
                "status": "pending",
                "added_at": _isoformat(now),
                "last_contact": None,
                "expires_at": _isoformat(now + timedelta(days=pending_days)),
                "notes": notes,
            }
            if allow_private_target:
                try:
                    from .security import audit

                    audit.log("friend_added_with_private_url", {
                        "friend_id": friend["id"],
                        "target_repr": allow_private_target,
                        "reason_present": bool(allow_private_reason.strip()),
                        "reason_length_bucket": _private_reason_bucket(allow_private_reason),
                    })
                except Exception:
                    logger.debug("Failed to write private URL audit event", exc_info=True)
            for entry in allowed_origins:
                _audit_origin_allowed(friend["id"], entry, effective_origin_reason)
            data["friends"].append(friend)
            self._write_unlocked(data)
            return dict(friend), raw_token

    def remove_friend(self, name_or_id: str) -> bool:
        """Hard-remove a friend record. Returns True if removed.

        Note on audit retention: this only deletes the entry from
        ``a2a_friends.json``. The audit log (``a2a_audit.jsonl``) is
        append-only and is not touched. Historical audit entries that
        reference the removed ``friend_id`` are deliberately preserved as
        the historical record. The dashboard / CLI should render those as
        "(removed friend)" or similar when displaying past events.
        """
        with self._lock, self._file_lock():
            data = self._read_unlocked()
            for i, f in enumerate(data["friends"]):
                if f.get("id") == name_or_id or f.get("name") == name_or_id:
                    data["friends"].pop(i)
                    self._write_unlocked(data)
                    return True
            return False

    def _set_status_unlocked(self, data: dict, name_or_id: str, status: str) -> bool:
        for f in data["friends"]:
            if f.get("id") == name_or_id or f.get("name") == name_or_id:
                f["status"] = status
                return True
        return False

    def pause(self, name_or_id: str) -> bool:
        return self._mutate_status(name_or_id, "paused")

    def unpause(self, name_or_id: str) -> bool:
        return self._mutate_status(name_or_id, "active")

    def block(self, name_or_id: str) -> bool:
        return self._mutate_status(name_or_id, "blocked")

    def unblock(self, name_or_id: str) -> bool:
        return self._mutate_status(name_or_id, "active")

    def _mutate_status(self, name_or_id: str, status: str) -> bool:
        if status not in VALID_STATUSES:
            raise ValueError(f"invalid status: {status}")
        with self._lock, self._file_lock():
            data = self._read_unlocked()
            if self._set_status_unlocked(data, name_or_id, status):
                self._write_unlocked(data)
                return True
            return False

    def rotate_token(self, name_or_id: str) -> Optional[str]:
        """Rotate the inbound token. Returns the new raw token, or None if not found.

        The previous hash is replaced atomically; any holder of the old token
        is immediately rejected by ``get_by_token``.
        """
        new_raw = _generate_token()
        with self._lock, self._file_lock():
            data = self._read_unlocked()
            for f in data["friends"]:
                if f.get("id") == name_or_id or f.get("name") == name_or_id:
                    f["inbound_token_hash"] = _hash_token(new_raw)
                    self._write_unlocked(data)
                    return new_raw
            return None

    def set_trust_level(self, name_or_id: str, trust_level: str) -> bool:
        if trust_level not in VALID_TRUST_LEVELS:
            raise ValueError(f"invalid trust_level: {trust_level}")
        with self._lock, self._file_lock():
            data = self._read_unlocked()
            for f in data["friends"]:
                if f.get("id") == name_or_id or f.get("name") == name_or_id:
                    f["trust_level"] = trust_level
                    self._write_unlocked(data)
                    return True
            return False

    def set_rate_limit(self, name_or_id: str, rate_limit_per_min: int) -> bool:
        if rate_limit_per_min <= 0:
            raise ValueError("rate_limit_per_min must be positive")
        with self._lock, self._file_lock():
            data = self._read_unlocked()
            for f in data["friends"]:
                if f.get("id") == name_or_id or f.get("name") == name_or_id:
                    f["rate_limit_per_min"] = rate_limit_per_min
                    self._write_unlocked(data)
                    return True
            return False

    def set_outbound_token(self, name_or_id: str, outbound_token: str) -> bool:
        with self._lock, self._file_lock():
            data = self._read_unlocked()
            for f in data["friends"]:
                if f.get("id") == name_or_id or f.get("name") == name_or_id:
                    f["outbound_token"] = outbound_token
                    self._write_unlocked(data)
                    return True
            return False

    def set_url(self, name_or_id: str, url: str) -> bool:
        if url and not _is_http_url_shape(url):
            raise ValueError("A2A URL must be an http(s) URL")
        normalized_target = None
        if url:
            try:
                normalized_target = normalize_target_url(url)
            except SSRFBlocked as exc:
                raise ValueError(f"invalid A2A URL: {exc}") from exc
        with self._lock, self._file_lock():
            data = self._read_unlocked()
            for f in data["friends"]:
                if f.get("id") == name_or_id or f.get("name") == name_or_id:
                    previous_target = f.get("allow_private_target", "")
                    f["url"] = url
                    if not normalized_target or not previous_target or normalized_target != previous_target:
                        f["allow_private_target"] = ""
                        f["allow_private_reason"] = ""
                    f["allowed_origins"] = [
                        entry for entry in effective_allowed_origins(f)
                        if normalized_target and entry.get("origin") == normalized_target
                    ]
                    _clear_legacy_tunnel_fields(f)
                    self._write_unlocked(data)
                    return True
            return False

    def clear_private_approval(self, name_or_id: str) -> bool:
        with self._lock, self._file_lock():
            data = self._read_unlocked()
            for f in data["friends"]:
                if f.get("id") == name_or_id or f.get("name") == name_or_id:
                    f["allow_private_target"] = ""
                    f["allow_private_reason"] = ""
                    self._write_unlocked(data)
                    return True
            return False

    def allow_origin(
        self,
        name_or_id: str,
        reason: str,
        expires_at: Optional[str] = None,
    ) -> bool:
        with self._lock, self._file_lock():
            data = self._read_unlocked()
            for f in data["friends"]:
                if f.get("id") == name_or_id or f.get("name") == name_or_id:
                    entry = _validate_origin_allow(f.get("url", ""), reason, expires_at)
                    entries = [
                        item for item in effective_allowed_origins(f)
                        if item.get("origin") != entry["origin"] or item.get("scope") != entry["scope"]
                    ]
                    entries.append(entry)
                    f["allowed_origins"] = entries
                    _clear_legacy_tunnel_fields(f)
                    self._write_unlocked(data)
                    _audit_origin_allowed(f.get("id", ""), entry, reason)
                    return True
            return False

    def revoke_origin(self, name_or_id: str, origin: str = "") -> bool:
        with self._lock, self._file_lock():
            data = self._read_unlocked()
            for f in data["friends"]:
                if f.get("id") == name_or_id or f.get("name") == name_or_id:
                    target_origin = ""
                    if origin:
                        target_origin = normalize_target_url(origin)
                    elif f.get("url"):
                        target_origin = normalize_target_url(f.get("url", ""))
                    previous_entries = effective_allowed_origins(f)
                    remaining = []
                    revoked = []
                    for entry in previous_entries:
                        if target_origin and entry.get("origin") == target_origin:
                            revoked.append(entry)
                        elif not target_origin:
                            revoked.append(entry)
                        else:
                            remaining.append(entry)
                    f["allowed_origins"] = remaining
                    _clear_legacy_tunnel_fields(f)
                    self._write_unlocked(data)
                    for entry in revoked:
                        _audit_origin_revoked(f.get("id", ""), entry)
                    return True
            return False

    def list_allowed_origins(self, name_or_id: str) -> Optional[list[dict]]:
        with self._lock, self._file_lock():
            data = self._read_unlocked()
            for f in data["friends"]:
                if f.get("id") == name_or_id or f.get("name") == name_or_id:
                    return [dict(entry) for entry in effective_allowed_origins(f)]
            return None

    def approve_tunnel(
        self,
        name_or_id: str,
        reason: str,
        expires_at: Optional[str] = None,
    ) -> bool:
        return self.allow_origin(name_or_id, reason, expires_at)

    def revoke_tunnel(self, name_or_id: str) -> bool:
        return self.revoke_origin(name_or_id)

    def record_last_contact(self, name_or_id: str) -> bool:
        """Record a successful inbound auth from this friend.

        Updates ``last_contact`` and transitions ``pending`` -> ``active``.
        Other statuses are not changed (e.g. a paused friend remains paused
        even if they manage to authenticate elsewhere).
        """
        with self._lock, self._file_lock():
            data = self._read_unlocked()
            for f in data["friends"]:
                if f.get("id") == name_or_id or f.get("name") == name_or_id:
                    f["last_contact"] = _isoformat(_now())
                    if f.get("status") == "pending":
                        f["status"] = "active"
                    self._write_unlocked(data)
                    return True
            return False

    def bootstrap_legacy(self, raw_token: str) -> Optional[dict]:
        """Import a raw legacy token as a single ``legacy`` friend record.

        No-op if the store already contains any record (so this is safe to
        call on every plugin load). Returns the new friend record on first
        migration, ``None`` otherwise. The raw token is hashed with the
        store's normal hashing function and the original ``A2A_AUTH_TOKEN``
        env var continues to work transparently for existing callers.
        """
        if not raw_token:
            return None
        with self._lock, self._file_lock():
            data = self._read_unlocked()
            if data["friends"]:
                return None
            now = _now()
            legacy = {
                "id": "f_legacy",
                "name": "legacy",
                "display_name": "Legacy A2A_AUTH_TOKEN",
                "url": "",
                "allow_private_target": "",
                "allow_private_reason": "",
                **_empty_origin_fields(),
                "inbound_token_hash": _hash_token(raw_token),
                "outbound_token": "",
                "trust_level": "normal",
                "allow_inbound": True,
                "allow_initiate": False,
                "rate_limit_per_min": DEFAULT_RATE_LIMIT_PER_MIN,
                "max_message_chars": DEFAULT_MAX_MESSAGE_CHARS,
                "status": "active",
                "added_at": _isoformat(now),
                "last_contact": None,
                "expires_at": "",
                "notes": "Imported from A2A_AUTH_TOKEN env var on first startup",
            }
            data["friends"].append(legacy)
            self._write_unlocked(data)
            return dict(legacy)

    def expire_pending(self) -> int:
        """Sweep any ``pending`` friends past their ``expires_at`` to ``expired``.

        Returns the number of records expired. Safe to call frequently;
        only writes when there is at least one transition.
        """
        now_iso = _isoformat(_now())
        count = 0
        with self._lock, self._file_lock():
            data = self._read_unlocked()
            for f in data["friends"]:
                expires = f.get("expires_at")
                if (
                    f.get("status") == "pending"
                    and isinstance(expires, str)
                    and expires < now_iso
                ):
                    f["status"] = "expired"
                    count += 1
            if count:
                self._write_unlocked(data)
        return count


# Module-level singleton bound to the per-plugin friends path.
friends = FriendsStore()
