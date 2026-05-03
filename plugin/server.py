"""A2A HTTP server — runs in a background thread, no asyncio.

Handles inbound A2A JSON-RPC requests. Messages are queued and picked up
by the pre_llm_call hook; responses are captured by post_llm_call and
returned to the caller.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
import uuid
import builtins
from datetime import date, datetime, timezone
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from threading import Event, Lock
from collections import OrderedDict
from typing import Optional
import urllib.request
import urllib.error
from urllib.parse import urlparse

from . import provenance
from .paths import provenance_key_path
from .security import RateLimiter, audit, filter_outbound, sanitize_inbound
from .friends import friends, DEFAULT_RATE_LIMIT_PER_MIN

logger = logging.getLogger(__name__)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8081
_TASK_CACHE_MAX = 1000
_MAX_PENDING = 10
_RESPONSE_TIMEOUT = 120  # seconds to wait for agent response
_STATE_KEY = "_hermes_a2a_runtime_state"
_PROCESS_PROVENANCE_DIGEST_KEY = secrets.token_hex(32)
_FALSE_VALUES = frozenset({"0", "false", "no"})
_STRANGER_AGENT_CARD_HEADERS = ("Agent-Card-URL", "A2A-Agent-Card-URL")
_stranger_store = None

try:
    from hermes_cli import __version__ as HERMES_VERSION
except Exception:
    HERMES_VERSION = "0.0.0"


def _localhost_dev_trust_active() -> bool:
    """Whether the dev-only localhost trust escape hatch is active right now.

    Enable with ``A2A_DEV_LOCALHOST_TRUST_UNTIL=YYYY-MM-DD`` (or full ISO
    timestamp). Date-bounded so it cannot be silently left on forever — the
    classic foot-gun if the maintainer later exposes the local port via
    ngrok or similar.

    The bare ``A2A_DEV_LOCALHOST_TRUST=true`` form is intentionally NOT
    honoured. If it is set without an ``_UNTIL`` value we emit a one-time
    warning telling the maintainer to migrate.
    """
    raw_until = os.getenv("A2A_DEV_LOCALHOST_TRUST_UNTIL", "").strip()
    if raw_until:
        try:
            if "T" in raw_until:
                deadline_date = datetime.fromisoformat(
                    raw_until.replace("Z", "+00:00")
                ).date()
            else:
                deadline_date = date.fromisoformat(raw_until)
        except ValueError:
            logger.warning(
                "[A2A] A2A_DEV_LOCALHOST_TRUST_UNTIL=%r is not a valid date; ignoring",
                raw_until,
            )
            return False
        today = datetime.now(timezone.utc).date()
        return today <= deadline_date

    if os.getenv("A2A_DEV_LOCALHOST_TRUST", "").lower() == "true":
        logger.warning(
            "[A2A] A2A_DEV_LOCALHOST_TRUST=true without an _UNTIL date is "
            "ignored. Set A2A_DEV_LOCALHOST_TRUST_UNTIL=YYYY-MM-DD to opt in "
            "to a date-bounded localhost trust window."
        )
    return False


def _provenance_digest_key() -> str:
    """Local key material for replay digests stored in internal provenance."""
    env_key = (
        os.getenv("A2A_PROVENANCE_DIGEST_KEY", "")
        or os.getenv("A2A_WEBHOOK_SECRET", "")
        or os.getenv("A2A_AUTH_TOKEN", "")
    )
    if env_key:
        return env_key

    key_path = provenance_key_path()
    try:
        if key_path.exists():
            existing = key_path.read_text(encoding="utf-8").strip()
            if existing:
                return existing
        key_path.parent.mkdir(parents=True, exist_ok=True)
        generated = secrets.token_hex(32)
        key_path.write_text(generated + "\n", encoding="utf-8")
        try:
            key_path.chmod(0o600)
        except OSError:
            pass
        return generated
    except OSError:
        logger.warning("[A2A] Could not persist provenance digest key; using process-local key")
        return _PROCESS_PROVENANCE_DIGEST_KEY


def _stranger_capture_enabled() -> bool:
    return os.getenv("A2A_STRANGER_CAPTURE", "").strip().lower() not in _FALSE_VALUES


def _stranger_card_fetch_enabled() -> bool:
    return os.getenv("A2A_STRANGER_CARD_FETCH", "").strip().lower() not in _FALSE_VALUES


def _get_stranger_store():
    global _stranger_store
    if _stranger_store is None:
        from .strangers import StrangerStore

        _stranger_store = StrangerStore(digest_key=_provenance_digest_key())
    return _stranger_store


def _stranger_agent_card_header(headers) -> str:
    for name in _STRANGER_AGENT_CARD_HEADERS:
        value = headers.get(name, "")
        if value:
            return value
    return ""


def _fetch_stranger_agent_card(url: str) -> dict:
    from .strangers import fetch_stranger_agent_card

    return fetch_stranger_agent_card(url)


def _should_fetch_stranger_agent_card(capture_result: dict) -> bool:
    if not _stranger_card_fetch_enabled():
        return False
    if not capture_result.get("stored"):
        return False
    if capture_result.get("blocked") or capture_result.get("rate_limited"):
        return False
    request = capture_result.get("request")
    if not isinstance(request, dict) or not request.get("agent_card_url"):
        return False
    fetch = request.get("agent_card_fetch")
    if isinstance(fetch, dict) and fetch.get("status", "none") != "none":
        return False
    return True


class _PendingTask:
    __slots__ = ("task_id", "text", "metadata", "response", "ready", "created_at")

    def __init__(self, task_id: str, text: str, metadata: dict):
        self.task_id = task_id
        self.text = text
        self.metadata = metadata
        self.response: Optional[str] = None
        self.ready = Event()
        self.created_at = time.time()


class TaskQueue:
    """Thread-safe queue for pending A2A tasks."""

    def __init__(self):
        self._pending: OrderedDict[str, _PendingTask] = OrderedDict()
        self._completed: OrderedDict[str, _PendingTask] = OrderedDict()
        self._lock = Lock()

    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending)

    def enqueue(self, task_id: str, text: str, metadata: dict) -> _PendingTask | None:
        task = _PendingTask(task_id, text, metadata)
        with self._lock:
            if task_id in self._pending:
                return None
            self._pending[task_id] = task
            while len(self._pending) > _TASK_CACHE_MAX:
                _, old = self._pending.popitem(last=False)
                old.response = "(dropped — queue overflow)"
                old.ready.set()
        return task

    def drain_pending(self, exclude: set[str] | None = None) -> list[_PendingTask]:
        with self._lock:
            if exclude:
                return [t for t in self._pending.values() if t.task_id not in exclude]
            return list(self._pending.values())

    def complete(self, task_id: str, response: str) -> None:
        with self._lock:
            task = self._pending.pop(task_id, None)
            if task:
                task.response = response
                task.ready.set()
                self._completed[task_id] = task
                while len(self._completed) > _TASK_CACHE_MAX:
                    self._completed.popitem(last=False)

    def cancel(self, task_id: str) -> None:
        with self._lock:
            task = self._pending.pop(task_id, None)
            if task:
                task.response = "(canceled)"
                task.ready.set()
                self._completed[task_id] = task

    def get_status(self, task_id: str) -> dict:
        with self._lock:
            if task_id in self._pending:
                return {"state": "working"}
            task = self._completed.get(task_id)
            if task:
                if task.response == "(canceled)":
                    return {"state": "canceled"}
                return {"state": "completed", "response": filter_outbound(task.response)}
        return {"state": "unknown"}

    def get_completed_task(self, task_id: str) -> _PendingTask | None:
        with self._lock:
            return self._completed.get(task_id)


def _runtime_state() -> dict:
    """Return process-wide A2A runtime state that survives plugin reloads."""
    state = getattr(builtins, _STATE_KEY, None)
    if not isinstance(state, dict):
        state = {}
        setattr(builtins, _STATE_KEY, state)

    queue = state.get("task_queue")
    if not _is_usable_task_queue(queue):
        state["task_queue"] = TaskQueue()
    state.setdefault("server", None)
    state.setdefault("thread", None)
    state.setdefault("owner_module", __name__)
    return state


def _is_usable_task_queue(queue) -> bool:
    """Accept queue objects created before plugin reload changed class identity."""
    return all(
        callable(getattr(queue, name, None))
        for name in (
            "pending_count",
            "enqueue",
            "drain_pending",
            "complete",
            "cancel",
            "get_status",
        )
    )


task_queue = _runtime_state()["task_queue"]


def get_runtime_state() -> dict:
    """Expose the process-wide runtime state to the plugin loader."""
    return _runtime_state()


def set_runtime_server(server, thread) -> None:
    state = _runtime_state()
    state["server"] = server
    state["thread"] = thread
    state["owner_module"] = __name__


def clear_runtime_server(server=None) -> None:
    state = _runtime_state()
    if server is not None and state.get("server") is not server:
        return
    state["server"] = None
    state["thread"] = None


def _trigger_webhook():
    """POST to the internal webhook to trigger an agent turn."""
    secret = os.getenv("A2A_WEBHOOK_SECRET", "")
    if not secret:
        return

    port = int(os.getenv("WEBHOOK_PORT", "8644"))
    body = json.dumps({"event_type": "a2a_inbound"}).encode()
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    target_url = _internal_webhook_url(port)
    try:
        _assert_internal_webhook_url(target_url, port)
    except RuntimeError as exc:
        logger.warning("[A2A] Skipping internal webhook trigger: %s", exc)
        return

    req = urllib.request.Request(
        target_url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature-256": sig,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            logger.debug("[A2A] Webhook trigger: %d", resp.status)
    except Exception as e:
        logger.debug("[A2A] Webhook trigger failed: %s", e)


def _internal_webhook_url(port: int) -> str:
    return f"http://127.0.0.1:{port}/webhooks/a2a_trigger"


def _assert_internal_webhook_url(url: str, port: int) -> None:
    parsed = urlparse(url)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.port != port
        or parsed.path != "/webhooks/a2a_trigger"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError("internal A2A webhook URL must stay hardcoded to 127.0.0.1")


class A2ARequestHandler(BaseHTTPRequestHandler):
    """Handles A2A HTTP requests."""

    server: "A2AServer"

    def log_message(self, format, *args):
        logger.debug("A2A HTTP: %s", format % args)

    def _send_json(self, data: dict, status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _check_auth(self) -> tuple[bool, Optional[dict], str]:
        """Authenticate the inbound request against FriendsStore.

        Returns ``(authenticated, friend, reason)``:

        - ``authenticated`` — True iff the request should proceed.
        - ``friend``        — the matched friend record (a dict copy) on
          success; the rejected friend record on policy denial; ``None`` if
          no friend was identified.
        - ``reason``        — short string suitable for audit logs:
          ``ok`` / ``unknown_token`` / ``no_token`` /
          ``friend_paused|blocked|expired|removed`` / ``localhost_dev``.

        Pending friends are accepted; the caller transitions them to
        ``active`` via ``friends.record_last_contact`` after the request is
        actually served.
        """
        auth_header = self.headers.get("Authorization", "")
        raw_token = ""
        if auth_header.startswith("Bearer "):
            raw_token = auth_header[7:].strip()

        if raw_token:
            match = friends.get_by_token(raw_token)
            if match is not None:
                status = match.get("status", "")
                if status in ("paused", "blocked", "expired", "removed"):
                    return False, match, f"friend_{status}"
                return True, match, "ok"
            return False, None, "unknown_token"

        if _localhost_dev_trust_active():
            remote = self.client_address[0]
            if remote in ("127.0.0.1", "::1"):
                return True, {
                    "id": "f_localhost",
                    "name": "localhost-dev",
                    "trust_level": "trusted",
                    "rate_limit_per_min": DEFAULT_RATE_LIMIT_PER_MIN,
                    "_synthetic": True,
                }, "localhost_dev"

        return False, None, "no_token"

    def _capture_stranger_auth_failure(self, friend: Optional[dict], reason: str) -> None:
        if not _stranger_capture_enabled():
            return
        try:
            store = _get_stranger_store()
            result = store.capture(
                client_ip=self.client_address[0],
                auth_reason=reason,
                agent_card_url_header=_stranger_agent_card_header(self.headers),
                matched_friend_id=(friend or {}).get("id", ""),
                matched_friend_name=(friend or {}).get("name", ""),
            )
            if _should_fetch_stranger_agent_card(result):
                request = result["request"]
                try:
                    projection = _fetch_stranger_agent_card(request["agent_card_url"])
                except Exception as exc:
                    logger.warning("[A2A] Failed to fetch stranger Agent Card", exc_info=True)
                    projection = {"status": "error", "reason_class": exc.__class__.__name__}
                store.update_agent_card_fetch(request["id"], projection)
        except Exception:
            logger.warning("[A2A] Failed to capture stranger auth failure", exc_info=True)

    def do_GET(self) -> None:
        if self.path == "/.well-known/agent.json":
            self._send_json(self.server.build_agent_card())
        elif self.path == "/health":
            self._send_json({
                "status": "ok",
                "agent": self.server.agent_name,
                "version": HERMES_VERSION,
            })
        else:
            self._send_json({"error": "Not found"}, 404)

    def do_POST(self) -> None:
        authed, friend, reason = self._check_auth()
        if not authed:
            self._capture_stranger_auth_failure(friend, reason)
            audit_data = {
                "client": self.client_address[0],
                "reason": reason,
            }
            if friend is not None:
                audit_data["friend_id"] = friend.get("id", "")
                audit_data["friend_name"] = friend.get("name", "")
            audit.log("auth_fail", audit_data)
            self._send_json(
                {"jsonrpc": "2.0", "error": {"code": -32000, "message": "Unauthorized"}, "id": None},
                401,
            )
            return

        # Per-friend rate limit. Synthetic localhost-dev gets the default cap.
        rate_key = friend.get("id") or self.client_address[0]
        rate_cap = friend.get("rate_limit_per_min") or DEFAULT_RATE_LIMIT_PER_MIN
        if not self.server.limiter.allow(rate_key, rate_cap):
            audit.log("rate_limited", {
                "client": self.client_address[0],
                "friend_id": friend.get("id", ""),
                "friend_name": friend.get("name", ""),
            })
            self._send_json(
                {"jsonrpc": "2.0", "error": {"code": -32000, "message": "Rate limit exceeded"}, "id": None},
                429,
            )
            return

        # Stash the friend on the handler so do_POST sub-handlers can read it
        # (audit metadata, friend identity overrides self-reported sender_name).
        self._friend = friend

        try:
            length = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            self._send_json(
                {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Content-Length"}, "id": None},
                400,
            )
            return

        if length <= 0 or length > 65536:
            self._send_json(
                {"jsonrpc": "2.0", "error": {"code": -32600, "message": f"Content-Length must be 1-65536, got {length}"}, "id": None},
                413 if length > 65536 else 400,
            )
            return

        try:
            body = json.loads(self.rfile.read(length))
        except Exception:
            self._send_json(
                {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": None},
                400,
            )
            return

        method = body.get("method", "")
        params = body.get("params", {})
        rpc_id = body.get("id")

        audit.log("rpc_request", {
            "method": method,
            "client": self.client_address[0],
            "friend_id": friend.get("id", ""),
            "friend_name": friend.get("name", ""),
        })

        # Pending → active transition (post-auth, after we know it's a real request).
        if friend.get("status") == "pending" and not friend.get("_synthetic"):
            try:
                friends.record_last_contact(friend["id"])
            except Exception:
                logger.debug("Failed to record last_contact for friend", exc_info=True)
        elif friend.get("id") and not friend.get("_synthetic"):
            # Already active/normal: still touch last_contact, but don't fail
            # the request if writing fails.
            try:
                friends.record_last_contact(friend["id"])
            except Exception:
                logger.debug("Failed to record last_contact for friend", exc_info=True)

        if method == "tasks/send":
            result = self._handle_task_send(params)
        elif method == "tasks/get":
            tid = params.get("id", "")
            task = task_queue.get_completed_task(tid)
            if task is not None:
                result = self._completion_result_for_task(task)
            else:
                status = task_queue.get_status(tid)
                result = {"id": tid, "status": {"state": status["state"]}}
        elif method == "tasks/cancel":
            tid = params.get("id", "")
            task_queue.cancel(tid)
            result = {"id": tid, "status": {"state": "canceled"}}
        else:
            self._send_json({
                "jsonrpc": "2.0",
                "error": {"code": -32601, "message": f"Method not found: {method}"},
                "id": rpc_id,
            })
            return

        self._send_json({"jsonrpc": "2.0", "result": result, "id": rpc_id})

    def _completion_result_for_task(self, task) -> dict:
        from .permission import evaluate_outbound

        response = task.response or ""
        prov = provenance.trusted_from_metadata(task.metadata, required=True)
        decision, _hop_count = evaluate_outbound(
            response,
            getattr(self, "_friend", None),
            provenance=prov,
            replay_texts=(task.text,),
        )
        if not decision.allow:
            audit.log("outbound_denied", {
                "target": "inbound_a2a_response",
                "friend_name": (getattr(self, "_friend", None) or {}).get("name", ""),
                "friend_id": (getattr(self, "_friend", None) or {}).get("id", ""),
                "reason": decision.reason,
                "hop_count": 0,
                "message_length": len(response),
                "provenance": decision.provenance,
            })
            return {
                "id": task.task_id,
                "status": {"state": "failed"},
                "artifacts": [{"parts": [{"type": "text", "text": f"Outbound denied: {decision.detail}"}], "index": 0}],
            }

        filtered = filter_outbound(response)
        audit.log("task_completed", {
            "task_id": task.task_id,
            "response_length": len(filtered),
            "provenance": decision.provenance,
        })
        return {
            "id": task.task_id,
            "status": {"state": "completed"},
            "artifacts": [{"parts": [{"type": "text", "text": filtered}], "index": 0}],
        }

    def _handle_task_send(self, params: dict) -> dict:
        task_id = params.get("id", str(uuid.uuid4()))
        message = params.get("message", {})

        text_parts = []
        for part in message.get("parts", []):
            if part.get("type") == "text":
                text_parts.append(part.get("text", ""))
        user_text = "\n".join(text_parts)

        if not user_text.strip():
            return {
                "id": task_id,
                "status": {"state": "failed"},
                "artifacts": [{"parts": [{"type": "text", "text": "Empty message"}], "index": 0}],
            }

        user_text = sanitize_inbound(user_text)
        metadata = provenance.sanitize_remote_metadata(message.get("metadata", {}))
        if "sender_name" not in metadata:
            metadata["sender_name"] = metadata.get("agent_name", f"agent-{self.client_address[0]}")
        raw_name = metadata.get("sender_name", "")
        metadata["sender_name"] = "".join(c for c in raw_name if c.isalnum() or c in "-_.@ ")[:64]
        metadata = provenance.attach_internal_provenance(
            metadata,
            provenance.Provenance.a2a_inbound(user_text, _provenance_digest_key()),
        )

        audit.log("task_received", {"task_id": task_id, "length": len(user_text)})

        if task_queue.pending_count() >= _MAX_PENDING:
            return {
                "id": task_id,
                "status": {"state": "failed"},
                "artifacts": [{"parts": [{"type": "text", "text": "Agent busy — too many pending tasks"}], "index": 0}],
            }

        task = task_queue.enqueue(task_id, user_text, metadata)
        if task is None:
            return {
                "id": task_id,
                "status": {"state": "failed"},
                "artifacts": [{"parts": [{"type": "text", "text": "Task ID already in use"}], "index": 0}],
            }

        threading.Thread(target=_trigger_webhook, daemon=True).start()

        task.ready.wait(timeout=_RESPONSE_TIMEOUT)

        if task.response is None:
            return {
                "id": task_id,
                "status": {"state": "working"},
                "artifacts": [{"parts": [{"type": "text", "text": "(processing — poll with tasks/get)"}], "index": 0}],
            }

        return self._completion_result_for_task(task)


class A2AServer(ThreadingHTTPServer):
    """Threaded HTTP server with A2A configuration.

    Each request runs in its own thread so tasks/send can block waiting
    for agent response without starving health checks and agent card requests.
    """

    daemon_threads = True

    def __init__(self, host: str, port: int):
        self.agent_name = os.getenv("A2A_AGENT_NAME", "hermes-agent")
        self.agent_description = os.getenv("A2A_AGENT_DESCRIPTION", "A self-improving AI agent powered by Hermes")
        self.auth_token = os.getenv("A2A_AUTH_TOKEN", "")
        self.limiter = RateLimiter()
        super().__init__((host, port), A2ARequestHandler)

    def build_agent_card(self) -> dict:
        host, port = self.server_address
        return {
            "name": self.agent_name,
            "description": self.agent_description,
            "url": f"http://{host}:{port}",
            "version": HERMES_VERSION,
            "protocol": "a2a",
            "protocolVersion": "0.2.0",
            "capabilities": {
                "streaming": False,
                "pushNotifications": False,
                "multiTurn": False,
                "structuredMetadata": True,
            },
            "skills": [
                {
                    "id": "general",
                    "name": "General Assistant",
                    "description": "General-purpose AI assistant with tool use, web search, and more",
                }
            ],
            "authentication": {
                "schemes": ["bearer"] if self.auth_token else [],
            },
        }
