"""Slash-command helpers for A2A maintainer workflows."""

from __future__ import annotations

import shlex
import logging
from typing import Iterable

from . import ssrf
from .friends import friends as default_friends, mask_token

logger = logging.getLogger(__name__)


_HELP = """A2A friends commands:
/a2a friends
/a2a friends add <name> [url] [options]
/a2a friends remove <name-or-id> --confirm
/a2a friends pause <name-or-id>
/a2a friends unpause <name-or-id>
/a2a friends block <name-or-id>
/a2a friends unblock <name-or-id>
/a2a friends rotate-token <name-or-id> --confirm
/a2a friends set-trust <name-or-id> <new|normal|trusted> [--confirm]
/a2a friends set-rate-limit <name-or-id> <int>
/a2a friends set-url <name-or-id> <url>
/a2a friends set-outbound-token <name-or-id> <token>
/a2a friends clear-private-url <name-or-id>"""


_USAGE = {
    "add": "Usage: /a2a friends add <name> [url] [options]",
    "remove": "Usage: /a2a friends remove <name-or-id> --confirm",
    "pause": "Usage: /a2a friends pause <name-or-id>",
    "unpause": "Usage: /a2a friends unpause <name-or-id>",
    "block": "Usage: /a2a friends block <name-or-id>",
    "unblock": "Usage: /a2a friends unblock <name-or-id>",
    "rotate-token": "Usage: /a2a friends rotate-token <name-or-id> --confirm",
    "set-trust": "Usage: /a2a friends set-trust <name-or-id> <new|normal|trusted> [--confirm]",
    "set-rate-limit": "Usage: /a2a friends set-rate-limit <name-or-id> <int>",
    "set-url": "Usage: /a2a friends set-url <name-or-id> <url>",
    "set-outbound-token": "Usage: /a2a friends set-outbound-token <name-or-id> <token>",
    "clear-private-url": "Usage: /a2a friends clear-private-url <name-or-id>",
}


class CommandError(ValueError):
    pass


def _split(raw_args: str | Iterable[str]) -> list[str]:
    if isinstance(raw_args, str):
        try:
            return shlex.split(raw_args)
        except ValueError as exc:
            raise CommandError(f"Could not parse command: {exc}") from exc
    return list(raw_args)


def _parse_options(
    tokens: list[str],
    *,
    value_options: set[str] | None = None,
    flag_options: set[str] | None = None,
) -> tuple[list[str], dict[str, str | bool]]:
    value_options = value_options or set()
    flag_options = flag_options or set()
    positionals: list[str] = []
    options: dict[str, str | bool] = {}
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if not token.startswith("--"):
            positionals.append(token)
            i += 1
            continue
        if token in flag_options:
            options[token] = True
            i += 1
            continue
        if token in value_options:
            if i + 1 >= len(tokens) or tokens[i + 1].startswith("--"):
                raise CommandError(f"Missing value for {token}")
            options[token] = tokens[i + 1]
            i += 2
            continue
        raise CommandError(f"Unknown option: {token}")
    return positionals, options


def _format_friend(friend: dict) -> str:
    lines = [
        f"{friend.get('display_name') or friend.get('name', 'unnamed')} [{friend.get('id', '')}]",
        f"  name: {friend.get('name', '')}",
        f"  status: {friend.get('status', '')}",
        f"  trust: {friend.get('trust_level', '')}",
    ]
    if friend.get("url"):
        lines.append(f"  url: {friend.get('url')}")
    if friend.get("allow_private_target"):
        lines.append(f"  private target: {friend.get('allow_private_target')}")
    if friend.get("last_contact"):
        lines.append(f"  last contact: {friend.get('last_contact')}")
    elif friend.get("expires_at"):
        lines.append(f"  expires: {friend.get('expires_at')}")
    return "\n".join(lines)


def _cmd_list(store) -> str:
    friends = store.list_friends()
    if not friends:
        return "No A2A friends configured."
    blocks = [f"Friends ({len(friends)})"]
    blocks.extend(_format_friend(friend) for friend in friends)
    return "\n\n".join(blocks)


def _bool_option(options: dict[str, str | bool], key: str) -> bool:
    return bool(options.get(key))


def _int_option(options: dict[str, str | bool], key: str, default: int) -> int:
    value = options.get(key)
    if value is None:
        return default
    try:
        return int(str(value))
    except ValueError as exc:
        raise CommandError(f"{key} must be an integer") from exc


def _cmd_add(tokens: list[str], store) -> str:
    positionals, options = _parse_options(
        tokens,
        value_options={"--display-name", "--outbound-token", "--rate-limit", "--notes", "--pending-days", "--reason"},
        flag_options={"--allow-private-url"},
    )
    if not positionals or len(positionals) > 2:
        raise CommandError(_USAGE["add"])
    if options.get("--reason") and not _bool_option(options, "--allow-private-url"):
        raise CommandError("--reason requires --allow-private-url")
    friend, inbound_token = store.add_friend(
        name=positionals[0],
        url=positionals[1] if len(positionals) == 2 else "",
        display_name=str(options.get("--display-name", "")),
        outbound_token=str(options.get("--outbound-token", "")),
        trust_level="new",
        rate_limit_per_min=_int_option(options, "--rate-limit", 20),
        notes=str(options.get("--notes", "")),
        pending_days=_int_option(options, "--pending-days", 14),
        allow_private_url=_bool_option(options, "--allow-private-url"),
        allow_private_reason=str(options.get("--reason", "")),
    )
    return "\n".join([
        f"Added friend {friend.get('display_name') or friend.get('name')}.",
        f"friend_id: {friend.get('id')}",
        f"status: {friend.get('status')}",
        f"trust_level: {friend.get('trust_level')}",
        "",
        f"Send this inbound token to {friend.get('display_name') or friend.get('name')} out-of-band:",
        inbound_token,
        "",
        "This token will not be shown again.",
    ])


def _cmd_status_mutation(tokens: list[str], store, command: str, method_name: str, label: str) -> str:
    positionals, _options = _parse_options(tokens)
    if len(positionals) != 1:
        raise CommandError(_USAGE[command])
    name_or_id = positionals[0]
    if not getattr(store, method_name)(name_or_id):
        return f"Friend not found: {name_or_id}"
    return f"{label} {name_or_id}."


def _cmd_remove(tokens: list[str], store) -> str:
    positionals, options = _parse_options(tokens, flag_options={"--confirm"})
    if len(positionals) != 1:
        raise CommandError(_USAGE["remove"])
    if not _bool_option(options, "--confirm"):
        return "Refusing to remove friend without --confirm"
    name_or_id = positionals[0]
    if not store.remove_friend(name_or_id):
        return f"Friend not found: {name_or_id}"
    return f"Removed friend {name_or_id}."


def _cmd_rotate(tokens: list[str], store) -> str:
    positionals, options = _parse_options(tokens, flag_options={"--confirm"})
    if len(positionals) != 1:
        raise CommandError(_USAGE["rotate-token"])
    if not _bool_option(options, "--confirm"):
        return "Refusing to rotate token without --confirm"
    name_or_id = positionals[0]
    inbound_token = store.rotate_token(name_or_id)
    if inbound_token is None:
        return f"Friend not found: {name_or_id}"
    return "\n".join([
        f"Rotated inbound token for {name_or_id}.",
        "",
        "Send this to your friend out-of-band:",
        "I rotated your A2A inbound token. New token:",
        inbound_token,
        "Please update your outbound config for me.",
        "",
        "This token will not be shown again.",
    ])


def _cmd_set_trust(tokens: list[str], store) -> str:
    positionals, options = _parse_options(tokens, flag_options={"--confirm"})
    if len(positionals) != 2:
        raise CommandError(_USAGE["set-trust"])
    name_or_id, trust_level = positionals
    if trust_level == "trusted" and not _bool_option(options, "--confirm"):
        return "Refusing to set trust_level=trusted without --confirm"
    if not store.set_trust_level(name_or_id, trust_level):
        return f"Friend not found: {name_or_id}"
    return f"Set trust_level for {name_or_id} to {trust_level}."


def _cmd_set_rate_limit(tokens: list[str], store) -> str:
    positionals, _options = _parse_options(tokens)
    if len(positionals) != 2:
        raise CommandError(_USAGE["set-rate-limit"])
    name_or_id, value = positionals
    try:
        rate_limit = int(value)
    except ValueError as exc:
        raise CommandError("rate_limit_per_min must be an integer") from exc
    if not store.set_rate_limit(name_or_id, rate_limit):
        return f"Friend not found: {name_or_id}"
    return f"Set rate_limit_per_min for {name_or_id} to {rate_limit}."


def _cmd_set_url(tokens: list[str], store) -> str:
    positionals, _options = _parse_options(tokens)
    if len(positionals) != 2:
        raise CommandError(_USAGE["set-url"])
    name_or_id, url = positionals
    ssrf.validate_outbound_url(
        url,
        allow_private=False,
        allow_unconfigured=True,
        is_configured_friend=True,
        allow_env_private=False,
    )
    if not store.set_url(name_or_id, url):
        return f"Friend not found: {name_or_id}"
    return f"Set URL for {name_or_id}. Private URL approval cleared if the target changed."


def _cmd_set_outbound_token(tokens: list[str], store) -> str:
    positionals, _options = _parse_options(tokens)
    if len(positionals) != 2:
        raise CommandError(_USAGE["set-outbound-token"])
    name_or_id, token = positionals
    if not store.set_outbound_token(name_or_id, token):
        return f"Friend not found: {name_or_id}"
    return f"Updated outbound token for {name_or_id}.\nstored token: {mask_token(token)}"


def _cmd_clear_private(tokens: list[str], store) -> str:
    positionals, _options = _parse_options(tokens)
    if len(positionals) != 1:
        raise CommandError(_USAGE["clear-private-url"])
    name_or_id = positionals[0]
    if not store.clear_private_approval(name_or_id):
        return f"Friend not found: {name_or_id}"
    return f"Cleared private URL approval for {name_or_id}."


def _format_exception(exc: Exception) -> str:
    if isinstance(exc, CommandError):
        return str(exc)
    if isinstance(exc, ssrf.SSRFBlocked):
        return f"SSRF blocked: {exc}"
    if isinstance(exc, ssrf.DNSResolutionFailed):
        return f"DNS resolution failed: {exc}"
    if isinstance(exc, ssrf.RedirectBlocked):
        return str(exc)
    if isinstance(exc, ssrf.UnconfiguredURL):
        return str(exc)
    if isinstance(exc, ValueError):
        return str(exc)
    logger.exception("A2A friends command failed")
    return f"Command failed: {exc}"


def handle_friends_command(raw_args: str | Iterable[str], *, store=None) -> str:
    store = store or default_friends
    try:
        tokens = _split(raw_args)
        if not tokens or tokens[0] == "list":
            return _cmd_list(store)
        command, rest = tokens[0], tokens[1:]
        if command == "help":
            return _HELP
        if command == "add":
            return _cmd_add(rest, store)
        if command == "remove":
            return _cmd_remove(rest, store)
        if command == "pause":
            return _cmd_status_mutation(rest, store, command, "pause", "Paused friend")
        if command == "unpause":
            return _cmd_status_mutation(rest, store, command, "unpause", "Unpaused friend")
        if command == "block":
            return _cmd_status_mutation(rest, store, command, "block", "Blocked friend")
        if command == "unblock":
            return _cmd_status_mutation(rest, store, command, "unblock", "Unblocked friend")
        if command == "rotate-token":
            return _cmd_rotate(rest, store)
        if command == "set-trust":
            return _cmd_set_trust(rest, store)
        if command == "set-rate-limit":
            return _cmd_set_rate_limit(rest, store)
        if command == "set-url":
            return _cmd_set_url(rest, store)
        if command == "set-outbound-token":
            return _cmd_set_outbound_token(rest, store)
        if command == "clear-private-url":
            return _cmd_clear_private(rest, store)
        return f"Unknown friends command: {command}. Try /a2a friends help"
    except Exception as exc:
        return _format_exception(exc)
