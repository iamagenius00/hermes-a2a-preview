"""Tests for cross-process concurrency safety in plugin/friends.py.

Issue 4 Patch 1:
- ``fcntl.flock``-based cross-process lock around read-modify-write
- ``tempfile.mkstemp`` for unique tmp files (no .tmp collisions)

These tests use real subprocesses so they exercise OS-level file locking
behaviour, not just threading.Lock. Without the patch, both tests fail:

- ``test_concurrent_add_friend_no_lost_update``: lost-update race
  → only one of N concurrent add_friend() calls survives.
- ``test_concurrent_writes_no_orphan_tmp_files``: collision on the
  fixed ``.tmp`` filename → one tmp gets overwritten by another, and
  the failing rename leaves an orphan.

With the patch both tests pass deterministically.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _run_concurrent_adds(friends_path: Path, count: int) -> list[subprocess.Popen]:
    """Spawn ``count`` subprocesses that each add a uniquely-named friend.

    All subprocesses race the same friends.json. Each waits for a barrier
    file to appear before doing its add, so they collide as tightly as the
    OS allows. Returns the Popen list; caller waits and asserts exit codes.
    """
    barrier = friends_path.parent / "barrier"

    code = textwrap.dedent(
        f"""
        import sys, time
        from pathlib import Path
        sys.path.insert(0, {str(ROOT)!r})
        from plugin.friends import FriendsStore

        friend_name = sys.argv[1]
        barrier = Path({str(barrier)!r})
        # Wait for the test to release the barrier — synchronises start.
        for _ in range(500):
            if barrier.exists():
                break
            time.sleep(0.005)

        store = FriendsStore(path=Path({str(friends_path)!r}))
        record, raw = store.add_friend(name=friend_name)
        # Print the new friend's id so the parent can verify uniqueness.
        print(record["id"])
        """
    )

    procs = []
    for i in range(count):
        p = subprocess.Popen(
            [sys.executable, "-c", code, f"friend-{i}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        procs.append(p)
    # Brief delay to let all subprocs reach the barrier wait, then release.
    import time
    time.sleep(0.15)
    barrier.touch()
    return procs


def _wait_all(procs, timeout=20):
    failures = []
    outputs = []
    for p in procs:
        try:
            out, err = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            out, err = p.communicate()
            failures.append(f"timeout: stderr={err}")
            continue
        if p.returncode != 0:
            failures.append(f"rc={p.returncode}: stderr={err}")
        outputs.append(out.strip())
    return outputs, failures


def _run_with_barrier(
    friends_path: Path,
    payloads: list[str],
    stagger: float = 0.15,
) -> list[subprocess.Popen]:
    """Spawn one subprocess per payload; each waits for a barrier file
    before running, so they hit the read-modify-write window as closely
    in time as the OS schedules.

    Without this barrier two ``subprocess.Popen`` calls a few milliseconds
    apart can serialize entirely, making the test pass even when the
    cross-process lock is missing. Generic version of the
    ``_run_concurrent_adds`` pattern, for tests where each subprocess
    runs a different op.

    Each payload is a Python source string; the barrier wait + sys.path
    prelude are prepended automatically. Caller does ``communicate()``.
    """
    barrier = friends_path.parent / "barrier"

    procs = []
    for payload in payloads:
        prelude = textwrap.dedent(
            f"""
            import sys, time
            from pathlib import Path
            sys.path.insert(0, {str(ROOT)!r})
            _barrier = Path({str(barrier)!r})
            for _ in range(500):
                if _barrier.exists():
                    break
                time.sleep(0.005)
            """
        )
        code = prelude + textwrap.dedent(payload)
        p = subprocess.Popen(
            [sys.executable, "-c", code],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        procs.append(p)

    import time
    time.sleep(stagger)
    barrier.touch()
    return procs


# ── P1.1 — cross-process file lock ─────────────────────────────────────


def test_concurrent_add_friend_no_lost_update(tmp_path):
    """Five subprocesses race add_friend on the same store.

    Without the cross-process lock, several adds get lost because each
    subprocess reads the same baseline (empty), appends its own friend,
    and writes — last writer wins, earlier writers' friends vanish.

    With the lock, all five end up persisted.
    """
    friends_path = tmp_path / "friends.json"
    procs = _run_concurrent_adds(friends_path, count=5)
    outputs, failures = _wait_all(procs)
    assert not failures, f"subprocess failures: {failures}"

    # Inspect on-disk state directly so the assertion doesn't depend on
    # the same FriendsStore-loading code path being correct.
    assert friends_path.exists(), "friends.json missing"
    data = json.loads(friends_path.read_text(encoding="utf-8"))
    assert isinstance(data.get("friends"), list)
    names = sorted(f["name"] for f in data["friends"])
    expected = sorted(f"friend-{i}" for i in range(5))
    assert names == expected, (
        f"lost update: expected all 5 friends to persist; got {names}"
    )

    # Also check ids are unique.
    ids = [f["id"] for f in data["friends"]]
    assert len(set(ids)) == len(ids), f"duplicate ids: {ids}"


# ── P1.2 — unique tmp file names ───────────────────────────────────────


def test_concurrent_writes_no_orphan_tmp_files(tmp_path):
    """After concurrent writes, no orphan ``.tmp.*`` files should remain.

    Each writer's ``tempfile.mkstemp`` call gets a unique name, so the
    tmp gets renamed to friends.json on success and never leaks. With
    the previous fixed-``.tmp`` design, a slower writer's rename would
    fail (target moved) and leave an orphan tmp behind.
    """
    friends_path = tmp_path / "friends.json"
    procs = _run_concurrent_adds(friends_path, count=5)
    outputs, failures = _wait_all(procs)
    assert not failures, f"subprocess failures: {failures}"

    leftovers = list(tmp_path.glob(friends_path.name + ".tmp.*"))
    # Filter out very fresh in-flight tmp files (none should exist after
    # all subprocs returned, but be defensive against scheduler latency).
    persistent_orphans = [p for p in leftovers if p.exists()]
    assert not persistent_orphans, (
        f"orphan tmp files remain after concurrent writes: {persistent_orphans}"
    )


def test_lock_file_persists_after_writes(tmp_path):
    """The sidecar ``.lock`` file is created on first locked operation
    and stays around for reuse. It is NOT considered orphan."""
    friends_path = tmp_path / "friends.json"
    procs = _run_concurrent_adds(friends_path, count=2)
    outputs, failures = _wait_all(procs)
    assert not failures

    lock_file = friends_path.with_name(friends_path.name + ".lock")
    assert lock_file.exists(), "lock sidecar should be created and persist"


# ── orphan tmp sweep ──────────────────────────────────────────────────


def test_sweep_old_orphan_tmp_on_init(tmp_path):
    """A FriendsStore created with stale .tmp.* files in its dir should
    sweep them on init — but only if older than 60 seconds, so an
    in-flight writer's tmp is never destroyed."""
    from plugin.friends import FriendsStore

    friends_path = tmp_path / "friends.json"

    old_orphan = friends_path.with_name(friends_path.name + ".tmp.OLD")
    fresh_orphan = friends_path.with_name(friends_path.name + ".tmp.FRESH")
    old_orphan.write_text("garbage")
    fresh_orphan.write_text("garbage")

    # Backdate the old orphan to 2 hours ago.
    old_ts = old_orphan.stat().st_mtime - 7200
    os.utime(old_orphan, (old_ts, old_ts))

    FriendsStore(path=friends_path)  # __init__ runs the sweep

    assert not old_orphan.exists(), "old orphan should have been swept"
    assert fresh_orphan.exists(), "fresh orphan must NOT be swept (live writer's tmp)"


def test_init_sweep_skipped_when_writer_holds_lock(tmp_path):
    """Sweep must NOT delete the active writer's tmp.

    Hold the file lock from the test process, then have a child process
    try to init a FriendsStore (which runs sweep). The sweep must NOT
    fight us for the lock — it uses LOCK_NB and skips if held.
    """
    from plugin.friends import FriendsStore
    import fcntl

    friends_path = tmp_path / "friends.json"
    lock_path = friends_path.with_name(friends_path.name + ".lock")

    # Plant an "active writer" tmp file that's already old (>60s) so a
    # naive sweep would happily delete it. With the lock held, it should
    # be untouched.
    fake_writer_tmp = friends_path.with_name(friends_path.name + ".tmp.WRITER")
    fake_writer_tmp.write_text("in-flight write")
    old_ts = fake_writer_tmp.stat().st_mtime - 7200
    os.utime(fake_writer_tmp, (old_ts, old_ts))

    # Acquire the file lock from this process; hold it.
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    held_lock = open(lock_path, "w")
    fcntl.flock(held_lock.fileno(), fcntl.LOCK_EX)

    try:
        # Child process tries to construct a FriendsStore. Its __init__
        # sweep should detect we hold the lock and SKIP, leaving the
        # planted "writer's" tmp intact.
        code = textwrap.dedent(
            f"""
            import sys
            from pathlib import Path
            sys.path.insert(0, {str(ROOT)!r})
            from plugin.friends import FriendsStore
            FriendsStore(path=Path({str(friends_path)!r}))
            """
        )
        rc = subprocess.run(
            [sys.executable, "-c", code], timeout=10, capture_output=True
        )
        assert rc.returncode == 0, f"child init failed: {rc.stderr.decode()}"
        assert fake_writer_tmp.exists(), (
            "sweep deleted active writer's tmp file despite lock held — "
            "P2.1 regression"
        )
    finally:
        fcntl.flock(held_lock.fileno(), fcntl.LOCK_UN)
        held_lock.close()


# ── concurrent rotate must not auth-gap ────────────────────────────────


def test_concurrent_rotate_no_lost_state(tmp_path):
    """Two subprocesses race: one rotates, one paused. Both effects must
    land — pause persists AND rotate produces a new token that
    invalidates the old one.

    Regression coverage: the previous version only checked
    ``inbound_token_hash starts with "sha256:"``, which was true even if
    rotate did nothing. This version captures the OLD raw token (from
    seed) and the NEW raw token (from rotate subprocess stdout) and
    asserts:
      - new != old
      - get_by_token(old) → None  (old invalidated)
      - get_by_token(new) → matches alice
      - status is paused (pause not clobbered)
    """
    from plugin.friends import FriendsStore

    friends_path = tmp_path / "friends.json"
    seed_store = FriendsStore(path=friends_path)
    _, old_raw = seed_store.add_friend(name="alice")
    # Sanity: old token is valid before rotate.
    assert seed_store.get_by_token(old_raw) is not None

    rotate_payload = f"""
        from plugin.friends import FriendsStore
        store = FriendsStore(path=Path({str(friends_path)!r}))
        new_raw = store.rotate_token("alice")
        # Print the new raw token to stdout so the parent can verify.
        print(new_raw)
    """
    pause_payload = f"""
        from plugin.friends import FriendsStore
        store = FriendsStore(path=Path({str(friends_path)!r}))
        store.pause("alice")
    """

    rotate_proc, pause_proc = _run_with_barrier(
        friends_path, [rotate_payload, pause_payload]
    )
    rotate_out, rotate_err = rotate_proc.communicate(timeout=15)
    pause_out, pause_err = pause_proc.communicate(timeout=15)
    assert rotate_proc.returncode == 0, f"rotate failed: {rotate_err}"
    assert pause_proc.returncode == 0, f"pause failed: {pause_err}"

    new_raw = rotate_out.strip()
    assert new_raw, "rotate subprocess did not print new token"
    assert new_raw != old_raw, "new token equals old token — rotate was a no-op"

    final = FriendsStore(path=friends_path)
    f = final.get_by_name("alice")
    assert f is not None
    assert f["status"] == "paused", (
        "pause was lost; rotate's read-modify-write clobbered status"
    )
    assert final.get_by_token(old_raw) is None, "old token still valid after rotate"
    matched = final.get_by_token(new_raw)
    assert matched is not None and matched["name"] == "alice", (
        "new token does not authenticate as alice"
    )


# ── more state-machine combos under concurrency ────────────────────────


def test_concurrent_add_and_remove_state_machine(tmp_path):
    """Concurrent ``add_friend(bob)`` and ``remove_friend(alice)``.

    Both operations should serialise; final state has bob present and
    alice absent. Without cross-process lock, one could clobber the other
    (e.g. add reads no-alice baseline, appends bob → writes; remove never
    sees bob and removes alice → writes; depending on order, bob or
    alice's absence might be lost).
    """
    from plugin.friends import FriendsStore

    friends_path = tmp_path / "friends.json"
    seed = FriendsStore(path=friends_path)
    seed.add_friend(name="alice")

    add_payload = f"""
        from plugin.friends import FriendsStore
        FriendsStore(path=Path({str(friends_path)!r})).add_friend(name="bob")
    """
    remove_payload = f"""
        from plugin.friends import FriendsStore
        FriendsStore(path=Path({str(friends_path)!r})).remove_friend("alice")
    """
    procs = _run_with_barrier(friends_path, [add_payload, remove_payload])
    for p in procs:
        out, err = p.communicate(timeout=15)
        assert p.returncode == 0, f"subprocess failed rc={p.returncode}: stderr={err}"

    final = FriendsStore(path=friends_path)
    names = {f["name"] for f in final.list_friends()}
    assert names == {"bob"}, (
        f"concurrent add+remove lost an operation; got {names}, expected {{'bob'}}"
    )


def test_concurrent_block_and_record_last_contact(tmp_path):
    """``block`` and ``record_last_contact`` race.

    Both write to the same friend record — block sets status=blocked,
    record_last_contact updates last_contact (and only flips pending→
    active; other statuses are untouched per its implementation).
    Under serialisation, both effects land regardless of ordering and
    the final status is blocked.

    Without cross-process lock, the lost-update window is:
    record_last_contact reads the alice record (sees status=active);
    block writes the record (status=blocked) before rlc writes back;
    rlc writes back its in-memory dict (still carrying status=active
    from its earlier read), clobbering block's blocked status. Note
    rlc itself does not actively *flip* an active status — it just
    rewrites the whole record using its stale baseline. With the lock,
    rlc and block serialise and final status is reliably blocked.
    """
    from plugin.friends import FriendsStore

    friends_path = tmp_path / "friends.json"
    seed = FriendsStore(path=friends_path)
    seed.add_friend(name="alice")
    seed.record_last_contact("alice")  # → active

    block_payload = f"""
        from plugin.friends import FriendsStore
        FriendsStore(path=Path({str(friends_path)!r})).block("alice")
    """
    rlc_payload = f"""
        from plugin.friends import FriendsStore
        FriendsStore(path=Path({str(friends_path)!r})).record_last_contact("alice")
    """
    procs = _run_with_barrier(friends_path, [block_payload, rlc_payload])
    for p in procs:
        out, err = p.communicate(timeout=15)
        assert p.returncode == 0, f"subprocess failed rc={p.returncode}: stderr={err}"

    final = FriendsStore(path=friends_path).get_by_name("alice")
    # Two valid serialisations:
    #  (a) block first, then rlc: status=blocked, last_contact updated
    #  (b) rlc first, then block: status=blocked, last_contact updated
    # In both cases status is blocked. record_last_contact only flips
    # pending → active (alice was already active, so it never flipped).
    assert final["status"] == "blocked", (
        f"block was lost or clobbered by record_last_contact; status={final['status']}"
    )
    assert final["last_contact"] is not None, "last_contact was lost"
