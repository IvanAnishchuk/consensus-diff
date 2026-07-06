import dataclasses
import sys
from pathlib import Path

import pytest

from consensus_diff import backends as backends_mod
from consensus_diff.backends import BackendSpec, HandshakeError, ServerClient, spawn_clients
from consensus_diff.protocol import Verdict

FAKE = Path(__file__).parent / "fake_backend.py"


def spec(mode: str, timeout: float = 5.0, handshake_grace: float = 0.3) -> BackendSpec:
    return BackendSpec(
        name=f"fake-{mode}",
        cmd=(sys.executable, str(FAKE)),
        cwd=None,
        env={"FAKE_MODE": mode},
        forks=frozenset({"gloas"}),
        presets=frozenset({"minimal"}),
        timeout=timeout,
        handshake_grace=handshake_grace,
    )


def client(
    mode: str, tmp_path: Path, timeout: float = 5.0, handshake_grace: float = 0.3
) -> ServerClient:
    return ServerClient(
        spec(mode, timeout, handshake_grace), fork="gloas", preset="minimal", log_dir=tmp_path
    )


def test_load_all_parses_toml(tmp_path):
    (tmp_path / "backends.toml").write_text(
        '[backends.demo]\n'
        'cmd = ["/bin/echo", "{preset}"]\n'
        'forks = ["gloas"]\npresets = ["minimal", "mainnet"]\ntimeout = 12.5\n'
        'env = { X = "1" }\n'
    )
    (s,) = BackendSpec.load_all(tmp_path / "backends.toml")
    assert s.name == "demo" and s.timeout == 12.5 and s.env == {"X": "1"}
    assert s.argv("gloas", "mainnet") == ["/bin/echo", "mainnet", "gloas", "mainnet"]


def test_submit_round_trip(tmp_path):
    c = client("ok", tmp_path)
    v = c.submit("operations\tattestation\t-\t-\t1\t0\t-\t\t-\t1")
    assert (v.status, v.bucket) == ("pass", "ok")
    c.close()


def test_noise_lines_are_drained(tmp_path):
    c = client("noise-then-ok", tmp_path)
    assert c.submit("x\ty").status == "pass"
    c.close()


def test_garbage_line_is_drained_and_answer_awaited(tmp_path):
    c = client("garbage", tmp_path, timeout=2.0)
    v = c.submit("x\ty")
    assert v.bucket == "bug"  # only a non-protocol line arrived, then silence -> timeout -> infra
    assert "timeout" in v.detail
    c.close()


def test_death_respawns_once_then_synthesizes_bug(tmp_path):
    c = client("die", tmp_path)
    v = c.submit("x\ty")
    assert (v.status, v.bucket) == ("fail", "bug")
    assert "died" in v.detail
    c.close()


def test_hang_times_out_to_bug(tmp_path):
    c = client("hang", tmp_path, timeout=1.0)
    v = c.submit("x\ty")
    assert v.bucket == "bug"
    assert "timeout" in v.detail
    c.close()


def test_bad_argv_fails_handshake(tmp_path):
    # Use a generous grace so the test is load-robust: bad backends exit essentially
    # instantly (event-driven wait), so 2.0s is only the safety ceiling, not the cost.
    with pytest.raises(HandshakeError):
        ServerClient(
            spec("badargv", handshake_grace=2.0), fork="gloas", preset="minimal", log_dir=tmp_path
        )


def test_death_once_recovers_via_respawn_and_resend(tmp_path):
    s = spec("die-once")
    s = dataclasses.replace(s, env={**s.env, "FAKE_DIE_ONCE_FLAG": str(tmp_path / "flag")})
    c = ServerClient(s, fork="gloas", preset="minimal", log_dir=tmp_path)
    v = c.submit("x\ty")
    assert (v.status, v.bucket) == ("pass", "ok")  # died once, respawned, resent, answered
    c.close()


def test_close_shuts_down_cleanly(tmp_path):
    c = client("ok", tmp_path)
    assert c.submit("x\ty").status == "pass"
    proc = c._proc
    c.close()
    assert proc.returncode == 0


def test_load_all_names_the_broken_table(tmp_path):
    (tmp_path / "b.toml").write_text(
        '[backends.broken]\nforks = ["gloas"]\npresets = ["minimal"]\n'
    )
    with pytest.raises(ValueError, match="backends.broken"):
        BackendSpec.load_all(tmp_path / "b.toml")


def test_buckets_alias_table_parsed(tmp_path):
    (tmp_path / "b.toml").write_text(
        '[backends.eth]\n'
        'cmd = ["/bin/echo"]\nforks = ["gloas"]\npresets = ["minimal"]\n'
        '[backends.eth.buckets]\n'
        'pass = "ok"\npassing = "ok"\n'
    )
    (s,) = BackendSpec.load_all(tmp_path / "b.toml")
    assert s.buckets == {"pass": "ok", "passing": "ok"}


def test_canonicalize_remaps_listed_bucket_only():
    s = BackendSpec(name="eth", cmd=("/bin/echo",), cwd=None,
                    env={}, forks=frozenset({"gloas"}), presets=frozenset({"minimal"}),
                    buckets={"pass": "ok", "passing": "ok"})
    assert s.canonicalize(Verdict("pass", "pass", "d")) == Verdict("pass", "ok", "d")
    assert s.canonicalize(Verdict("pass", "passing", "")) == Verdict("pass", "ok", "")
    # "reject" is not in the alias table — canonicalize is identity
    assert s.canonicalize(Verdict("pass", "reject", "")) == Verdict("pass", "reject", "")


def test_no_alias_table_is_identity():
    s = BackendSpec(name="m", cmd=("/bin/echo",), cwd=None,
                    env={}, forks=frozenset({"gloas"}), presets=frozenset({"minimal"}))
    v = Verdict("pass", "ok", "x")
    assert s.canonicalize(v) is v  # frozen, unchanged, same object


def test_slow_startup_failure_is_caught_within_grace(tmp_path):
    # grace 2.0 must catch a backend that exits 2 only after a 0.6s delay
    s = spec("slow-badargv", handshake_grace=2.0)
    with pytest.raises(HandshakeError):
        ServerClient(s, fork="gloas", preset="minimal", log_dir=tmp_path)


def test_spawn_clients_closes_partial_on_handshake_failure(tmp_path, monkeypatch):
    # The second backend fails its handshake; the first (already spawned and
    # healthy) must be closed, leaving no orphaned process.
    created: list[ServerClient] = []

    class Recording(ServerClient):
        def __init__(self, *args, **kwargs):
            created.append(self)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(backends_mod, "ServerClient", Recording)
    good = spec("ok", handshake_grace=0.3)
    bad = spec("badargv", handshake_grace=2.0)
    with pytest.raises(HandshakeError):
        spawn_clients([good, bad], "gloas", "minimal", tmp_path / "logs")
    assert created, "the first (good) client should have been constructed"
    assert created[0]._proc is None and created[0]._closed  # closed, no leak


def test_spawn_clients_rejects_duplicate_names(tmp_path, monkeypatch):
    # Two specs share a name: the dup is rejected before it spawns, and the first
    # (already spawned) client is closed, so a duplicate name never orphans a process.
    created: list[ServerClient] = []

    class Recording(ServerClient):
        def __init__(self, *args, **kwargs):
            created.append(self)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(backends_mod, "ServerClient", Recording)
    dup = spec("ok")
    with pytest.raises(ValueError, match="duplicate backend name"):
        spawn_clients([dup, dup], "gloas", "minimal", tmp_path / "logs")
    assert len(created) == 1  # the dup was rejected before a second spawn
    assert created[0]._proc is None and created[0]._closed  # first closed, no leak


def test_short_grace_would_miss_the_slow_failure(tmp_path):
    # documents the boundary: a 0.2s grace returns before the 0.6s exit,
    # so the slow-failing backend is (wrongly) treated as healthy — this is
    # why the default grace is generous. No HandshakeError here.
    s = spec("slow-badargv", handshake_grace=0.2)
    c = ServerClient(s, fork="gloas", preset="minimal", log_dir=tmp_path)
    c.close()
