import dataclasses
import sys
from pathlib import Path

import pytest

from consensus_diff.backends import BackendSpec, HandshakeError, ServerClient
from consensus_diff.protocol import Verdict

FAKE = Path(__file__).parent / "fake_backend.py"


def spec(mode: str, timeout: float = 5.0) -> BackendSpec:
    return BackendSpec(
        name=f"fake-{mode}",
        cmd=(sys.executable, str(FAKE)),
        cwd=None,
        env={"FAKE_MODE": mode},
        forks=frozenset({"gloas"}),
        presets=frozenset({"minimal"}),
        timeout=timeout,
    )


def client(mode: str, tmp_path: Path, timeout: float = 5.0) -> ServerClient:
    return ServerClient(spec(mode, timeout), fork="gloas", preset="minimal", log_dir=tmp_path)


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
    with pytest.raises(HandshakeError):
        ServerClient(spec("badargv"), fork="gloas", preset="minimal", log_dir=tmp_path)


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
