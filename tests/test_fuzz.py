import random
import sys
import textwrap
from pathlib import Path

import cramjam
import pytest

from consensus_diff.fuzz import (
    Finding,
    _expand,
    _mutate_seed,
    render_fuzz_report,
    run_reject_fuzz,
    shrink,
    signature,
)
from consensus_diff.protocol import Verdict
from consensus_diff.vectors import Case

FAKE = Path(__file__).parent / "fake_backend.py"


def test_expand_resolves_home_prefix():
    # argparse would hand "~/x" through literally; _expand must resolve it so the
    # documented README run (a ~-rooted cache dir) doesn't look under a "~" dir.
    p = _expand(Path("~/nonexistent-xyz"))
    assert not str(p).startswith("~")
    assert p == Path.home() / "nonexistent-xyz"


def test_run_reject_fuzz_rejects_uncovered_fork(tmp_path):
    backends = tmp_path / "backends.toml"
    backends.write_text(textwrap.dedent(f"""
        [backends.only-capella]
        cmd = ["{sys.executable}", "{FAKE}"]
        forks = ["capella"]
        presets = ["minimal"]
        handshake_grace = 0.3
    """))
    with pytest.raises(ValueError, match="no backend"):
        run_reject_fuzz(
            backends_path=backends, fork="gloas", preset="minimal",
            vector_root=tmp_path, log_dir=tmp_path / "logs",
            iterations=1, rng_seed=0, mutate_bytes_only=True,
        )


def test_signature_groups_same_shape_different_field():
    v = {
        "etheorem": Verdict("pass", "reject", "x"),
        "moonglass": Verdict("fail", "accept-invalid", "y"),
    }
    f1 = Finding(case_id="minimal/gloas/operations/attestation/c1", verdicts=v,
                 seed_id="c1", rng_seed=1, iteration=0, mutation="attestation.slot",
                 kind="disagree")
    f2 = Finding(case_id="minimal/gloas/operations/attestation/c9", verdicts=v,
                 seed_id="c9", rng_seed=2, iteration=5, mutation="attestation.slot",
                 kind="disagree")
    # Same runner/handler + same disagree shape -> same signature (dedup).
    assert signature(f1) == signature(f2)
    # A different disagree shape -> different signature.
    v2 = {"etheorem": Verdict("pass", "ok", ""), "moonglass": Verdict("fail", "mismatch", "")}
    f3 = Finding(case_id=f1.case_id, verdicts=v2, seed_id="c1", rng_seed=1, iteration=0,
                 mutation="x", kind="disagree")
    assert signature(f3) != signature(f1)


def test_shrink_reduces_to_minimal_still_diverging():
    # Candidates are ints; "diverges" iff value >= 10. Shrinker should walk down
    # to the smallest still-diverging candidate among those offered.
    def candidates(x):
        return [x - 1, x - 5] if x > 0 else []
    def still_diverges(x):
        return x >= 10
    assert shrink(100, candidates, still_diverges) == 10


def test_reject_fuzz_finds_boundary_divergence(tmp_path):
    # One operations/attestation seed in a throwaway vector root (adapt layout to walk_cases).
    case = tmp_path / "tests" / "minimal" / "gloas" / "operations" / "attestation" / "s" / "c1"
    case.mkdir(parents=True)
    (case / "pre.ssz_snappy").write_bytes(bytes(cramjam.snappy.compress_raw(b"PRE")))
    (case / "attestation.ssz_snappy").write_bytes(bytes(cramjam.snappy.compress_raw(b"OP")))

    backends = tmp_path / "backends.toml"
    backends.write_text(textwrap.dedent(f"""
        [backends.etheorem]
        cmd = ["{sys.executable}", "{FAKE}"]
        env = {{ FAKE_MODE = "reject-boundary" }}
        forks = ["gloas"]
        presets = ["minimal"]
        handshake_grace = 0.3

        [backends.moonglass]
        cmd = ["{sys.executable}", "{FAKE}"]
        env = {{ FAKE_MODE = "reject-boundary", FAKE_ACCEPTS = "1" }}
        forks = ["gloas"]
        presets = ["minimal"]
        handshake_grace = 0.3
    """))

    findings = run_reject_fuzz(
        backends_path=backends, fork="gloas", preset="minimal",
        vector_root=tmp_path, log_dir=tmp_path / "logs",
        iterations=3, rng_seed=42, mutate_bytes_only=True,
    )
    assert findings, "expected a validity-boundary divergence"
    assert all(f.verdicts.keys() == {"etheorem", "moonglass"} for f in findings)


def test_render_report_lists_findings_by_signature():
    v = {
        "etheorem": Verdict("pass", "reject", ""),
        "moonglass": Verdict("fail", "accept-invalid", ""),
    }
    f = Finding(case_id="minimal/gloas/operations/attestation/c1", verdicts=v,
                seed_id="c1", rng_seed=42, iteration=0, mutation="attestation.slot",
                kind="disagree")
    text = render_fuzz_report([f], fork="gloas", preset="minimal")
    assert "operations/attestation" in text
    assert "rng_seed=42" in text          # reproducibility recorded
    assert "iteration=0" in text          # replays from (rng_seed, iteration)
    assert "mutation=attestation.slot" in text
    assert "etheorem=pass/reject" in text


def test_mutate_seed_byte_fallback_for_uintless_container(tmp_path):
    # A container with no uint leaf (sync_aggregate) can't take a schema-path
    # mutation; _mutate_seed must fall back to the byte-level flip so it changes.
    from consensus_diff.schema import Schema  # heavy pyspec: lazy, keeps the module import-light

    schema = Schema(fork="gloas", preset="mainnet")
    original = schema.container_for("operations", "sync_aggregate")().encode_bytes()
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "pre.ssz_snappy").write_bytes(bytes(cramjam.snappy.compress_raw(b"PRE")))
    (case_dir / "sync_aggregate.ssz_snappy").write_bytes(
        bytes(cramjam.snappy.compress_raw(original)))
    seed = Case("mainnet", "gloas", "operations", "sync_aggregate", "s", "c0", case_dir)

    req, desc = _mutate_seed(seed, schema, random.Random(0), tmp_path / "work", bytes_only=False)
    assert desc == "bytes"                            # sentinel path -> byte fallback
    assert req.inputs[-1].read_bytes() != original    # operand actually mutated


def test_asymmetric_crash_is_a_crash_finding_and_report_shows_tally(tmp_path):
    case = tmp_path / "tests" / "minimal" / "gloas" / "operations" / "attestation" / "s" / "c1"
    case.mkdir(parents=True)
    (case / "pre.ssz_snappy").write_bytes(bytes(cramjam.snappy.compress_raw(b"PRE")))
    (case / "attestation.ssz_snappy").write_bytes(bytes(cramjam.snappy.compress_raw(b"OP")))
    backends = tmp_path / "backends.toml"
    backends.write_text(textwrap.dedent(f"""
        [backends.healthy]
        cmd = ["{sys.executable}", "{FAKE}"]
        env = {{ FAKE_MODE = "ok" }}
        forks = ["gloas"]
        presets = ["minimal"]
        handshake_grace = 0.3

        [backends.crasher]
        cmd = ["{sys.executable}", "{FAKE}"]
        env = {{ FAKE_MODE = "bug" }}
        forks = ["gloas"]
        presets = ["minimal"]
        handshake_grace = 0.3
    """))
    result = run_reject_fuzz(
        backends_path=backends, fork="gloas", preset="minimal",
        vector_root=tmp_path, log_dir=tmp_path / "logs",
        iterations=3, rng_seed=7, mutate_bytes_only=True,
    )
    assert result.findings, "a one-sided crash must be recorded, not masked as infra"
    assert all(f.kind == "crash" for f in result.findings)
    text = render_fuzz_report(result.findings, "gloas", "minimal", tally=result.tally)
    assert "## tally" in text and "infra:" in text   # denominator printed
    assert "## crash" in text
