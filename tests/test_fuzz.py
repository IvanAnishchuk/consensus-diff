import random
import sys
import textwrap
from pathlib import Path

import cramjam
import pytest

from conftest import requires_pyspec
from consensus_diff.fuzz import (
    Finding,
    _expand,
    _mutate_seed,
    load_known_ids,
    render_fuzz_report,
    run_reject_fuzz,
    signature,
)
from consensus_diff.mutate import mutate_bytes
from consensus_diff.protocol import Verdict
from consensus_diff.vectors import Case


def _boundary_backends_toml(tmp_path) -> Path:
    """Two fake backends that disagree on every request (validity boundary)."""
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
    return backends


def _one_attestation_seed(tmp_path) -> None:
    case = tmp_path / "tests" / "minimal" / "gloas" / "operations" / "attestation" / "s" / "c1"
    case.mkdir(parents=True)
    (case / "pre.ssz_snappy").write_bytes(bytes(cramjam.snappy.compress_raw(b"PRE")))
    (case / "attestation.ssz_snappy").write_bytes(bytes(cramjam.snappy.compress_raw(b"OP")))

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
    f1 = Finding(runner="operations", handler="attestation", verdicts=v, reason="r1",
                 seed_id="minimal/gloas/operations/attestation/s/c1", rng_seed=1,
                 iteration=0, mutation="attestation.slot", kind="disagree")
    f2 = Finding(runner="operations", handler="attestation", verdicts=v, reason="r2",
                 seed_id="minimal/gloas/operations/attestation/s/c9", rng_seed=2,
                 iteration=5, mutation="attestation.slot", kind="disagree")
    # Same runner/handler + same disagree shape -> same signature (dedup).
    assert signature(f1) == signature(f2)
    # A different disagree shape -> different signature.
    v2 = {"etheorem": Verdict("pass", "ok", ""), "moonglass": Verdict("fail", "mismatch", "")}
    f3 = Finding(runner="operations", handler="attestation", verdicts=v2, reason="r3",
                 seed_id=f1.seed_id, rng_seed=1, iteration=0, mutation="x", kind="disagree")
    assert signature(f3) != signature(f1)


def test_reject_fuzz_finds_boundary_divergence(tmp_path):
    _one_attestation_seed(tmp_path)
    backends = _boundary_backends_toml(tmp_path)

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
    f = Finding(runner="operations", handler="attestation", verdicts=v,
                reason="etheorem=pass/reject; moonglass=fail/accept-invalid (boundary)",
                seed_id="minimal/gloas/operations/attestation/s/c1", rng_seed=42,
                iteration=0, mutation="attestation.slot", kind="disagree")
    text = render_fuzz_report([f], fork="gloas", preset="minimal")
    assert "operations/attestation" in text
    assert "rng_seed=42" in text          # reproducibility recorded
    assert "iteration=0" in text          # replays from (rng_seed, iteration)
    assert "mutation=attestation.slot" in text
    assert "etheorem=pass/reject" in text  # the classifier's reason, not a re-derived shape


@requires_pyspec
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

    req, desc, mutated = _mutate_seed(
        seed, schema, random.Random(0), tmp_path / "work", bytes_only=False)
    assert desc == "bytes"                            # sentinel path -> byte fallback
    assert mutated != original                        # operand actually mutated
    assert req.inputs[-1].read_bytes() == mutated     # and the mutated bytes were written to disk


def test_asymmetric_crash_is_a_crash_finding_and_report_shows_tally(tmp_path):
    _one_attestation_seed(tmp_path)
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


def test_load_known_ids_reads_toml(tmp_path):
    p = tmp_path / "known.toml"
    p.write_text('[[known]]\nid = "minimal/gloas/operations/attestation/s/c1"\nreason = "x"\n')
    assert load_known_ids(p) == frozenset({"minimal/gloas/operations/attestation/s/c1"})
    assert load_known_ids(tmp_path / "absent.toml") == frozenset()  # missing file -> empty


def test_repeated_request_is_not_submitted_twice(tmp_path):
    _one_attestation_seed(tmp_path)
    backends = tmp_path / "backends.toml"
    backends.write_text(textwrap.dedent(f"""
        [backends.a]
        cmd = ["{sys.executable}", "{FAKE}"]
        env = {{ FAKE_MODE = "ok" }}
        forks = ["gloas"]
        presets = ["minimal"]
        handshake_grace = 0.3

        [backends.b]
        cmd = ["{sys.executable}", "{FAKE}"]
        env = {{ FAKE_MODE = "ok" }}
        forks = ["gloas"]
        presets = ["minimal"]
        handshake_grace = 0.3
    """))
    iterations = 40
    result = run_reject_fuzz(
        backends_path=backends, fork="gloas", preset="minimal",
        vector_root=tmp_path, log_dir=tmp_path / "logs",
        iterations=iterations, rng_seed=1, mutate_bytes_only=True,
    )
    # "OP" is 2 bytes; single-bit flips give <=16 distinct operands, so the cycling
    # corpus repeats and dedup must fire: distinct submissions < iterations.
    expected = {mutate_bytes(b"OP", random.Random(f"1:{i}")) for i in range(iterations)}
    assert result.submitted == len(expected)
    assert result.submitted < iterations
    # #12: the per-run workdir is removed in finally, so no mut* dir is leaked.
    assert not list((tmp_path / "logs").glob("mut*"))


def test_known_divergence_is_not_a_new_finding(tmp_path):
    _one_attestation_seed(tmp_path)
    backends = _boundary_backends_toml(tmp_path)
    seed_id = "minimal/gloas/operations/attestation/s/c1"
    common = dict(backends_path=backends, fork="gloas", preset="minimal",
                  vector_root=tmp_path, log_dir=tmp_path / "logs",
                  iterations=3, rng_seed=42, mutate_bytes_only=True)
    # Control: an unlisted boundary split is a fresh finding.
    control = run_reject_fuzz(**common, known_ids=frozenset())
    assert control.findings
    # Listed in the known set: counted as KNOWN, never a fresh finding.
    result = run_reject_fuzz(**common, known_ids=frozenset({seed_id}))
    assert not result.findings
    assert result.tally.get("known", 0) >= 1
