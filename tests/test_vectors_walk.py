from pathlib import Path

from consensus_diff.protocol import GENERIC_RUNNERS
from consensus_diff.vectors import IN_SCOPE_RUNNERS, walk_cases


def make_tree(root: Path, entries: list[str]) -> Path:
    """entries are 'runner/handler/suite/case' under tests/minimal/gloas/."""
    for e in entries:
        (root / "tests" / "minimal" / "gloas" / e).mkdir(parents=True)
    return root


def test_allowlist_is_the_documented_eleven():
    assert IN_SCOPE_RUNNERS == (
        "epoch_processing", "finality", "fork", "fork_choice", "genesis",
        "operations", "random", "rewards", "sanity", "ssz_static", "transition",
    )


def test_allowlist_agrees_with_the_wire_shapes():
    assert set(IN_SCOPE_RUNNERS) == GENERIC_RUNNERS | {"fork_choice", "ssz_static"}


def test_walk_is_sorted_filtered_and_identified(tmp_path):
    make_tree(tmp_path, [
        "operations/attestation/pyspec_tests/case_b",
        "operations/attestation/pyspec_tests/case_a",
        "bls/verify/small/one",            # out of scope: never collected
        "sanity/blocks/pyspec_tests/x",
    ])
    ids = [c.id for c in walk_cases(tmp_path, "minimal", "gloas", subset=0)]
    assert ids == [
        "minimal/gloas/operations/attestation/pyspec_tests/case_a",
        "minimal/gloas/operations/attestation/pyspec_tests/case_b",
        "minimal/gloas/sanity/blocks/pyspec_tests/x",
    ]


def test_subset_is_per_runner_handler_pair(tmp_path):
    make_tree(tmp_path, [
        "operations/attestation/suite_a/c1",
        "operations/attestation/suite_a/c2",
        "operations/attestation/suite_b/c3",
        "operations/deposit/suite_a/c1",
    ])
    ids = [c.id for c in walk_cases(tmp_path, "minimal", "gloas", subset=2)]
    assert ids == [
        "minimal/gloas/operations/attestation/suite_a/c1",
        "minimal/gloas/operations/attestation/suite_a/c2",
        "minimal/gloas/operations/deposit/suite_a/c1",
    ]


def test_fulu_fork_and_transition_carved_out(tmp_path):
    for e in ["fork/fork/suite/c", "transition/core/suite/c", "sanity/slots/suite/c"]:
        (tmp_path / "tests" / "minimal" / "fulu" / e).mkdir(parents=True)
    ids = [c.id for c in walk_cases(tmp_path, "minimal", "fulu", subset=0)]
    assert ids == ["minimal/fulu/sanity/slots/suite/c"]


def test_missing_fork_dir_yields_nothing(tmp_path):
    (tmp_path / "tests" / "minimal").mkdir(parents=True)
    assert list(walk_cases(tmp_path, "minimal", "heze", subset=0)) == []
