"""SSZ mutation fuzzer: sibling entry point over the differential core.

Phase 1 (reject-class): mutate a valid operations seed, present it with post
absent (protocol = "expect reject"), and any accept/reject disagreement between
the backends is a validity-boundary finding. Local / nightly only; never in CI.
"""

from dataclasses import dataclass

from consensus_diff.protocol import Verdict


@dataclass(frozen=True)
class Finding:
    case_id: str
    verdicts: dict[str, Verdict]
    seed_id: str
    rng_seed: int
    mutation: str


def signature(f: Finding) -> tuple:
    """Dedup key: runner/handler + the sorted per-backend (status, bucket_class) shape.
    Independent of which specific seed or field produced it."""
    _preset, _fork, runner, handler, *_ = f.case_id.split("/")
    shape = tuple(sorted(
        (name, v.status, v.bucket_class) for name, v in f.verdicts.items()
    ))
    return (runner, handler, shape)


def shrink(start, candidates, still_diverges):
    """Greedy shrink: repeatedly replace the current witness with the first smaller
    candidate that still diverges, until no candidate does. `candidates(x)` yields
    smaller attempts (most-reduced first); `still_diverges(x)` re-runs the classifier."""
    current = start
    changed = True
    while changed:
        changed = False
        for cand in candidates(current):
            if still_diverges(cand):
                current = cand
                changed = True
                break
    return current
