"""SSZ mutation fuzzer: sibling entry point over the differential core.

Phase 1 (reject-class): mutate a valid operations seed, present it with post
absent (protocol = "expect reject"), and any accept/reject disagreement between
the backends is a validity-boundary finding. Local / nightly only; never in CI.
"""

import random
from dataclasses import dataclass, replace
from pathlib import Path

from consensus_diff.backends import BackendSpec, ServerClient
from consensus_diff.compare import DISAGREE, classify
from consensus_diff.mutate import mutate_bytes, mutate_object
from consensus_diff.protocol import Verdict
from consensus_diff.vectors import prepare, walk_cases


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


def render_fuzz_report(findings: list[Finding], fork: str, preset: str) -> str:
    lines = [f"# consensus-diff fuzz findings — {fork} {preset}", "",
             f"- distinct findings: {len(findings)}", ""]
    for f in sorted(findings, key=signature):
        _p, _f, runner, handler, *_ = f.case_id.split("/")
        shape = "; ".join(f"{n}={v.status}/{v.bucket_class}"
                          for n, v in sorted(f.verdicts.items()))
        lines += [f"## {runner}/{handler}",
                  f"- seed: `{f.seed_id}`  rng_seed={f.rng_seed}  mutation={f.mutation}",
                  f"- verdicts: {shape}", ""]
    return "\n".join(lines) + "\n"


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


def _has_operand(case) -> bool:
    """True iff the operations case carries an operand file to mutate.

    An operand is the single snappy file whose stem is not ``pre``/``post`` and
    is not a ``blocks_*`` entry (docs/protocol.md §3.1, field-8 assembly). The
    ``withdrawals`` handler carries only pre/post state, so it is skipped — there
    is nothing to mutate.
    """
    for p in case.path.glob("*.ssz_snappy"):
        stem = p.name.removesuffix(".ssz_snappy")
        if stem not in ("pre", "post") and not stem.startswith("blocks_"):
            return True
    return False


def _mutate_seed(seed, schema, rng, workdir, bytes_only):
    """Build the seed's request via the tested ``prepare`` path, mutate its
    operations operand in place, and return the (post-stripped) request.

    ``prepare`` decompresses every input to a raw ``.ssz`` in ``workdir`` and
    assembles the 10-field line exactly as the differential driver does, so the
    fuzz request exercises the same live verdict verb the backends already
    answer. The operations operand is the last assembled input; we overwrite it
    with the mutated raw bytes (still a decompressed ``.ssz``, per protocol.md
    §3.1 field 8) and drop ``post`` so field 4 is absent — the "expect reject"
    signal that turns any accept/reject split into a validity-boundary finding.
    """
    req = prepare(seed, workdir)
    operand = req.inputs[-1]
    raw = operand.read_bytes()
    if bytes_only or schema is None:
        mutated = mutate_bytes(raw, rng)
    else:
        obj = schema.container_for(seed.runner, seed.handler).decode_bytes(raw)
        mutated_obj, _op = mutate_object(obj, rng)
        mutated = mutated_obj.encode_bytes()
    operand.write_bytes(mutated)
    return replace(req, post=None)


def run_reject_fuzz(*, backends_path, fork, preset, vector_root, log_dir,
                    iterations, rng_seed, mutate_bytes_only=False):
    """Fuzz the reject class: mutate operations seeds, submit each to every
    backend that covers ``(fork, preset)``, and collect the deduplicated
    accept/reject disagreements.

    The schema (pyspec-aware) lane is used unless ``mutate_bytes_only`` — then
    only the byte-flip complement runs, so no pyspec/eth-remerkleable object
    model is needed. Deterministic in ``rng_seed``.
    """
    specs = [s for s in BackendSpec.load_all(backends_path)
             if fork in s.forks and preset in s.presets]
    clients = {s.name: ServerClient(s, fork, preset, log_dir) for s in specs}
    schema = None
    if not mutate_bytes_only:
        # Lazy: importing Schema pulls the heavy pyspec (eth_consensus_specs).
        from consensus_diff.schema import Schema
        schema = Schema(fork, preset)
    rng = random.Random(rng_seed)
    seen = set()
    findings: list[Finding] = []
    try:
        seeds = [c for c in walk_cases(vector_root, preset, fork, runners=("operations",),
                                       subset=0) if _has_operand(c)]
        if not seeds:
            return findings
        for i in range(iterations):
            seed = seeds[i % len(seeds)]
            workdir = Path(log_dir) / f"mut{i}"
            workdir.mkdir(parents=True, exist_ok=True)
            req = _mutate_seed(seed, schema, rng, workdir, mutate_bytes_only)
            line = req.line()
            verdicts = {name: c.spec.canonicalize(c.submit(line))
                        for name, c in clients.items()}
            if classify(verdicts, case_id=seed.id).cls != DISAGREE:
                continue
            f = Finding(case_id=seed.id, verdicts=verdicts, seed_id=seed.id,
                        rng_seed=rng_seed, mutation=f"iter{i}")
            sig = signature(f)
            if sig not in seen:
                seen.add(sig)
                findings.append(f)
    finally:
        for c in clients.values():
            c.close()
    return findings
