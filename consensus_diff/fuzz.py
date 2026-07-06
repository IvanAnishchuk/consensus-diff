"""SSZ mutation fuzzer: sibling entry point over the differential core.

Phase 1 (reject-class): mutate a valid operations seed, present it with post
absent (protocol = "expect reject"), and any accept/reject disagreement between
the backends is a validity-boundary finding. Local / nightly only; never in CI.
"""

import argparse
import hashlib
import os
import random
import shutil
import tomllib
from collections import Counter
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path

from consensus_diff.backends import BackendSpec, spawn_clients
from consensus_diff.compare import DISAGREE, SKIPPED, classify
from consensus_diff.mutate import mutate_bytes, mutate_object
from consensus_diff.protocol import Verdict
from consensus_diff.vectors import is_operand_stem, prepare, walk_cases


def _expand(p) -> Path:
    """Resolve a leading ``~``. argparse hands ``--vector-root=~/x`` through as a
    literal ``~`` path, so every filesystem path the fuzzer accepts is run through
    this before use (the documented README run uses a ``~``-rooted cache dir)."""
    return Path(p).expanduser()


def load_known_ids(path) -> frozenset[str]:
    """Load the triaged known-divergence case ids exactly as the differential
    driver does (conftest.py): the ``id`` of each ``[[known]]`` entry. A missing
    file yields the empty set, so a repo without the file just reports everything.
    """
    p = Path(path)
    if not p.exists():
        return frozenset()
    data = tomllib.loads(p.read_text(encoding="utf-8"))
    return frozenset(e["id"] for e in data.get("known", []))


@dataclass(frozen=True)
class Finding:
    runner: str
    handler: str
    verdicts: dict[str, Verdict]
    reason: str  # the classifier's per-backend rendering (evidence; never re-parsed)
    seed_id: str
    rng_seed: int
    iteration: int
    mutation: str
    kind: str  # "disagree" (validity boundary) | "crash" (one-sided bug bucket)


@dataclass(frozen=True)
class FuzzResult:
    """The deduplicated findings, the per-class tally (the denominator), and the
    count of distinct requests actually submitted. Iterable / truthy over
    ``findings`` so a caller can treat it directly as the finding list."""

    findings: list[Finding]
    tally: Counter
    submitted: int = 0

    def __iter__(self):
        return iter(self.findings)

    def __len__(self) -> int:
        return len(self.findings)

    def __bool__(self) -> bool:
        return bool(self.findings)


def signature(f: Finding) -> tuple:
    """Dedup key: runner/handler + the sorted per-backend (status, bucket_class) shape.
    Independent of which specific seed or field produced it."""
    shape = tuple(sorted(
        (name, v.status, v.bucket_class) for name, v in f.verdicts.items()
    ))
    return (f.runner, f.handler, shape)


def render_fuzz_report(findings: list[Finding], fork: str, preset: str,
                       tally: Counter | None = None, submitted: int | None = None) -> str:
    """Markdown report: the per-class tally (the denominator — how many mutated
    requests were classified into what) followed by the deduplicated findings
    grouped by kind (disagree / crash)."""
    tally = tally if tally is not None else Counter()
    lines = [f"# consensus-diff fuzz findings — {fork} {preset}", "",
             f"- iterations classified: {sum(tally.values())}"]
    if submitted is not None:
        lines.append(f"- distinct requests submitted: {submitted}")
    lines += [f"- distinct findings: {len(findings)}", ""]
    if tally:
        lines.append("## tally")
        lines += [f"- {cls}: {count}" for cls, count in sorted(tally.items())]
        lines.append("")
    for kind in ("disagree", "crash"):
        group = sorted((f for f in findings if f.kind == kind), key=signature)
        if not group:
            continue
        lines.append(f"## {kind}")
        for f in group:
            lines += [f"### {f.runner}/{f.handler}",
                      f"- seed: `{f.seed_id}`  rng_seed={f.rng_seed}  "
                      f"iteration={f.iteration}  mutation={f.mutation}",
                      f"- verdicts: {f.reason}", ""]
    return "\n".join(lines) + "\n"


def _has_operand(case) -> bool:
    """True iff the operations case carries an operand file to mutate.

    An operand is the single snappy file whose stem is not ``pre``/``post`` and
    is not a ``blocks_N`` block (docs/protocol.md §3.1, field-8 assembly). The
    ``withdrawals`` handler carries only pre/post state, so it is skipped — there
    is nothing to mutate. The ``is_operand_stem`` predicate is shared with
    ``vectors.prepare`` so the two never disagree on what an operand is.
    """
    for p in case.path.glob("*.ssz_snappy"):
        if is_operand_stem(p.name.removesuffix(".ssz_snappy")):
            return True
    return False


def _mutate_seed(seed, schema, rng, workdir, bytes_only):
    """Build the seed's request via the tested ``prepare`` path, mutate its
    operations operand in place, and return ``(request, mutation_desc, mutated)``.

    ``prepare`` decompresses every input to a raw ``.ssz`` in ``workdir`` and
    assembles the 10-field line exactly as the differential driver does, so the
    fuzz request exercises the same live verdict verb the backends already
    answer. The operations operand is the last assembled input; we overwrite it
    with the mutated raw bytes (still a decompressed ``.ssz``, per protocol.md
    §3.1 field 8) and drop ``post`` so field 4 is absent — the "expect reject"
    signal that turns any accept/reject split into a validity-boundary finding.

    ``mutation_desc`` records what changed for the finding: ``"<field.path>=<value>"``
    for a schema-path mutation, or ``"bytes"`` for the byte-level path. When the
    container has no mutable uint leaf (sync_aggregate, consolidation_request,
    builder_exit_request), the schema mutator returns its empty-path sentinel and
    we fall back to the byte-level flip, so the operand is still mutated.

    ``mutated`` is the raw operand bytes just written to disk; the caller reuses
    them for the dedup hash rather than reading the file back.
    """
    req = prepare(seed, workdir)
    operand = req.inputs[-1]
    raw = operand.read_bytes()
    if bytes_only or schema is None:
        mutated, desc = mutate_bytes(raw, rng), "bytes"
    else:
        obj = schema.container_for(seed.runner, seed.handler).decode_bytes(raw)
        mutated_obj, op = mutate_object(obj, rng)
        if op.path:
            mutated, desc = mutated_obj.encode_bytes(), f"{'.'.join(op.path)}={op.value}"
        else:
            mutated, desc = mutate_bytes(raw, rng), "bytes"  # no uint leaf: byte fallback
    operand.write_bytes(mutated)
    return replace(req, post=None), desc, mutated


def _finding_kind(agreement, verdicts) -> str | None:
    """The finding class this iteration warrants, or ``None`` to record nothing.

    A ``DISAGREE`` is a validity-boundary finding. An *asymmetric* crash — at
    least one backend in the ``bug`` bucket (crash/timeout) but not all of them —
    is a one-sided-crash finding that ``classify()`` would otherwise fold into
    ``INFRA`` and mask; a symmetric all-bug iteration is just infra noise.
    """
    if agreement.cls == DISAGREE:
        return "disagree"
    bugged = [n for n, v in verdicts.items() if v.bucket_class == "bug"]
    if bugged and len(bugged) < len(verdicts):
        return "crash"
    return None


def run_reject_fuzz(*, backends_path, fork, preset, vector_root, log_dir,
                    iterations, rng_seed, mutate_bytes_only=False,
                    known_ids=frozenset()):
    """Fuzz the reject class: mutate operations seeds, submit each to every
    backend that covers ``(fork, preset)``, and collect the deduplicated
    accept/reject disagreements (and one-sided crashes).

    The schema (pyspec-aware) lane is used unless ``mutate_bytes_only`` — then
    only the byte-flip complement runs, so the out-of-band pyspec
    (``eth_consensus_specs``) is never imported. ``eth-remerkleable`` is a base
    dependency and is always present. Deterministic in ``rng_seed``. ``known_ids``
    reclassifies a triaged divergence as ``KNOWN`` (counted, not a fresh finding).
    """
    vector_root = _expand(vector_root)
    specs = [s for s in BackendSpec.load_all(backends_path)
             if fork in s.forks and preset in s.presets]
    if not specs:
        raise ValueError(f"no backend in {backends_path} covers {fork}/{preset}")
    schema = None
    if not mutate_bytes_only:
        # Lazy: importing Schema pulls the heavy pyspec (eth_consensus_specs).
        from consensus_diff.schema import Schema
        schema = Schema(fork, preset)
    seeds = [c for c in walk_cases(vector_root, preset, fork, runners=("operations",),
                                   subset=0) if _has_operand(c)]
    tally: Counter = Counter()
    seen = set()
    submitted: set = set()
    findings: list[Finding] = []
    # Nothing eligible to fuzz: bail before spawning clients. spawn_clients starts
    # subprocesses and runs handshakes, so doing it only to close them again on an
    # empty corpus is pure waste (gemini/copilot review).
    if not seeds:
        return FuzzResult(findings, tally, 0)
    # Pre-filter to seeds this Schema can decode/mutate, so every one of `iterations`
    # steps lands on a fuzzable seed instead of cycling onto unmapped handlers and
    # burning the budget on skips (gemini review). SKIPPED then counts unmapped seeds
    # once -- a stable corpus property -- rather than per-iteration skips that scaled
    # with `iterations`. Byte-only mode (schema is None) can fuzz every seed, so it
    # skips the filter.
    if schema is not None:
        n_all = len(seeds)
        seeds = [s for s in seeds if schema.knows(s.runner, s.handler)]
        if n_all > len(seeds):
            tally[SKIPPED] = n_all - len(seeds)
        if not seeds:
            return FuzzResult(findings, tally, 0)
    # One per-run workdir (#12): prepare overwrites the operand each iteration, so
    # the disk footprint stays bounded to a single dir instead of 1000 mut{i}/ ones.
    # The fork/preset/pid suffix keeps concurrent fuzz runs that share one log_dir
    # from corrupting each other's operand file, and the finally below removes it.
    workdir = Path(log_dir) / f"mut_{fork}_{preset}_{os.getpid()}"
    # spawn_clients closes any partially-spawned client if a later spawn raises;
    # the try/finally then closes them all even if Schema/iteration below raises.
    clients = spawn_clients(specs, fork, preset, log_dir)
    try:
        for i in range(iterations):
            seed = seeds[i % len(seeds)]  # every seed is mapped: pre-filtered above
            # Fresh per-iteration RNG so every mutation replays from (rng_seed, i).
            rng_i = random.Random(f"{rng_seed}:{i}")
            req, mutation, mutated = _mutate_seed(seed, schema, rng_i, workdir, mutate_bytes_only)
            # Dedup on the mutated operand bytes: the reused workdir keeps every
            # request line identical, and cycling the corpus re-derives the same
            # single-field mutations, so identical requests must not be resubmitted.
            key = (seed.id, hashlib.sha256(mutated).digest())
            if key in submitted:
                continue
            submitted.add(key)
            line = req.line()
            verdicts = {name: c.spec.canonicalize(c.submit(line))
                        for name, c in clients.items()}
            ag = classify(verdicts, known_ids=known_ids, case_id=seed.id)
            tally[ag.cls] += 1
            kind = _finding_kind(ag, verdicts)
            if kind is None:
                continue
            f = Finding(runner=seed.runner, handler=seed.handler, verdicts=verdicts,
                        reason=ag.reason, seed_id=seed.id, rng_seed=rng_seed,
                        iteration=i, mutation=mutation, kind=kind)
            sig = signature(f)
            if sig not in seen:
                seen.add(sig)
                findings.append(f)
    finally:
        for c in clients.values():
            c.close()
        shutil.rmtree(workdir, ignore_errors=True)
    return FuzzResult(findings, tally, len(submitted))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m consensus_diff.fuzz")
    p.add_argument("--backends", type=Path, default=Path("backends.toml"))
    p.add_argument("--fork", default="gloas")
    p.add_argument("--preset", default="minimal")
    p.add_argument("--vector-root", type=Path, required=True)
    p.add_argument("--iterations", type=int, default=1000)
    p.add_argument("--rng-seed", type=int, default=0)
    p.add_argument("--report-dir", type=Path, default=Path("reports"))
    p.add_argument("--known", type=Path, default=Path("known-divergences.toml"),
                   help="TOML of triaged known divergences to suppress (default: repo file)")
    a = p.parse_args(argv)
    backends_path, vector_root, report_dir = (
        _expand(a.backends), _expand(a.vector_root), _expand(a.report_dir))
    known_ids = load_known_ids(_expand(a.known))
    result = run_reject_fuzz(
        backends_path=backends_path, fork=a.fork, preset=a.preset,
        vector_root=vector_root, log_dir=report_dir / "logs",
        iterations=a.iterations, rng_seed=a.rng_seed, known_ids=known_ids,
    )
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = report_dir / f"{stamp}-{a.fork}-{a.preset}-fuzz.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_fuzz_report(result.findings, a.fork, a.preset,
                                      tally=result.tally, submitted=result.submitted),
                   encoding="utf-8")
    skipped = result.tally.get(SKIPPED, 0)
    print(f"{len(result.findings)} distinct findings, {result.submitted} requests "
          f"({skipped} unmapped seeds skipped) -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
