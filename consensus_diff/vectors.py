"""consensus-spec-tests plumbing: archive cache, case walk, request building.

Written from docs/protocol.md and the clean-room behavior record; behavioral
divergences by design: atomic archive download, own cache dir, explicit
runner allowlist (alphabetical), no substring filtering.
"""

import collections
import re
import shutil
import sys
import tarfile
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import cramjam
import yaml

from consensus_diff.protocol import ForkChoiceRequest, GenericRequest, SszStaticRequest

PINNED_TAG = "v1.7.0-alpha.11"
CACHE_ROOT = Path("~/.cache/consensus-diff").expanduser()

#: Explicit allowlist (alphabetical) = GENERIC_RUNNERS + the two special
#: wire shapes. Named exclusions, same rationale as the ecosystem convention:
#: ssz_generic/bls/kzg/light_client/merkle_proof/networking/sync exercise
#: primitives owned elsewhere; fast_confirmation is future work — add here
#: deliberately, never collect silently.
IN_SCOPE_RUNNERS = (
    "epoch_processing", "finality", "fork", "fork_choice", "genesis",
    "operations", "random", "rewards", "sanity", "ssz_static", "transition",
)

#: fulu vectors for these runners need an Electra parent that no backend models.
FORK_CARVEOUTS: dict[str, frozenset[str]] = {"fulu": frozenset({"fork", "transition"})}


@dataclass(frozen=True)
class Case:
    preset: str
    fork: str
    runner: str
    handler: str
    suite: str
    name: str
    path: Path  # the case directory

    @property
    def id(self) -> str:
        return f"{self.preset}/{self.fork}/{self.runner}/{self.handler}/{self.suite}/{self.name}"


def ensure_archive(tag: str, preset: str) -> Path:
    """Download+extract once; atomic tarball write (tmp + rename), size check."""
    root = CACHE_ROOT / f"{tag}-{preset}"
    if (root / "tests").is_dir():
        return root
    CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    tarball = CACHE_ROOT / f"{tag}-{preset}.tar.gz"
    if not tarball.exists():
        url = f"https://github.com/ethereum/consensus-specs/releases/download/{tag}/{preset}.tar.gz"
        tmp = tarball.with_suffix(".part")
        print(f"  downloading {url} ...", file=sys.stderr)
        with urllib.request.urlopen(url) as resp, open(tmp, "wb") as out:
            shutil.copyfileobj(resp, out)
        if tmp.stat().st_size < 1_000_000:  # both presets are far larger; catch truncation
            tmp.unlink()
            raise RuntimeError(f"suspiciously small download for {url}")
        tmp.rename(tarball)
    tmp_root = root.with_name(root.name + ".extracting")
    if tmp_root.exists():
        shutil.rmtree(tmp_root)
    tmp_root.mkdir(parents=True)
    try:
        with tarfile.open(tarball) as tar:
            tar.extractall(tmp_root, filter="data")
    except tarfile.ReadError as exc:
        tarball.unlink()
        raise RuntimeError(
            f"corrupt tarball removed ({tarball}); re-run to re-download"
        ) from exc
    tmp_root.rename(root)
    return root


def walk_cases(
    root: Path,
    preset: str,
    fork: str,
    runners: tuple[str, ...] = IN_SCOPE_RUNNERS,
    subset: int = 2,
) -> Iterator[Case]:
    """Deterministic sorted walk of tests/<preset>/<fork>/<runner>/<handler>/<suite>/<case>.

    subset=N keeps the first N cases per (runner, handler) pair in walk
    order; subset=0 means everything.
    """
    fork_dir = Path(root) / "tests" / preset / fork
    if not fork_dir.is_dir():
        return
    carved = FORK_CARVEOUTS.get(fork, frozenset())
    admitted: collections.Counter[tuple[str, str]] = collections.Counter()
    for runner_dir in sorted(p for p in fork_dir.iterdir() if p.is_dir()):
        runner = runner_dir.name
        if runner not in runners or runner in carved:
            continue
        for handler_dir in sorted(p for p in runner_dir.iterdir() if p.is_dir()):
            for suite_dir in sorted(p for p in handler_dir.iterdir() if p.is_dir()):
                for case_dir in sorted(p for p in suite_dir.iterdir() if p.is_dir()):
                    if subset and admitted[(runner, handler_dir.name)] >= subset:
                        continue
                    admitted[(runner, handler_dir.name)] += 1
                    yield Case(preset, fork, runner, handler_dir.name,
                               suite_dir.name, case_dir.name, case_dir)


# --- request building (docs/protocol.md §3) ---

# Digits-only by design: a non-numeric blocks_* stem is corpus corruption we'd rather
# exclude loudly (count mismatch) than guess an order for.
_BLOCKS_RE = re.compile(r"^blocks_(\d+)$")

_REWARDS_ORDER = ("source_deltas", "target_deltas", "head_deltas", "inactivity_penalty_deltas")

_FC_CHECK_SUBKEYS = {
    "head": {"root", "slot", "payload_status"},
    "payload_timeliness_vote": {"block_root", "votes"},
    "payload_data_availability_vote": {"block_root", "votes"},
    "justified_checkpoint": {"epoch", "root"},
    "finalized_checkpoint": {"epoch", "root"},
}


def _decompress(case: Case, stem: str, workdir: Path) -> Path:
    src = case.path / f"{stem}.ssz_snappy"
    dst = workdir / f"{stem}.ssz"
    dst.write_bytes(bytes(cramjam.snappy.decompress_raw(src.read_bytes())))
    return dst


def _load_yaml(case: Case, name: str):
    p = case.path / name
    if not p.exists():
        return None
    return yaml.safe_load(p.read_text())


def _votes(seq) -> str:
    return ",".join("t" if v is True else "f" if v is False else "n" for v in seq)


def _valid_flag(step: dict) -> str:
    return "1" if step.get("valid", True) else "0"


def _check_lines(checks: dict, out: list[str], unsupported: list[str]) -> None:
    for key, val in checks.items():
        if key == "get_proposer_head":
            out.append(f"get_proposer_head {val}")
        elif key == "should_override_forkchoice_update":
            out.append("unsupported should_override_forkchoice_update")
        elif key == "head":
            out.append(f"head {val['root']} {val['slot']}")
            if "payload_status" in val:
                out.append(f"head_payload_status {val['payload_status']}")
            unsupported.extend(f"head.{k}" for k in sorted(set(val) - _FC_CHECK_SUBKEYS["head"]))
        elif key in ("payload_timeliness_vote", "payload_data_availability_vote"):
            out.append(f"{key} {val['block_root']} {_votes(val['votes'])}")
            unsupported.extend(f"{key}.{k}" for k in sorted(set(val) - _FC_CHECK_SUBKEYS[key]))
        elif key == "justified_checkpoint":
            out.append(f"justified {val['epoch']} {val['root']}")
            unsupported.extend(
                f"justified_checkpoint.{k}" for k in sorted(set(val) - _FC_CHECK_SUBKEYS[key])
            )
        elif key == "finalized_checkpoint":
            out.append(f"finalized {val['epoch']} {val['root']}")
            unsupported.extend(
                f"finalized_checkpoint.{k}" for k in sorted(set(val) - _FC_CHECK_SUBKEYS[key])
            )
        elif key == "proposer_boost_root":
            out.append(f"boost {val}")
        elif key == "time":
            out.append(f"time {val}")
        elif key == "genesis_time":
            out.append(f"genesis_time {val}")
        else:
            unsupported.append(key)


def build_fc_script(steps: list, resolve) -> str:
    """steps.yaml entries -> the newline-joined script (no trailing newline).

    ``resolve(stem)`` maps a vector-file stem to its decompressed path. Any
    unmodeled step or check key becomes an explicit ``unsupported`` line so
    the case lands in the todo bucket with an accurate reason, never a
    silent drop (docs/protocol.md §3.2).
    """
    # Script lines are space-delimited with embedded paths: protocol.md §3.2 requires
    # whitespace-free paths, which holds for our workdir/tmp layout.
    out: list[str] = []
    for step in steps:
        if "tick" in step:
            out.append(f"tick {step['tick']}")
        elif "block" in step:
            cols = ",".join(str(resolve(c)) for c in step.get("columns", [])) or "-"
            out.append(f"block {resolve(step['block'])} {_valid_flag(step)} {cols}")
        elif "attestation" in step:
            out.append(f"attestation {resolve(step['attestation'])} {_valid_flag(step)}")
        elif "attester_slashing" in step:
            out.append(
                f"attester_slashing {resolve(step['attester_slashing'])} {_valid_flag(step)}"
            )
        elif "execution_payload" in step:
            out.append(
                f"execution_payload {resolve(step['execution_payload'])} {_valid_flag(step)}"
            )
        elif "payload_attestation_message" in step:
            out.append(
                f"payload_attestation_message {resolve(step['payload_attestation_message'])} "
                f"{_valid_flag(step)}"
            )
        elif "checks" in step:
            unsupported: list[str] = []
            _check_lines(step["checks"], out, unsupported)
            if unsupported:
                out.append(f"unsupported {'/'.join(sorted(unsupported))}")
        else:
            keys = sorted(set(step) - {"valid", "columns"})
            out.append(f"unsupported {'/'.join(keys) or 'unknown-step'}")
    return "\n".join(out)


def prepare(case: Case, workdir: Path):
    """Decompress the case's files into workdir and build its request object."""
    workdir.mkdir(parents=True, exist_ok=True)
    snappy_stems = sorted(p.name.removesuffix(".ssz_snappy")
                          for p in case.path.glob("*.ssz_snappy"))

    if case.runner == "ssz_static":
        serialized = _decompress(case, "serialized", workdir)
        roots = _load_yaml(case, "roots.yaml") or {}
        return SszStaticRequest(handler=case.handler, serialized=serialized,
                                root=str(roots["root"]))

    if case.runner == "fork_choice":
        anchor_state = _decompress(case, "anchor_state", workdir)
        anchor_block = _decompress(case, "anchor_block", workdir)
        steps = _load_yaml(case, "steps.yaml")
        if steps is None:
            raise FileNotFoundError(f"{case.id}: fork_choice case without steps.yaml")
        done: dict[str, Path] = {}

        def resolve(stem: str) -> Path:
            if stem not in done:
                done[stem] = _decompress(case, stem, workdir)
            return done[stem]

        script = workdir / "fc_script.txt"
        script.write_text(build_fc_script(steps, resolve))
        return ForkChoiceRequest(handler=case.handler, anchor_state=anchor_state,
                                 anchor_block=anchor_block, script=script)

    # generic 10-field shape
    meta = _load_yaml(case, "meta.yaml") or {}
    pre = _decompress(case, "pre", workdir) if "pre" in snappy_stems else None
    post = _decompress(case, "post", workdir) if "post" in snappy_stems else None

    blocks = sorted(
        (int(m.group(1)), s) for s in snappy_stems if (m := _BLOCKS_RE.match(s))
    )
    inputs = [_decompress(case, stem, workdir) for _, stem in blocks]

    if case.runner == "operations":
        operands = [s for s in snappy_stems
                    if s not in ("pre", "post") and not _BLOCKS_RE.match(s)]
        if operands:
            inputs.append(_decompress(case, operands[0], workdir))

    if (case.runner, case.handler) == ("sanity", "slots"):
        slots = int(_load_yaml(case, "slots.yaml"))
        blob = workdir / "slots_count.bin"
        blob.write_bytes(slots.to_bytes(max(1, (slots.bit_length() + 7) // 8), "big"))
        inputs.append(blob)

    if case.runner == "rewards":
        inputs.extend(_decompress(case, stem, workdir)
                      for stem in _REWARDS_ORDER if stem in snappy_stems)

    execution_valid = True
    if (case.runner, case.handler) == ("operations", "execution_payload"):
        execution = _load_yaml(case, "execution.yaml") or {}
        execution_valid = bool(execution.get("execution_valid", True))

    return GenericRequest(
        runner=case.runner,
        handler=case.handler,
        pre=pre,
        post=post,
        bls_setting=int(meta.get("bls_setting", 1)),
        blocks_count=int(meta.get("blocks_count", len(blocks))),
        fork_epoch=int(meta["fork_epoch"]) if "fork_epoch" in meta else None,
        inputs=tuple(inputs),
        fork_block=int(meta["fork_block"]) if "fork_block" in meta else None,
        execution_valid=execution_valid,
    )
