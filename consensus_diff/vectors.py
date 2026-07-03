"""consensus-spec-tests plumbing: archive cache, case walk, request building.

Written from docs/protocol.md and the clean-room behavior record; behavioral
divergences by design: atomic archive download, own cache dir, explicit
runner allowlist (alphabetical), no substring filtering.
"""

import collections
import shutil
import tarfile
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

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

#: fulu vectors for these runners need an Electra parent no backend models.
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
        print(f"  downloading {url} ...")
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
    with tarfile.open(tarball) as tar:
        tar.extractall(tmp_root, filter="data")
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
    admitted: collections.Counter = collections.Counter()
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
