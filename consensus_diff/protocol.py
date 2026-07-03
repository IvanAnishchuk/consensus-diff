"""Wire codec for the pyspec conformance protocol.

Implements docs/protocol.md (written from the clean-room behavior record
docs/moonglass/pyspec-harness-behavior.md in ivan-epf-research — never from
etheorem's LGPL sources). Three request shapes; one response shape.
"""

from dataclasses import dataclass
from pathlib import Path

ABSENT = "-"

#: Normative bucket vocabulary (docs/protocol.md §5). Anything else is
#: normalized to ``other:<string>`` so unpinned vocabularies across backends
#: can never silently compare equal.
BUCKETS = frozenset({"ok", "mismatch", "reject", "accept-invalid", "reject-valid",
                     "todo", "skip", "bug", "?"})


def _opt_path(p: Path | None) -> str:
    return str(p) if p is not None else ABSENT


def _opt_int(n: int | None) -> str:
    return str(n) if n is not None else ABSENT


@dataclass(frozen=True)
class GenericRequest:
    """The 10-field request line shared by nine runners."""

    runner: str
    handler: str
    pre: Path | None
    post: Path | None
    bls_setting: int = 1
    blocks_count: int = 0
    fork_epoch: int | None = None
    inputs: tuple[Path, ...] = ()
    fork_block: int | None = None
    execution_valid: bool = True

    def line(self) -> str:
        return "\t".join([
            self.runner,
            self.handler,
            _opt_path(self.pre),
            _opt_path(self.post),
            str(self.bls_setting),
            str(self.blocks_count),
            _opt_int(self.fork_epoch),
            ",".join(str(p) for p in self.inputs),  # empty string when no inputs
            _opt_int(self.fork_block),
            "1" if self.execution_valid else "0",
        ])


@dataclass(frozen=True)
class ForkChoiceRequest:
    """The 8-field fork_choice line; fields 4-7 are fixed placeholders."""

    handler: str
    anchor_state: Path
    anchor_block: Path
    script: Path

    def line(self) -> str:
        return "\t".join([
            "fork_choice", self.handler, str(self.anchor_state),
            ABSENT, "1", "0", ABSENT,
            f"{self.anchor_block},{self.script}",
        ])


@dataclass(frozen=True)
class SszStaticRequest:
    """The 4-field ssz_static line: container name, bytes, expected root."""

    handler: str
    serialized: Path
    root: str

    def line(self) -> str:
        return "\t".join(["ssz_static", self.handler, str(self.serialized), self.root])


@dataclass(frozen=True)
class Verdict:
    status: str  # "pass" | "fail"
    bucket: str
    detail: str

    @classmethod
    def try_parse(cls, line: str) -> "Verdict | None":
        """Parse one response line; None for permitted non-protocol noise."""
        fields = line.rstrip("\r\n").split("\t")
        if fields[0] not in ("pass", "fail"):
            return None
        bucket = fields[1] if len(fields) > 1 and fields[1] else "?"
        detail = fields[2] if len(fields) > 2 else ""
        return cls(status=fields[0], bucket=bucket, detail=detail)

    @property
    def bucket_class(self) -> str:
        return self.bucket if self.bucket in BUCKETS else f"other:{self.bucket}"
