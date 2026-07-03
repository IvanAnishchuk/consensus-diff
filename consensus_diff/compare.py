"""N-way agreement policy over per-backend verdicts.

Pure: verdicts in, agreement class out.

Precedence for mixed special bucket classes (infra > uncovered > skipped):
- Any backend with bucket class ``bug``  → INFRA   (infrastructure noise; not a real
  protocol disagreement and not a coverage gap — the run was corrupt).
- Any backend with bucket class ``todo`` → UNCOVERED (at least one backend hasn't
  implemented the case yet; no meaningful comparison is possible).
- Any backend with bucket class ``skip`` → SKIPPED  (out of scope for at least one
  backend; suppress from the diff table).
After the three special bucket classes are drained the remaining outcomes must all
share the same (status, bucket_class) pair to agree; anything else is DISAGREE
(or KNOWN, when the case_id is listed in the known-divergence set).

``known_ids`` only reclassifies *actual disagreements* — a case that happens to
appear in the known set but whose backends actually agree stays AGREE_PASS /
AGREE_FAIL, surfacing it as an xpass at the driver level.
"""

from dataclasses import dataclass
from typing import Literal

from consensus_diff.protocol import Verdict

AgreementClass = Literal[
    "agree-pass", "agree-fail", "uncovered", "skipped", "infra", "disagree", "known"
]

AGREE_PASS: AgreementClass = "agree-pass"
AGREE_FAIL: AgreementClass = "agree-fail"
UNCOVERED: AgreementClass = "uncovered"
SKIPPED: AgreementClass = "skipped"
INFRA: AgreementClass = "infra"
DISAGREE: AgreementClass = "disagree"
KNOWN: AgreementClass = "known"


@dataclass(frozen=True)
class Agreement:
    """One classified comparison result.

    ``cls`` is one of the seven AgreementClass values.
    ``reason`` is human-readable evidence for census records and failure messages —
    never machine-parsed.
    """

    cls: AgreementClass
    reason: str


def _backends_with(verdicts: dict[str, Verdict], bucket_class: str) -> list[str]:
    """Return sorted backend names whose verdict carries the given bucket_class."""
    return sorted(n for n, v in verdicts.items() if v.bucket_class == bucket_class)


def _render(verdicts: dict[str, Verdict]) -> str:
    """Human-readable summary: each backend's status/bucket_class (and detail)."""
    return "; ".join(
        f"{n}={v.status}/{v.bucket_class}" + (f" ({v.detail})" if v.detail else "")
        for n, v in sorted(verdicts.items())
    )


def classify(
    verdicts: dict[str, Verdict],
    known_ids: frozenset[str] = frozenset(),
    case_id: str = "",
) -> Agreement:
    """Classify N backend verdicts into a single Agreement.

    See module docstring for the full precedence story and the known-ids xpass
    subtlety.  A single-backend dict yields a vacuous agreement, deliberately
    (bring-up mode); an EMPTY dict is a driver bug and raises ValueError.
    """
    if not verdicts:
        raise ValueError("classify() needs at least one verdict (driver bug)")
    if bugs := _backends_with(verdicts, "bug"):
        return Agreement(INFRA, f"bug on {', '.join(bugs)}: {_render(verdicts)}")
    if todos := _backends_with(verdicts, "todo"):
        return Agreement(UNCOVERED, f"todo on {', '.join(todos)}: {_render(verdicts)}")
    if skips := _backends_with(verdicts, "skip"):
        return Agreement(SKIPPED, f"skip on {', '.join(skips)}: {_render(verdicts)}")

    outcomes = {(v.status, v.bucket_class) for v in verdicts.values()}
    if len(outcomes) == 1:
        status, _bucket_class = next(iter(outcomes))
        cls = AGREE_PASS if status == "pass" else AGREE_FAIL
        return Agreement(cls, _render(verdicts))

    if case_id and case_id in known_ids:
        return Agreement(KNOWN, _render(verdicts))
    return Agreement(DISAGREE, _render(verdicts))
