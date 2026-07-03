"""Census stream (multi-document YAML) and the human summary.

Records are opaque data: ``reason`` is never parsed, only quoted through
``yaml.safe_dump_all`` (which escapes tabs and YAML syntax safely).
"""

import collections
from pathlib import Path

import yaml

CLASS_ORDER = ("agree-pass", "agree-fail", "uncovered", "skipped", "known", "disagree", "infra")


def write_census(records: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump_all(records, f, sort_keys=False)


def render_summary(records: list[dict], fork: str, preset: str) -> str:
    counts = collections.Counter(r["class"] for r in records)
    by_handler: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for r in records:
        _preset, _fork, runner, handler, *_ = r["id"].split("/")
        by_handler[f"{runner}/{handler}"][r["class"]] += 1

    lines = [f"# consensus-diff summary — {fork} {preset}", ""]
    lines += [f"- {cls}: {counts.get(cls, 0)}" for cls in CLASS_ORDER]
    for section, title in (("disagree", "Disagreements (findings)"),
                           ("infra", "Infra failures"),
                           ("agree-fail", "Agreed-but-failing (both diverge from vectors)")):
        picked = [r for r in records if r["class"] == section]
        if picked:
            lines += ["", f"## {title}", ""]
            lines += [f"- `{r['id']}` — {r['reason']}" for r in picked]
    lines += ["", "## Per-handler census (ledger feed)", "",
              "| runner/handler | " + " | ".join(CLASS_ORDER) + " |",
              "|---|" + "---|" * len(CLASS_ORDER)]
    for key in sorted(by_handler):
        row = by_handler[key]
        lines.append(f"| {key} | " + " | ".join(str(row.get(c, 0)) for c in CLASS_ORDER) + " |")
    return "\n".join(lines) + "\n"
