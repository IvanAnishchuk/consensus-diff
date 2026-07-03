from typing import get_args

import yaml

from consensus_diff.compare import AgreementClass
from consensus_diff.report import CLASS_ORDER, render_summary, write_census


def records():
    return [
        {"id": "minimal/gloas/operations/attestation/s/a", "class": "agree-pass",
         "reason": "", "verdicts": {"lean": {"status": "pass", "bucket": "ok", "detail": ""},
                                    "rust": {"status": "pass", "bucket": "ok", "detail": ""}}},
        {"id": "minimal/gloas/operations/attestation/s/b", "class": "disagree",
         "reason": "lean=pass/ok; rust=fail/mismatch (post differs)",
         "verdicts": {"lean": {"status": "pass", "bucket": "ok", "detail": ""},
                      "rust": {"status": "fail", "bucket": "mismatch", "detail": "post differs"}}},
        {"id": "minimal/gloas/sanity/blocks/s/c", "class": "uncovered",
         "reason": "todo on rust", "verdicts": {}},
        {"id": "minimal/gloas/operations/deposit/s/d", "class": "agree-fail",
         "reason": "all fail/mismatch", "verdicts": {}},
    ]


def test_census_is_a_yaml_stream(tmp_path):
    out = tmp_path / "census.yaml"
    write_census(records(), out)
    docs = list(yaml.safe_load_all(out.read_text()))
    assert len(docs) == 4 and docs[1]["class"] == "disagree"


def test_census_round_trips_hostile_reason(tmp_path):
    hostile = [{"id": "x", "class": "infra", "reason": "tab\there; (parens) --- and: colon",
                "verdicts": {}}]
    out = tmp_path / "h.yaml"
    write_census(hostile, out)
    (doc,) = yaml.safe_load_all(out.read_text())
    assert doc["reason"] == "tab\there; (parens) --- and: colon"


def test_class_order_covers_the_agreement_vocabulary():
    assert set(CLASS_ORDER) == set(get_args(AgreementClass))


def test_summary_counts_and_sections():
    text = render_summary(records(), fork="gloas", preset="minimal")
    assert "agree-pass: 1" in text and "disagree: 1" in text
    assert "operations/attestation/s/b" in text          # the disagreement is listed
    assert "agree-fail" in text and "operations/deposit" in text  # flagged section
    assert "| operations/attestation |" in text          # per-handler ledger row
