"""One test per vector case: the outcome mapping over the agreement class."""

import pytest

from consensus_diff.compare import (
    AGREE_FAIL,
    AGREE_PASS,
    DISAGREE,
    INFRA,
    KNOWN,
    SKIPPED,
    UNCOVERED,
)


def test_case(diff_case, agreement):
    ag = agreement
    if ag.cls == INFRA:
        pytest.fail(f"{diff_case.id}: infra — {ag.reason}")
    elif ag.cls == UNCOVERED:
        pytest.xfail(f"coverage gap — {ag.reason}")
    elif ag.cls == SKIPPED:
        pytest.skip(f"unmodeled — {ag.reason}")
    elif ag.cls == KNOWN:
        pytest.xfail(f"known divergence — {ag.reason}")
    elif ag.cls == DISAGREE:
        pytest.fail(f"{diff_case.id}: DISAGREEMENT — {ag.reason}")
    else:
        assert ag.cls in (AGREE_PASS, AGREE_FAIL)
