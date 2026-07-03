from consensus_diff.compare import (
    AGREE_FAIL,
    AGREE_PASS,
    DISAGREE,
    INFRA,
    KNOWN,
    SKIPPED,
    UNCOVERED,
    classify,
)
from consensus_diff.protocol import Verdict


def v(status, bucket, detail=""):
    return Verdict(status, bucket, detail)


def test_agree_pass():
    a = classify({"lean": v("pass", "ok"), "rust": v("pass", "ok")})
    assert a.cls == AGREE_PASS


def test_agree_fail_same_bucket_class():
    a = classify({"lean": v("fail", "mismatch"), "rust": v("fail", "mismatch")})
    assert a.cls == AGREE_FAIL


def test_todo_anywhere_is_uncovered():
    a = classify({"lean": v("pass", "ok"), "rust": v("fail", "todo", "unsupported runner")})
    assert a.cls == UNCOVERED
    assert "rust" in a.reason


def test_skip_is_skipped():
    a = classify({"lean": v("fail", "skip", "not modeled"), "rust": v("pass", "ok")})
    assert a.cls == SKIPPED


def test_bug_is_infra():
    a = classify({"lean": v("fail", "bug", "server died twice"), "rust": v("pass", "ok")})
    assert a.cls == INFRA


def test_status_or_bucket_difference_disagrees():
    assert classify({"lean": v("pass", "ok"), "rust": v("fail", "mismatch")}).cls == DISAGREE
    assert classify({"lean": v("pass", "ok"), "rust": v("pass", "reject")}).cls == DISAGREE


def test_known_divergence_is_xfail_class():
    a = classify(
        {"lean": v("pass", "ok"), "rust": v("fail", "mismatch")},
        known_ids=frozenset({"minimal/gloas/operations/attestation/x/case_0"}),
        case_id="minimal/gloas/operations/attestation/x/case_0",
    )
    assert a.cls == KNOWN


def test_precedence_infra_beats_uncovered_beats_skipped():
    both = {"lean": v("fail", "bug"), "rust": v("fail", "todo")}
    assert classify(both).cls == INFRA
    both = {"lean": v("fail", "todo"), "rust": v("fail", "skip")}
    assert classify(both).cls == UNCOVERED


def test_other_buckets_never_silently_agree():
    a = classify({"lean": v("pass", "strange"), "rust": v("pass", "strange")})
    assert a.cls == AGREE_PASS  # same other:-class agrees...
    assert "other:strange" in a.reason  # ...but the reason surfaces the unpinned bucket
