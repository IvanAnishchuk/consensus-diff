from pathlib import Path

import pytest

from consensus_diff.protocol import (
    ForkChoiceRequest,
    GenericRequest,
    SszStaticRequest,
    Verdict,
)


def test_generic_line_all_fields_present():
    r = GenericRequest(
        runner="operations", handler="attestation",
        pre=Path("/t/pre.ssz"), post=Path("/t/post.ssz"),
        bls_setting=1, blocks_count=0, fork_epoch=None,
        inputs=(Path("/t/attestation.ssz"),), fork_block=None, execution_valid=True,
    )
    assert r.line() == (
        "operations\tattestation\t/t/pre.ssz\t/t/post.ssz\t1\t0\t-\t"
        "/t/attestation.ssz\t-\t1"
    )


def test_generic_line_absent_markers_and_empty_inputs():
    r = GenericRequest(
        runner="epoch_processing", handler="slashings",
        pre=Path("/t/pre.ssz"), post=None,
        bls_setting=2, blocks_count=0, fork_epoch=None,
        inputs=(), fork_block=None, execution_valid=False,
    )
    # post/fork_epoch/fork_block are '-', inputs is EMPTY STRING (two different absent markers)
    assert r.line() == "epoch_processing\tslashings\t/t/pre.ssz\t-\t2\t0\t-\t\t-\t0"


def test_fork_choice_line_fixed_placeholders():
    r = ForkChoiceRequest(
        handler="get_head", anchor_state=Path("/t/anchor_state.ssz"),
        anchor_block=Path("/t/anchor_block.ssz"), script=Path("/t/fc_script.txt"),
    )
    assert r.line() == (
        "fork_choice\tget_head\t/t/anchor_state.ssz\t-\t1\t0\t-\t"
        "/t/anchor_block.ssz,/t/fc_script.txt"
    )


def test_ssz_static_line():
    r = SszStaticRequest(handler="Attestation", serialized=Path("/t/serialized.ssz"), root="0xabcd")
    assert r.line() == "ssz_static\tAttestation\t/t/serialized.ssz\t0xabcd"


def test_verdict_parse_full_line():
    v = Verdict.try_parse("pass\tok\tall good\n")
    assert (v.status, v.bucket, v.detail) == ("pass", "ok", "all good")


def test_verdict_parse_defaults_and_noise():
    assert Verdict.try_parse("Building pyspec_server...") is None       # noise line
    assert Verdict.try_parse("fail").bucket == "?"                      # missing bucket
    assert Verdict.try_parse("pass\tok").detail == ""                   # missing detail
    assert Verdict.try_parse("fail\t\tx").bucket == "?"                 # empty bucket field


def test_verdict_bucket_class_normalization():
    assert Verdict("fail", "mismatch", "").bucket_class == "mismatch"
    assert Verdict("pass", "weird-server-string", "").bucket_class == "other:weird-server-string"


def test_generic_line_joins_multiple_inputs_with_commas():
    r = GenericRequest(
        runner="rewards", handler="basic",
        pre=Path("/t/pre.ssz"), post=None,
        inputs=(Path("/t/a.ssz"), Path("/t/b.ssz"), Path("/t/c.ssz")),
    )
    assert r.line().split("\t")[7] == "/t/a.ssz,/t/b.ssz,/t/c.ssz"


def test_generic_defaults_apply():
    r = GenericRequest(runner="sanity", handler="slots", pre=None, post=None)
    assert r.line() == "sanity\tslots\t-\t-\t1\t0\t-\t\t-\t1"


def test_generic_rejects_non_generic_runner():
    with pytest.raises(ValueError, match="fork_choice"):
        GenericRequest(runner="fork_choice", handler="x", pre=None, post=None)


def test_verdict_parse_preserves_tabs_in_detail():
    v = Verdict.try_parse("fail\tbug\tdetail\twith\ttabs")
    assert v.detail == "detail\twith\ttabs"


def test_verdict_parse_empty_and_crlf():
    assert Verdict.try_parse("") is None
    assert Verdict.try_parse("pass\tok\tfine\r\n").detail == "fine"
