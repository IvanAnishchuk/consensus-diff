from pathlib import Path

import cramjam
import pytest
import yaml

from consensus_diff.protocol import ForkChoiceRequest, GenericRequest, SszStaticRequest
from consensus_diff.vectors import Case, build_fc_script, prepare


def put_snappy(case_dir: Path, stem: str, payload: bytes) -> None:
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / f"{stem}.ssz_snappy").write_bytes(bytes(cramjam.snappy.compress_raw(payload)))


def case(tmp_path: Path, runner: str, handler: str, name: str = "c0") -> Case:
    d = tmp_path / "vec" / runner / handler / "suite" / name
    d.mkdir(parents=True, exist_ok=True)
    return Case("minimal", "gloas", runner, handler, "suite", name, d)


def test_operations_case(tmp_path):
    c = case(tmp_path, "operations", "attestation")
    put_snappy(c.path, "pre", b"PRE")
    put_snappy(c.path, "post", b"POST")
    put_snappy(c.path, "attestation", b"OP")
    (c.path / "meta.yaml").write_text("bls_setting: 2\n")
    work = tmp_path / "work"
    r = prepare(c, work)
    assert isinstance(r, GenericRequest)
    assert r.bls_setting == 2 and r.blocks_count == 0 and r.execution_valid
    assert (work / "pre.ssz").read_bytes() == b"PRE"
    assert [p.name for p in r.inputs] == ["attestation.ssz"]


def test_invalid_vector_has_no_post_and_blocks_sort_numerically(tmp_path):
    c = case(tmp_path, "sanity", "blocks")
    put_snappy(c.path, "pre", b"PRE")
    for n in (0, 2, 10):
        put_snappy(c.path, f"blocks_{n}", b"B%d" % n)
    r = prepare(c, tmp_path / "w")
    assert r.post is None
    assert r.blocks_count == 3  # default: number of blocks_* files
    assert [p.name for p in r.inputs] == ["blocks_0.ssz", "blocks_2.ssz", "blocks_10.ssz"]


def test_meta_blocks_count_wins_over_file_count(tmp_path):
    c = case(tmp_path, "sanity", "blocks", name="c1")
    put_snappy(c.path, "pre", b"PRE")
    put_snappy(c.path, "blocks_0", b"B0")
    (c.path / "meta.yaml").write_text("blocks_count: 7\n")
    assert prepare(c, tmp_path / "w1").blocks_count == 7


def test_sanity_slots_encodes_minimal_big_endian(tmp_path):
    c = case(tmp_path, "sanity", "slots")
    put_snappy(c.path, "pre", b"PRE")
    put_snappy(c.path, "post", b"POST")
    (c.path / "slots.yaml").write_text("300\n")
    r = prepare(c, tmp_path / "w")
    (blob,) = r.inputs
    assert blob.name == "slots_count.bin"
    assert blob.read_bytes() == (300).to_bytes(2, "big")


def test_slots_zero_is_one_zero_byte(tmp_path):
    c = case(tmp_path, "sanity", "slots", name="c2")
    put_snappy(c.path, "pre", b"PRE")
    (c.path / "slots.yaml").write_text("0\n")
    r = prepare(c, tmp_path / "w")
    assert r.inputs[0].read_bytes() == b"\x00"


def test_rewards_deltas_fixed_order(tmp_path):
    c = case(tmp_path, "rewards", "basic")
    put_snappy(c.path, "pre", b"PRE")
    for stem in ("head_deltas", "source_deltas", "inactivity_penalty_deltas", "target_deltas"):
        put_snappy(c.path, stem, stem.encode())
    r = prepare(c, tmp_path / "w")
    assert [p.name for p in r.inputs] == [
        "source_deltas.ssz", "target_deltas.ssz", "head_deltas.ssz",
        "inactivity_penalty_deltas.ssz",
    ]


def test_execution_payload_reads_execution_yaml(tmp_path):
    c = case(tmp_path, "operations", "execution_payload")
    put_snappy(c.path, "pre", b"PRE")
    put_snappy(c.path, "body", b"BODY")
    (c.path / "execution.yaml").write_text("execution_valid: false\n")
    r = prepare(c, tmp_path / "w")
    assert not r.execution_valid


def test_ssz_static_request(tmp_path):
    c = case(tmp_path, "ssz_static", "Attestation")
    put_snappy(c.path, "serialized", b"BYTES")
    (c.path / "roots.yaml").write_text("root: '0x1234'\n")
    r = prepare(c, tmp_path / "w")
    assert isinstance(r, SszStaticRequest)
    assert r.root == "0x1234" and r.serialized.name == "serialized.ssz"


def test_fork_choice_request_and_script(tmp_path):
    c = case(tmp_path, "fork_choice", "get_head")
    put_snappy(c.path, "anchor_state", b"AS")
    put_snappy(c.path, "anchor_block", b"AB")
    put_snappy(c.path, "block_0xaa", b"BLK")
    (c.path / "steps.yaml").write_text(yaml.safe_dump([
        {"tick": 3},
        {"block": "block_0xaa", "valid": False},
        {"attestation": "block_0xaa"},
        {"checks": {"head": {"root": "0xdead", "slot": 7, "payload_status": 2},
                    "time": 99}},
        {"mystery_step": 1},
    ]))
    w = tmp_path / "w"
    r = prepare(c, w)
    assert isinstance(r, ForkChoiceRequest)
    script = (w / "fc_script.txt").read_text()
    lines = script.split("\n")
    assert lines[0] == "tick 3"
    assert lines[1] == f"block {w / 'block_0xaa.ssz'} 0 -"
    assert lines[2] == f"attestation {w / 'block_0xaa.ssz'} 1"
    # checks expand one line per key; head_payload_status rides its own line
    assert "head 0xdead 7" in lines and "head_payload_status 2" in lines and "time 99" in lines
    assert lines[-1] == "unsupported mystery_step"
    assert not script.endswith("\n")


def test_fc_vote_checks_encode_tfn():
    vote_step = {"checks": {"payload_timeliness_vote": {
        "block_root": "0xr", "votes": [True, False, None],
    }}}
    lines = build_fc_script(
        [vote_step],
        resolve=lambda stem: Path(f"/w/{stem}.ssz"),
    )
    assert lines == "payload_timeliness_vote 0xr t,f,n"


def test_fc_checkpoint_renames_and_unknown_subkeys():
    lines = build_fc_script(
        [{"checks": {
            "justified_checkpoint": {"epoch": 3, "root": "0xj", "surprise": 1},
            "finalized_checkpoint": {"epoch": 2, "root": "0xf"},
        }}],
        resolve=lambda stem: Path(f"/w/{stem}.ssz"),
    ).split("\n")
    assert "justified 3 0xj" in lines and "finalized 2 0xf" in lines
    assert lines[-1] == "unsupported justified_checkpoint.surprise"


def test_fc_should_override_and_unknown_check_key():
    lines = build_fc_script(
        [{"checks": {"should_override_forkchoice_update": True, "wat": 1}}],
        resolve=lambda stem: Path(f"/w/{stem}.ssz"),
    ).split("\n")
    assert "unsupported should_override_forkchoice_update" in lines
    assert lines[-1] == "unsupported wat"


def test_fc_block_columns_join_and_default_dash():
    lines = build_fc_script(
        [{"block": "b1", "columns": ["c1", "c2"]}, {"block": "b2"}],
        resolve=lambda stem: Path(f"/w/{stem}.ssz"),
    ).split("\n")
    assert lines[0] == "block /w/b1.ssz 1 /w/c1.ssz,/w/c2.ssz"
    assert lines[1] == "block /w/b2.ssz 1 -"


def test_fork_choice_missing_steps_is_loud(tmp_path):
    c = case(tmp_path, "fork_choice", "get_head", name="nosteps")
    put_snappy(c.path, "anchor_state", b"AS")
    put_snappy(c.path, "anchor_block", b"AB")
    with pytest.raises(FileNotFoundError, match="nosteps"):
        prepare(c, tmp_path / "w")
