import cramjam
import pytest

from consensus_diff.schema import Schema

# The gloas operations handlers -> the container per handler.
# The handler keys are the vector directory names under
# tests/mainnet/gloas/operations/; the container names are verified against
# eth_consensus_specs.gloas.mainnet by byte-exact SSZ round-trip of a real
# vector input. `withdrawals` is omitted: its case dirs carry no operation
# input file (only pre/post), so there is no seed to decode or mutate.
OPS = [
    ("attestation", "Attestation"),
    ("attester_slashing", "AttesterSlashing"),
    ("block_header", "BeaconBlock"),
    ("bls_to_execution_change", "SignedBLSToExecutionChange"),
    ("builder_deposit_request", "BuilderDepositRequest"),
    ("builder_exit_request", "BuilderExitRequest"),
    ("consolidation_request", "ConsolidationRequest"),
    ("deposit_request", "DepositRequest"),
    ("execution_payload_bid", "SignedExecutionPayloadBid"),
    ("parent_execution_payload", "BeaconBlock"),
    ("payload_attestation", "PayloadAttestation"),
    ("proposer_slashing", "ProposerSlashing"),
    ("sync_aggregate", "SyncAggregate"),
    ("voluntary_exit", "SignedVoluntaryExit"),
    ("voluntary_exit_churn", "SignedVoluntaryExit"),
    ("withdrawal_request", "WithdrawalRequest"),
]


@pytest.mark.parametrize("handler,cls_name", OPS)
def test_container_for_operations(handler, cls_name):
    schema = Schema(fork="gloas", preset="mainnet")
    assert schema.container_for("operations", handler).__name__ == cls_name


def test_attestation_round_trip(tmp_path):
    schema = Schema(fork="gloas", preset="mainnet")
    # Build a canonical empty Attestation via the schema and write it as a seed.
    obj = schema.container_for("operations", "attestation")()
    seed = tmp_path / "attestation.ssz_snappy"
    seed.write_bytes(bytes(cramjam.snappy.compress_raw(obj.encode_bytes())))

    decoded = schema.decode("operations", "attestation", seed)
    assert schema.htr(decoded) == schema.htr(obj)

    out = tmp_path / "out.ssz_snappy"
    schema.write(decoded, out)
    reloaded = schema.decode("operations", "attestation", out)
    assert schema.htr(reloaded) == schema.htr(obj)
