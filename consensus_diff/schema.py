"""The pyspec/remerkleable schema lane.

The ONLY module that imports the pyspec. Used to decode, re-serialize, and
hash_tree_root vector inputs so the fuzzer can produce decode-valid mutations.
It is never a judge: the two backends remain the sole verdict authorities
(design doc, neutrality guard).
"""

from importlib import import_module
from pathlib import Path

import cramjam

# (runner, handler) -> container class name in the fork's pyspec module.
# The handler keys are the vector directory names under
# tests/mainnet/gloas/operations/; each container is the SSZ type the handler's
# operation input file decodes to, verified by byte-exact round-trip of a real
# vector (see tests/test_schema.py::OPS). `withdrawals` is intentionally absent:
# its case dirs carry no operation input (only pre/post state), so there is no
# seed to decode or mutate.
_CONTAINER = {
    ("operations", "attestation"): "Attestation",
    ("operations", "attester_slashing"): "AttesterSlashing",
    ("operations", "block_header"): "BeaconBlock",
    ("operations", "bls_to_execution_change"): "SignedBLSToExecutionChange",
    ("operations", "builder_deposit_request"): "BuilderDepositRequest",
    ("operations", "builder_exit_request"): "BuilderExitRequest",
    ("operations", "consolidation_request"): "ConsolidationRequest",
    ("operations", "deposit_request"): "DepositRequest",
    ("operations", "execution_payload_bid"): "SignedExecutionPayloadBid",
    ("operations", "parent_execution_payload"): "BeaconBlock",
    ("operations", "payload_attestation"): "PayloadAttestation",
    ("operations", "proposer_slashing"): "ProposerSlashing",
    ("operations", "sync_aggregate"): "SyncAggregate",
    ("operations", "voluntary_exit"): "SignedVoluntaryExit",
    ("operations", "voluntary_exit_churn"): "SignedVoluntaryExit",
    ("operations", "withdrawal_request"): "WithdrawalRequest",
}


class Schema:
    def __init__(self, fork: str, preset: str) -> None:
        self._spec = import_module(f"eth_consensus_specs.{fork}.{preset}")

    @staticmethod
    def knows(runner: str, handler: str) -> bool:
        """True iff ``(runner, handler)`` has a mapped container — i.e. a seed the
        schema lane can decode/mutate. A schema-mode seed for an unmapped handler
        must be skipped (counted), never decoded (that would KeyError)."""
        return (runner, handler) in _CONTAINER

    def container_for(self, runner: str, handler: str) -> type:
        name = _CONTAINER[(runner, handler)]
        return getattr(self._spec, name)

    def decode(self, runner: str, handler: str, path: Path):
        raw = bytes(cramjam.snappy.decompress_raw(Path(path).read_bytes()))
        return self.container_for(runner, handler).decode_bytes(raw)

    def write(self, obj, path: Path) -> None:
        Path(path).write_bytes(bytes(cramjam.snappy.compress_raw(obj.encode_bytes())))

    def htr(self, obj) -> str:
        return obj.hash_tree_root().hex()
