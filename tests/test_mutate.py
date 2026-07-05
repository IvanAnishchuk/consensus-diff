import random

from consensus_diff.mutate import mutate_object
from consensus_diff.schema import Schema


def test_mutation_is_deterministic_and_changes_root():
    schema = Schema(fork="gloas", preset="mainnet")
    obj = schema.container_for("operations", "attestation")()
    base_root = schema.htr(obj)

    m1, op1 = mutate_object(obj, random.Random(1234))
    m2, op2 = mutate_object(obj, random.Random(1234))

    # Same seed -> same mutation (reproducibility).
    assert schema.htr(m1) == schema.htr(m2)
    assert op1 == op2
    # A mutation actually changed the object.
    assert schema.htr(m1) != base_root
    # Still decode-valid: it re-serializes.
    assert m1.encode_bytes() == m2.encode_bytes()
