import cramjam

from consensus_diff.schema import Schema


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
