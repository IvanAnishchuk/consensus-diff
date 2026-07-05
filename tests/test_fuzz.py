from consensus_diff.fuzz import Finding, signature
from consensus_diff.protocol import Verdict


def test_signature_groups_same_shape_different_field():
    v = {
        "etheorem": Verdict("pass", "reject", "x"),
        "moonglass": Verdict("fail", "accept-invalid", "y"),
    }
    f1 = Finding(case_id="minimal/gloas/operations/attestation/c1", verdicts=v,
                 seed_id="c1", rng_seed=1, mutation="attestation.slot")
    f2 = Finding(case_id="minimal/gloas/operations/attestation/c9", verdicts=v,
                 seed_id="c9", rng_seed=2, mutation="attestation.slot")
    # Same runner/handler + same disagree shape -> same signature (dedup).
    assert signature(f1) == signature(f2)
    # A different disagree shape -> different signature.
    v2 = {"etheorem": Verdict("pass", "ok", ""), "moonglass": Verdict("fail", "mismatch", "")}
    f3 = Finding(case_id=f1.case_id, verdicts=v2, seed_id="c1", rng_seed=1, mutation="x")
    assert signature(f3) != signature(f1)
