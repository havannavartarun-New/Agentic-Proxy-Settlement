"""Tests proving the deterministic policy gate defends against price tampering,
unauthorized MCCs, expired mandates, pool exhaustion, and nonce replay -- and
that every rejected transaction leaves the gate's ledger completely untouched
(THE BAR: bounded, gated, and provably free of state leakage on failure).
"""

from __future__ import annotations

import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from crypto_guardrails import (
    DeterministicPolicyGate,
    PolicyViolation,
    SpendMandate,
)


def _signed_mandate(private_key: Ed25519PrivateKey, **overrides) -> SpendMandate:
    pubkey_hex = private_key.public_key().public_bytes_raw().hex()
    fields = {
        "mandate_id": "m-001",
        "payer_id": "payer-42",
        "pool_limit_paise": 100_000,
        "max_per_tx_paise": 40_000,
        "allowed_mcc": ["5411", "5732"],
        "valid_until": time.time() + 3600,
        "user_pubkey_hex": pubkey_hex,
    }
    fields.update(overrides)
    mandate = SpendMandate(**fields)
    mandate.signature_hex = private_key.sign(mandate.canonical_bytes()).hex()
    return mandate


@pytest.fixture
def private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def gate() -> DeterministicPolicyGate:
    return DeterministicPolicyGate()


def test_valid_mandate_passes(gate, private_key):
    mandate = _signed_mandate(private_key)
    gate.authorize(
        mandate, amount_paise=25_000, mcc="5411", invoice_nonce="inv-1"
    )
    assert gate.spent_paise == 25_000


def test_invalid_signature_fails(gate, private_key):
    mandate = _signed_mandate(private_key)
    # Tamper with a signed field; signature no longer matches canonical bytes.
    mandate.pool_limit_paise = 10_000_000
    with pytest.raises(PolicyViolation, match="invalid mandate signature"):
        gate.authorize(
            mandate, amount_paise=25_000, mcc="5411", invoice_nonce="inv-1"
        )


def test_pool_exhaustion_fails(gate, private_key):
    mandate = _signed_mandate(private_key)
    gate.authorize(
        mandate, amount_paise=40_000, mcc="5411", invoice_nonce="inv-1"
    )
    gate.authorize(
        mandate, amount_paise=40_000, mcc="5411", invoice_nonce="inv-2"
    )
    # 80_000 spent, pool is 100_000; a third 40_000 tx exhausts the pool.
    with pytest.raises(PolicyViolation, match="POOL EXHAUSTED"):
        gate.authorize(
            mandate, amount_paise=40_000, mcc="5411", invoice_nonce="inv-3"
        )
    assert gate.spent_paise == 80_000  # the failed attempt deducted nothing


def test_nonce_replay_fails(gate, private_key):
    mandate = _signed_mandate(private_key)
    gate.authorize(
        mandate, amount_paise=10_000, mcc="5411", invoice_nonce="inv-1"
    )
    with pytest.raises(PolicyViolation, match="replayed invoice nonce"):
        gate.authorize(
            mandate, amount_paise=10_000, mcc="5411", invoice_nonce="inv-1"
        )
    assert gate.spent_paise == 10_000


def test_disallowed_mcc_fails(gate, private_key):
    mandate = _signed_mandate(private_key)
    with pytest.raises(PolicyViolation, match="merchant category code not allowed"):
        gate.authorize(
            mandate, amount_paise=10_000, mcc="7995", invoice_nonce="inv-1"
        )


def test_expired_mandate_fails(gate, private_key):
    mandate = _signed_mandate(private_key, valid_until=time.time() - 1)
    with pytest.raises(PolicyViolation, match="expired"):
        gate.authorize(
            mandate, amount_paise=10_000, mcc="5411", invoice_nonce="inv-1"
        )


def test_per_tx_limit_fails(gate, private_key):
    mandate = _signed_mandate(private_key)
    with pytest.raises(PolicyViolation, match="THRESHOLD BREACH"):
        gate.authorize(
            mandate, amount_paise=50_000, mcc="5411", invoice_nonce="inv-1"
        )


def test_price_tampering_via_challenge_dict(gate, private_key):
    """Mutating challenge['amount_paise'] is exactly what the gate checks."""
    mandate = _signed_mandate(private_key, max_per_tx_paise=3_000)
    challenge = {"amount_paise": 2_500, "mcc": "5411", "invoice_nonce": "inv-x"}
    challenge["amount_paise"] = 50_000  # dynamic price tampering -> ₹500.00
    with pytest.raises(
        PolicyViolation,
        match=r"THRESHOLD BREACH: ₹500\.00 exceeds single-tx ceiling of ₹30\.00",
    ):
        gate.evaluate_and_lock(mandate, challenge)


# --------------------------------------------------------------------------- #
# State-integrity invariants: THE BAR requires every rejected transaction to
# leave zero trace on the gate's ledger -- no partial deduction, no nonce
# burned, nothing an attacker (or a buggy retry) could exploit.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "bad_challenge,expected_match",
    [
        ({"amount_paise": 999_999, "mcc": "5411"}, "THRESHOLD BREACH"),
        ({"amount_paise": 10_000, "mcc": "7995"}, "merchant category code not allowed"),
    ],
)
def test_rejected_transaction_never_consumes_the_nonce(
    gate, private_key, bad_challenge, expected_match
):
    """A blocked attempt must not burn its invoice nonce.

    Proof: the exact same nonce, reused in a *valid* follow-up call, must
    still succeed -- which is only possible if the failed attempt never
    reached ``seen_nonces.add(...)``.
    """
    mandate = _signed_mandate(private_key, max_per_tx_paise=3_000, pool_limit_paise=10_000)
    nonce = "inv-reused-after-rejection"
    challenge = {"invoice_nonce": nonce, **bad_challenge}
    with pytest.raises(PolicyViolation, match=expected_match):
        gate.evaluate_and_lock(mandate, challenge)

    assert nonce not in gate.seen_nonces
    assert gate.consumed_pools == 0

    # The same nonce now clears a legitimate, in-policy transaction.
    gate.evaluate_and_lock(
        mandate, {"amount_paise": 2_500, "mcc": "5411", "invoice_nonce": nonce}
    )
    assert gate.consumed_pools == 2_500


def test_rejected_transaction_never_deducts_pool_balance(gate, private_key):
    """A budget-breaching attempt must not partially deduct the pool."""
    mandate = _signed_mandate(private_key, pool_limit_paise=5_000, max_per_tx_paise=10_000)
    with pytest.raises(PolicyViolation, match="POOL EXHAUSTED"):
        gate.evaluate_and_lock(
            mandate, {"amount_paise": 6_000, "mcc": "5411", "invoice_nonce": "inv-1"}
        )
    assert gate.consumed_pools == 0
    assert gate.seen_nonces == set()
