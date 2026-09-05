"""Deterministic, zero-LLM policy engine for Ed25519-delegated spend mandates.

This module enforces the core architecture constraint that money execution must
sit behind a deterministic policy gate: an LLM may *propose* a payment, but only
``DeterministicPolicyGate`` decides whether it is allowed. Every check is pure and
reproducible given the same inputs.

Protocol alignment
-------------------
``SpendMandate`` is a delegated-authorization credential in the spirit of
Google/industry AP2 ("Agent Payments Protocol") and NPCI's UAP ("Unified
Authorization Protocol") work on agent-initiated payments: a human signs one
long-lived, bounded permission slip (an Ed25519 signature over
``canonical_bytes()``), and an agent then presents narrower, single-use
payment intents against it. The gate below is what actually *checks* that
delegation on every attempt -- expiry, category (MCC) binding, a hard per-
transaction ceiling, and a cumulative pool ceiling -- exactly the invariant
category both AP2 and UAP require before an agent may move money.
"""

from __future__ import annotations

import json
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, Field


class PolicyViolation(Exception):
    """Raised when a proposed payment fails any deterministic policy check.

    The string message always states a single, human-readable reason so that
    callers (and tests) can assert on *why* a payment was rejected.
    """


class SpendMandate(BaseModel):
    """A user pre-authorization for agentic spending, signed with Ed25519.

    The mandate is signed off-chain by the user's key (``user_pubkey_hex``). The
    signature covers exactly the bytes produced by :meth:`canonical_bytes`, which
    deliberately excludes ``signature_hex`` itself.
    """

    mandate_id: str
    payer_id: str
    pool_limit_paise: int = Field(ge=0)
    max_per_tx_paise: int = Field(ge=0)
    allowed_mcc: list[str]
    valid_until: float
    user_pubkey_hex: str
    signature_hex: str = ""

    def canonical_bytes(self) -> bytes:
        """Return deterministic UTF-8 JSON bytes for signing/verification.

        Keys are sorted, whitespace is stripped, and the ``signature_hex`` field
        is omitted so the signature can be computed over a stable payload.
        """
        payload = self.model_dump(exclude={"signature_hex"})
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")


class DeterministicPolicyGate:
    """Deterministic validator for payments proposed against a spend mandate.

    A single gate instance tracks cumulative spend and consumed invoice nonces
    in memory, so it should live for the duration of a mandate's use.
    """

    def __init__(self) -> None:
        # Mutable ledger. These are the ONLY pieces of state the gate owns, and
        # they are mutated exactly once per call, at the very end of
        # ``evaluate_and_lock``, after every validation has passed.
        self.seen_nonces: set[str] = set()
        self.consumed_pools: int = 0

    @property
    def spent_paise(self) -> int:
        """Total paise locked against the pool so far (alias of consumed_pools)."""
        return self.consumed_pools

    def _verify_signature(self, mandate: SpendMandate) -> None:
        if not mandate.signature_hex:
            raise PolicyViolation("mandate is not signed")
        try:
            public_key = Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(mandate.user_pubkey_hex)
            )
            public_key.verify(
                bytes.fromhex(mandate.signature_hex),
                mandate.canonical_bytes(),
            )
        except (InvalidSignature, ValueError) as exc:
            raise PolicyViolation("invalid mandate signature") from exc

    def evaluate_and_lock(self, mandate: SpendMandate, challenge: dict) -> None:
        """Validate a proposed payment described by a merchant *challenge* dict.

        The ``challenge`` dict is the exact payload the caller intends to pay
        against -- it must carry ``amount_paise``, ``mcc`` and ``invoice_nonce``
        (an optional ``now`` overrides the wall clock for tests). Every check
        reads straight from this dict, so any tampering an upstream actor
        performs on it (e.g. dynamic price re-writing) is exactly what the gate
        scrutinises.

        Returns ``None`` on success, after which the invoice nonce is consumed
        and the amount is locked against the cumulative pool budget. Raises
        :class:`PolicyViolation` with a specific reason on any failure.

        IMPORTANT: every validation below runs to completion, and only the
        final two lines touch ``self.seen_nonces`` / ``self.consumed_pools``.
        A ``PolicyViolation`` raised anywhere above them exits the function
        immediately via Python's normal exception unwinding, so a rejected
        transaction can *never* consume a nonce or deduct from the pool --
        there is no code path that mutates state before every check passes.
        """
        amount_paise = int(challenge["amount_paise"])
        mcc = str(challenge["mcc"])
        invoice_nonce = str(challenge["invoice_nonce"])
        now = challenge.get("now")
        current_time = time.time() if now is None else now

        # 1. Cryptographic authenticity of the mandate.
        self._verify_signature(mandate)

        # 2. Replay protection: each invoice nonce may be used at most once.
        if invoice_nonce in self.seen_nonces:
            raise PolicyViolation(f"replayed invoice nonce: {invoice_nonce}")

        # 3. Expiration.
        if current_time >= mandate.valid_until:
            raise PolicyViolation("mandate has expired")

        # 4. Allowed merchant category code.
        if mcc not in mandate.allowed_mcc:
            raise PolicyViolation(f"merchant category code not allowed: {mcc}")

        # 5. Single-transaction ceiling -- checked BEFORE any pool deduction,
        #    so dynamic price tampering is caught without ever touching the
        #    budget.
        if amount_paise <= 0:
            raise PolicyViolation("payment amount must be positive")
        if amount_paise > mandate.max_per_tx_paise:
            raise PolicyViolation(
                f"THRESHOLD BREACH: ₹{amount_paise / 100:.2f} exceeds "
                f"single-tx ceiling of ₹{mandate.max_per_tx_paise / 100:.2f}"
            )

        # 6. Cumulative pool budget -- catches pool exhaustion from prior spends.
        remaining_paise = mandate.pool_limit_paise - self.consumed_pools
        if amount_paise > remaining_paise:
            raise PolicyViolation(
                f"POOL EXHAUSTED: ₹{amount_paise / 100:.2f} requested but only "
                f"₹{remaining_paise / 100:.2f} remains of the "
                f"₹{mandate.pool_limit_paise / 100:.2f} pool"
            )

        # All checks passed: this is the ONLY place state is mutated.
        self.seen_nonces.add(invoice_nonce)
        self.consumed_pools += amount_paise

    def authorize(
        self,
        mandate: SpendMandate,
        *,
        amount_paise: int,
        mcc: str,
        invoice_nonce: str,
        now: float | None = None,
    ) -> None:
        """Keyword-argument convenience wrapper around :meth:`evaluate_and_lock`."""
        challenge = {
            "amount_paise": amount_paise,
            "mcc": mcc,
            "invoice_nonce": invoice_nonce,
        }
        if now is not None:
            challenge["now"] = now
        self.evaluate_and_lock(mandate, challenge)
