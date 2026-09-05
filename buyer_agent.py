"""Buyer agent: LLM plans, deterministic gate decides, Razorpay settles.

Flow
----
1. Groq (groq/compound-mini) inspects the merchant's agentic-commerce manifest
   and decides whether the advertised resource fits the user's goal, emitting a
   structured tool call.
2. The agent hits the protected resource, catches the HTTP 402 challenge.
3. The challenge + the user's signed Ed25519 ``SpendMandate`` go to the
   ``DeterministicPolicyGate`` -- a zero-LLM policy engine.
4. Only if the gate passes: create a Razorpay test order, fire the HMAC-signed
   ``order.paid`` webhook to simulate instant settlement, then fetch the unlocked
   resource with the new order id.

Attack simulation flags (``TAMPER_PRICE``, ``UNAUTHORIZED_MCC``,
``REPLAY_NONCE``, ``POOL_EXHAUSTION``) force adversarial inputs so you can
watch the deterministic gate catch and halt the transaction. On any
``PolicyViolation`` the function returns immediately with
``status: "HALTED"`` and ``deducted: 0`` -- ``create_test_order`` and
``fire_settlement_webhook`` are never called for a rejected transaction.

The LLM is used for exactly one thing: reading the manifest and deciding
whether the advertised resource fits the user's stated goal (intent
extraction + discovery). It never sees Razorpay credentials, never
constructs a payment amount, and has no code path into
``DeterministicPolicyGate`` -- that gate is the sole, deterministic authority
over whether money moves.

Every step is appended to a structured audit trail returned by ``run_agent``.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
from dotenv import load_dotenv
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from crypto_guardrails import DeterministicPolicyGate, PolicyViolation, SpendMandate

load_dotenv()

MERCHANT_BASE_URL = os.environ.get("MERCHANT_BASE_URL", "http://127.0.0.1:8000")
MANIFEST_PATH = "/.well-known/agentic-commerce.json"
RESOURCE_PATH = "/api/v1/market-data"
WEBHOOK_PATH = "/api/v1/razorpay-webhook"

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL = os.environ.get("GROQ_MODEL", "groq/compound-mini")
WEBHOOK_SECRET = os.environ["RAZORPAY_WEBHOOK_SECRET"]


# --------------------------------------------------------------------------- #
# Audit trail
# --------------------------------------------------------------------------- #
@dataclass
class AuditTrail:
    entries: list[dict[str, Any]] = field(default_factory=list)

    def record(self, step: str, status: str, detail: Any = None) -> None:
        self.entries.append(
            {
                "step": step,
                "status": status,
                "timestamp": time.time(),
                "iso_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "detail": detail,
            }
        )

    def as_list(self) -> list[dict[str, Any]]:
        return self.entries


# --------------------------------------------------------------------------- #
# Step 1-2: LLM inspects the manifest and emits a structured tool call
# --------------------------------------------------------------------------- #
TOOL_SCHEMA_HINT = {
    "name": "purchase_resource",
    "arguments": {
        "fits_goal": "bool - does the resource satisfy the user's goal?",
        "resource_path": "str",
        "max_price_paise": "int - the user's stated ceiling, in paise",
        "expected_mcc": "str",
        "reason": "str",
    },
}


def _heuristic_decision(user_prompt: str, manifest: dict) -> dict:
    """Deterministic fallback when the LLM is unavailable."""
    resource = manifest["resources"][0]
    # Pull a rupee ceiling like "under ₹30" / "under Rs 30" out of the prompt.
    ceiling_paise = 3000
    for token in user_prompt.replace("₹", " ").replace("Rs", " ").split():
        cleaned = token.strip(".,")
        if cleaned.isdigit():
            ceiling_paise = int(cleaned) * 100
            break
    return {
        "name": "purchase_resource",
        "arguments": {
            "fits_goal": resource["amount_paise"] <= ceiling_paise,
            "resource_path": resource.get("resource", resource.get("path")),
            "max_price_paise": ceiling_paise,
            "expected_mcc": resource["mcc"],
            "reason": "heuristic: manifest price within stated ceiling",
        },
        "engine": "heuristic-fallback",
    }


def llm_plan(user_prompt: str, manifest: dict, audit: AuditTrail) -> dict:
    """Ask Groq to inspect the manifest and return a structured tool call."""
    if not GROQ_API_KEY:
        decision = _heuristic_decision(user_prompt, manifest)
        audit.record("llm_plan", "fallback", {"reason": "no GROQ_API_KEY", **decision})
        return decision

    try:
        from groq import Groq

        client = Groq(api_key=GROQ_API_KEY)
        prompt = (
            "You are a purchasing agent. Inspect this merchant manifest and the "
            "user goal, then decide if the resource fits. Respond with ONLY a "
            "JSON object matching this shape (no markdown):\n"
            f"{json.dumps(TOOL_SCHEMA_HINT)}\n\n"
            f"USER GOAL: {user_prompt}\n"
            f"MANIFEST: {json.dumps(manifest)}\n"
        )
        resp = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": "You reply with a single JSON object and nothing else.",
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0,
        )
        text = resp.choices[0].message.content.strip()
        # Tolerate markdown fences or prose around the JSON object.
        text = text[text.find("{") : text.rfind("}") + 1]
        parsed = json.loads(text)
        arguments = parsed.get("arguments", parsed)
        decision = {"name": "purchase_resource", "arguments": arguments, "engine": GROQ_MODEL}
        audit.record("llm_plan", "ok", decision)
        return decision
    except Exception as exc:  # network, quota, parse -- fall back deterministically
        decision = _heuristic_decision(user_prompt, manifest)
        audit.record(
            "llm_plan", "fallback", {"error": f"{type(exc).__name__}: {exc}", **decision}
        )
        return decision


# --------------------------------------------------------------------------- #
# Mandate helper
# --------------------------------------------------------------------------- #
def build_signed_mandate(
    private_key: Ed25519PrivateKey,
    *,
    pool_limit_paise: int = 10_000,
    max_per_tx_paise: int = 3_000,
    allowed_mcc: list[str] | None = None,
    ttl_seconds: int = 3600,
) -> SpendMandate:
    mandate = SpendMandate(
        mandate_id="mandate-buyer-001",
        payer_id="user-havannavar",
        pool_limit_paise=pool_limit_paise,
        max_per_tx_paise=max_per_tx_paise,
        allowed_mcc=allowed_mcc or ["7372"],
        valid_until=time.time() + ttl_seconds,
        user_pubkey_hex=private_key.public_key().public_bytes_raw().hex(),
    )
    mandate.signature_hex = private_key.sign(mandate.canonical_bytes()).hex()
    return mandate


# --------------------------------------------------------------------------- #
# Razorpay + webhook
# --------------------------------------------------------------------------- #
def create_test_order(amount_paise: int, audit: AuditTrail) -> str:
    """Create a Razorpay test-mode order; fall back to a mock id if offline."""
    try:
        import razorpay

        client = razorpay.Client(
            auth=(os.environ["RAZORPAY_KEY_ID"], os.environ["RAZORPAY_KEY_SECRET"])
        )
        order = client.order.create(
            {"amount": amount_paise, "currency": "INR", "payment_capture": 1}
        )
        audit.record("razorpay_order_create", "ok", {"order_id": order["id"], "amount": amount_paise})
        return order["id"]
    except Exception as exc:
        mock_id = f"order_MOCK{int(time.time())}"
        audit.record(
            "razorpay_order_create",
            "fallback",
            {"error": f"{type(exc).__name__}: {exc}", "order_id": mock_id},
        )
        return mock_id


def fire_settlement_webhook(order_id: str, amount_paise: int, audit: AuditTrail) -> None:
    body = json.dumps(
        {
            "event": "order.paid",
            "payload": {
                "order": {
                    "entity": {"id": order_id, "amount": amount_paise, "currency": "INR"}
                }
            },
        }
    ).encode("utf-8")
    signature = hmac.new(WEBHOOK_SECRET.encode("utf-8"), body, hashlib.sha256).hexdigest()
    resp = httpx.post(
        f"{MERCHANT_BASE_URL}{WEBHOOK_PATH}",
        content=body,
        headers={"Content-Type": "application/json", "X-Razorpay-Signature": signature},
        timeout=10,
    )
    audit.record(
        "settlement_webhook",
        "ok" if resp.status_code == 200 else "error",
        {"http_status": resp.status_code, "body": resp.json()},
    )


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def run_agent(
    user_prompt: str,
    *,
    tamper_price: bool = False,
    unauthorized_mcc: bool = False,
    replay_nonce: bool = False,
    pool_exhaustion: bool = False,
) -> dict[str, Any]:
    audit = AuditTrail()
    audit.record("start", "ok", {"user_prompt": user_prompt,
                                 "attacks": {"TAMPER_PRICE": tamper_price,
                                             "UNAUTHORIZED_MCC": unauthorized_mcc,
                                             "REPLAY_NONCE": replay_nonce,
                                             "POOL_EXHAUSTION": pool_exhaustion}})

    client = httpx.Client(base_url=MERCHANT_BASE_URL, timeout=10)

    # Step 1: fetch manifest (LLM never sees Razorpay credentials or the gate --
    # it only ever reads this discovery document to decide *whether* a resource
    # fits the user's goal, never *whether* payment is authorized).
    manifest = client.get(MANIFEST_PATH).json()
    audit.record("fetch_manifest", "ok", manifest)

    # Step 2: LLM plan -- pure intent extraction. Its output can only steer
    # *which* resource to pursue; it has no path to Razorpay, no reference to
    # the gate, and cannot influence amount/MCC/nonce validation below.
    plan = llm_plan(user_prompt, manifest, audit)
    if not plan["arguments"].get("fits_goal", False):
        reason = plan["arguments"].get("reason", "resource does not fit the stated goal")
        audit.record("halt", "llm_rejected", {"reason": reason})
        return {"status": "HALTED", "reason": reason, "deducted": 0, "audit": audit.as_list()}

    # Step 3: hit protected resource, expect 402
    resp = client.get(RESOURCE_PATH)
    if resp.status_code != 402:
        reason = f"expected HTTP 402, got {resp.status_code}"
        audit.record("challenge", "unexpected", {"http_status": resp.status_code})
        return {"status": "HALTED", "reason": reason, "deducted": 0, "audit": audit.as_list()}
    challenge = resp.json()
    audit.record("challenge_402", "ok", challenge)

    # Step 4: build mandate + submit challenge to the deterministic gate
    private_key = Ed25519PrivateKey.generate()
    allowed_mcc = ["7372"]
    mandate = build_signed_mandate(private_key, allowed_mcc=allowed_mcc)

    gate = DeterministicPolicyGate()

    # Attack injection: mutate the *exact* dict handed to the gate, so the gate
    # scrutinises the tampered values -- not some pristine copy.
    if tamper_price:
        challenge["amount_paise"] = 50_000  # merchant dynamically re-prices to ₹500.00
        audit.record("attack_TAMPER_PRICE", "injected",
                     {"amount_paise": challenge["amount_paise"]})
    if unauthorized_mcc:
        challenge["mcc"] = "7995"  # gambling -- not in allowed_mcc
        audit.record("attack_UNAUTHORIZED_MCC", "injected", {"mcc": challenge["mcc"]})
    if replay_nonce:
        # Burn the nonce once so the real attempt is a replay.
        gate.seen_nonces.add(challenge["invoice_nonce"])
        audit.record("attack_REPLAY_NONCE", "injected", {"nonce": challenge["invoice_nonce"]})
    if pool_exhaustion:
        # Simulate a mandate whose pool is nearly spent from prior transactions,
        # leaving less headroom than this (otherwise in-policy) charge needs.
        gate.consumed_pools = mandate.pool_limit_paise - (challenge["amount_paise"] - 100)
        audit.record("attack_POOL_EXHAUSTION", "injected",
                     {"consumed_pools": gate.consumed_pools,
                      "pool_limit_paise": mandate.pool_limit_paise})

    # Step 4b: submit to the deterministic gate. On any PolicyViolation we
    # HALT immediately -- no Razorpay order is created and no webhook fires,
    # so nothing is ever deducted for a rejected transaction.
    try:
        gate.evaluate_and_lock(mandate, challenge)
    except PolicyViolation as pv:
        audit.record("policy_gate", "BLOCKED", {"reason": str(pv)})
        return {
            "status": "HALTED",
            "reason": str(pv),
            "deducted": 0,
            "audit": audit.as_list(),
        }
    audit.record("policy_gate", "PASS",
                 {"amount_paise": challenge["amount_paise"], "mcc": challenge["mcc"],
                  "spent_paise": gate.spent_paise})

    # Step 5: gate passed -> settle for real
    amount_paise = challenge["amount_paise"]
    order_id = create_test_order(amount_paise, audit)
    fire_settlement_webhook(order_id, amount_paise, audit)

    unlocked = client.get(RESOURCE_PATH, headers={"X-Payment-Order-Id": order_id})
    audit.record(
        "fetch_unlocked_resource",
        "ok" if unlocked.status_code == 200 else "error",
        {"http_status": unlocked.status_code, "body": unlocked.json()},
    )

    # The gate already locked the pool at this point -- delivery is a separate,
    # merchant-side concern from the policy decision, so a delivery hiccup is
    # reported as SETTLEMENT_FAILED (funds committed) rather than HALTED
    # (funds never touched), which is reserved for gate rejections.
    settled = unlocked.status_code == 200
    audit.record("done", "settled" if settled else "settlement_failed", {"order_id": order_id})
    return {
        "status": "SUCCESS" if settled else "SETTLEMENT_FAILED",
        "reason": None if settled else f"merchant returned HTTP {unlocked.status_code}",
        "deducted": amount_paise,
        "order_id": order_id,
        "resource": unlocked.json() if settled else None,
        "audit": audit.as_list(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Agentic buyer with deterministic guardrails")
    parser.add_argument(
        "prompt",
        nargs="?",
        default="Find and purchase tech equity sentiment under ₹30",
    )
    parser.add_argument("--tamper-price", action="store_true", help="TAMPER_PRICE attack")
    parser.add_argument("--unauthorized-mcc", action="store_true", help="UNAUTHORIZED_MCC attack")
    parser.add_argument("--replay-nonce", action="store_true", help="REPLAY_NONCE attack")
    parser.add_argument("--pool-exhaustion", action="store_true", help="POOL_EXHAUSTION attack")
    args = parser.parse_args()

    result = run_agent(
        args.prompt,
        tamper_price=args.tamper_price,
        unauthorized_mcc=args.unauthorized_mcc,
        replay_nonce=args.replay_nonce,
        pool_exhaustion=args.pool_exhaustion,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
