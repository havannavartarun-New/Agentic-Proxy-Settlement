"""Streamlit evaluator UI for the Razorpay Agentic Settlement Proxy.

Built for Razorpay AI Buildathon — Track 01: AI Growth & Agentic Commerce.
"Every money action explainable, bounded and gated."

Sidebar    -> the user's Ed25519 spend mandate (auto-signed in memory, live).
Main body  -> a header of live status badges + a 4-metric ledger row, a
              scenario executor (happy path + 4 attacks), and five audit-stage
              cards: Manifest Discovery -> HTTP 402 Intercept -> Deterministic
              Policy Gate -> Razorpay Settlement & HMAC Webhook -> Payload
              Delivery / Graceful Halt.

The merchant server (merchant_server.py) must be running on MERCHANT_BASE_URL.
"""

from __future__ import annotations

import hashlib
import json
import os
import time

import httpx
import streamlit as st
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from buyer_agent import (
    MANIFEST_PATH,
    MERCHANT_BASE_URL,
    RESOURCE_PATH,
    AuditTrail,
    create_test_order,
    fire_settlement_webhook,
    llm_plan,
)
from crypto_guardrails import DeterministicPolicyGate, PolicyViolation, SpendMandate

st.set_page_config(page_title="Agentic Settlement Proxy", page_icon="🔐", layout="wide")

RAZORPAY_KEY_ID = os.environ.get("RAZORPAY_KEY_ID", "")
RAZORPAY_MODE = "TEST" if RAZORPAY_KEY_ID.startswith("rzp_test_") else "LIVE"
RAZORPAY_ORDERS_DASHBOARD = "https://dashboard.razorpay.com/app/orders"

MCC_CATALOG = {
    "7372": "Software / SaaS / Data APIs",
    "5411": "Grocery Stores",
    "5732": "Electronics",
    "4816": "Computer Network / Information Services",
    "7995": "Betting / Gambling",
}

# Ordered scenario catalog for the Scenario Executor. Each entry is one of the
# five money-moving situations THE BAR requires us to demonstrate: one happy
# path, plus every failure mode explicitly named in the track brief.
SCENARIOS = [
    {
        "key": "happy",
        "label": "✅ Happy Path",
        "short": "₹25 valid autonomous data settlement",
        "description": (
            "A well-formed ₹25.00 charge, in-policy MCC, fresh nonce — the gate "
            "passes and Razorpay settles end to end."
        ),
    },
    {
        "key": "tamper_price",
        "label": "💸 Price Tampering",
        "short": "Merchant hikes the challenge above your per-tx ceiling",
        "description": (
            "The merchant's 402 challenge is rewritten to an amount always "
            "strictly above the mandate's per-tx ceiling — whatever you set it "
            "to in the sidebar. The gate must reject before any order is created."
        ),
    },
    {
        "key": "unauthorized_mcc",
        "label": "🎰 Unauthorized MCC",
        "short": "Settlement rerouted to MCC 7995 (Gambling)",
        "description": (
            "The challenge's MCC is swapped to 7995 (Betting/Gambling), outside "
            "the mandate's allow-list. The gate must reject regardless of price."
        ),
    },
    {
        "key": "replay_nonce",
        "label": "🔁 Replay Attack",
        "short": "Attacker replays a signed invoice nonce",
        "description": (
            "A previously-consumed invoice nonce is presented again. The gate's "
            "replay cache must reject it even though signature, price and MCC "
            "are all otherwise valid."
        ),
    },
    {
        "key": "pool_exhaustion",
        "label": "🪫 Pool Exhaustion",
        "short": "Spend attempted when balance is depleted",
        "description": (
            "The mandate's pool is simulated as already nearly spent from prior "
            "transactions, so an otherwise in-policy ₹25.00 charge no longer "
            "fits the remaining budget."
        ),
    },
]
SCENARIO_OPTIONS = {f"{s['label']} — {s['short']}": s for s in SCENARIOS}


# --------------------------------------------------------------------------- #
# CSS
# --------------------------------------------------------------------------- #
st.markdown(
    """
    <style>
      .block-container { padding-top: 2.2rem; }

      /* --- top status bar --- */
      .topbar {
        display: flex; align-items: center; justify-content: space-between;
        gap: 1rem; padding: 16px 20px; margin-bottom: 4px;
        border: 1px solid rgba(128,128,128,0.22); border-radius: 14px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.05);
        background: linear-gradient(90deg, rgba(99,102,241,0.06), rgba(16,185,129,0.05));
        flex-wrap: wrap;
      }
      .topbar__title { font-size: 1.2rem; font-weight: 700; letter-spacing: .2px; }
      .topbar__badges { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 6px; }
      .topbar__status { display: flex; gap: 8px; flex-wrap: wrap; }

      /* --- pills & chips --- */
      .pill, .chip {
        display: inline-flex; align-items: center; gap: 6px;
        font-size: .74rem; font-weight: 600; line-height: 1;
        padding: 6px 10px; border-radius: 999px; white-space: nowrap;
      }
      .pill::before {
        content: ""; width: 7px; height: 7px; border-radius: 50%;
        background: currentColor; box-shadow: 0 0 0 3px rgba(0,0,0,0.06);
      }
      .pill--ok    { color: #15803d; background: rgba(34,197,94,0.14); }
      .pill--down  { color: #b91c1c; background: rgba(239,68,68,0.14); }
      .pill--test  { color: #b45309; background: rgba(245,158,11,0.16); }
      .pill--live  { color: #6d28d9; background: rgba(139,92,246,0.16); }

      .chip--neutral { color: #334155; background: rgba(100,116,139,0.16); }
      .chip--ok      { color: #15803d; background: rgba(34,197,94,0.14); }
      .chip--bad     { color: #b91c1c; background: rgba(239,68,68,0.14); }
      .chip--warn    { color: #b45309; background: rgba(245,158,11,0.16); }
      .chip--track   { color: #4338ca; background: rgba(99,102,241,0.14); }

      /* --- monospace crypto material --- */
      .mono {
        font-family: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
        font-size: .82rem; word-break: break-all;
        padding: 2px 6px; border-radius: 6px;
        background: rgba(128,128,128,0.12);
      }

      /* --- card accent borders on bordered containers --- */
      div[data-testid="stVerticalBlockBorderWrapper"]:has(.acc) {
        box-shadow: 0 4px 12px rgba(0,0,0,0.05);
        border-radius: 14px;
      }
      div[data-testid="stVerticalBlockBorderWrapper"]:has(.acc-green)  { border-left: 5px solid #16a34a; }
      div[data-testid="stVerticalBlockBorderWrapper"]:has(.acc-red)    { border-left: 5px solid #dc2626; }
      div[data-testid="stVerticalBlockBorderWrapper"]:has(.acc-amber)  { border-left: 5px solid #d97706; }
      div[data-testid="stVerticalBlockBorderWrapper"]:has(.acc-blue)   { border-left: 5px solid #2563eb; }
      div[data-testid="stVerticalBlockBorderWrapper"]:has(.acc-slate)  { border-left: 5px solid #64748b; }
      .acc { display: none; }

      /* --- scenario picker as a pill / segmented control --- */
      div[data-testid="stRadio"] > div[role="radiogroup"] { gap: 8px; flex-wrap: wrap; }
      div[data-testid="stRadio"] > div[role="radiogroup"] label {
        border: 1px solid rgba(128,128,128,0.25); border-radius: 999px;
        padding: 6px 14px; margin: 0;
      }
    </style>
    """,
    unsafe_allow_html=True,
)


def pill(text: str, kind: str) -> str:
    return f'<span class="pill pill--{kind}">{text}</span>'


def chip(text: str, kind: str = "neutral") -> str:
    return f'<span class="chip chip--{kind}">{text}</span>'


def mono(text: str) -> str:
    return f'<span class="mono">{text}</span>'


# --------------------------------------------------------------------------- #
# Session state — signing key + persistent spend ledger
# --------------------------------------------------------------------------- #
if "signing_key_bytes" not in st.session_state:
    st.session_state.signing_key_bytes = Ed25519PrivateKey.generate().private_bytes_raw()
st.session_state.setdefault("last_nonce", None)
st.session_state.setdefault("spent_paise", 0)
st.session_state.setdefault("used_nonces", set())

private_key = Ed25519PrivateKey.from_private_bytes(st.session_state.signing_key_bytes)
public_key_hex = private_key.public_key().public_bytes_raw().hex()


def build_mandate(pool_paise: int, per_tx_paise: int, allowed_mcc: list[str]) -> SpendMandate:
    """Construct and Ed25519-sign a mandate. Re-run on every widget change.

    This is the AP2 / NPCI UAP-style delegated-authorization credential: a
    human signs one bounded permission slip (pool ceiling, per-tx ceiling,
    MCC allow-list, expiry) that an agent presents against, transaction by
    transaction, for a DeterministicPolicyGate to check.
    """
    mandate = SpendMandate(
        mandate_id="mandate-streamlit-001",
        payer_id="user-havannavar",
        pool_limit_paise=pool_paise,
        max_per_tx_paise=per_tx_paise,
        allowed_mcc=allowed_mcc,
        valid_until=time.time() + 3600,
        user_pubkey_hex=public_key_hex,
    )
    mandate.signature_hex = private_key.sign(mandate.canonical_bytes()).hex()
    return mandate


def load_gate() -> DeterministicPolicyGate:
    """A gate seeded with the session's persistent ledger (spend + nonces)."""
    gate = DeterministicPolicyGate()
    gate.consumed_pools = st.session_state.spent_paise
    gate.seen_nonces = set(st.session_state.used_nonces)
    return gate


# --------------------------------------------------------------------------- #
# SIDEBAR — mandate controls
# --------------------------------------------------------------------------- #
with st.sidebar:
    st.header("🖊️ User Spend Mandate")

    pool_rupees = st.number_input(
        "Total Pool Limit (₹)", min_value=10, max_value=10_000, value=100, step=10,
        help="Cumulative budget the agent may spend against this mandate.",
    )
    per_tx_rupees = st.number_input(
        # Default ₹30.00 == 3,000 paise -- the single-tx ceiling the gate
        # enforces before it ever touches the pool budget.
        "Max Per-Transaction Limit (₹)", min_value=5, max_value=5_000, value=30, step=5,
        help="Ceiling enforced on any single transaction.",
    )
    selected_mcc = st.multiselect(
        "Allowed Merchant Categories (MCC)",
        options=list(MCC_CATALOG.keys()),
        default=["7372"],
        format_func=lambda code: f"{code} — {MCC_CATALOG[code]}",
    )

    pool_paise = int(pool_rupees) * 100
    per_tx_paise = int(per_tx_rupees) * 100
    mandate = build_mandate(pool_paise, per_tx_paise, selected_mcc)
    mandate_digest = hashlib.sha256(mandate.canonical_bytes()).hexdigest()

    if selected_mcc:
        st.markdown(
            "".join(chip(f"{c} · {MCC_CATALOG[c]}") for c in selected_mcc),
            unsafe_allow_html=True,
        )

    st.divider()
    st.caption("Auto-signed in real time with an in-memory Ed25519 key")
    st.markdown(f"**Public key**<br>{mono(public_key_hex)}", unsafe_allow_html=True)
    st.markdown(
        f"**Signature**<br>{mono(mandate.signature_hex[:64] + '…')}", unsafe_allow_html=True
    )
    with st.expander("Canonical signed bytes"):
        st.code(mandate.canonical_bytes().decode("utf-8"), language="json")

    st.divider()
    if st.button("↺ Reset spend ledger", use_container_width=True):
        st.session_state.spent_paise = 0
        st.session_state.used_nonces = set()
        st.session_state.last_nonce = None
        st.rerun()


# --------------------------------------------------------------------------- #
# HEADER BAR + METRIC ROW
# --------------------------------------------------------------------------- #
def check_merchant() -> tuple[bool, dict | None]:
    try:
        r = httpx.get(f"{MERCHANT_BASE_URL}{MANIFEST_PATH}", timeout=2)
        return r.status_code == 200, r.json()
    except Exception:
        return False, None


merchant_up, manifest_preview = check_merchant()

# A dedicated placeholder so the metric row can be re-rendered with the
# post-execution ledger *after* execute() runs below, instead of freezing at
# its pre-click values for the rest of this script pass.
header_slot = st.empty()


def render_header() -> None:
    with header_slot.container():
        st.markdown(
            f"""
            <div class="topbar">
              <div>
                <div class="topbar__title">🔐 Agentic Settlement Proxy</div>
                <div class="topbar__badges">
                  {chip("Track 01: AI Growth &amp; Agentic Commerce", "track")}
                  {chip("Protocol: x402 / AP2 Delegation", "track")}
                </div>
              </div>
              <div class="topbar__status">
                {pill("Merchant Backend: Connected" if merchant_up else "Merchant Backend: Down",
                      "ok" if merchant_up else "down")}
                {pill(f"Razorpay Test Rail: {RAZORPAY_MODE}",
                      "test" if RAZORPAY_MODE == "TEST" else "live")}
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        remaining_paise = max(pool_paise - st.session_state.spent_paise, 0)
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Active Pool Balance", f"₹{pool_paise / 100:,.2f}")
        m2.metric("Max Single-Tx Ceiling", f"₹{per_tx_paise / 100:,.2f}")
        m3.metric(
            "Consumed Quota",
            f"₹{st.session_state.spent_paise / 100:,.2f}",
            delta=f"₹{remaining_paise / 100:,.2f} remaining",
            delta_color="off",
        )
        m4.metric("Cryptographic Nonce", mandate_digest[:16])

        st.caption(
            "LLM plans → the deterministic zero-LLM gate decides → Razorpay settles. "
            "Money never touches the model."
        )


render_header()


# --------------------------------------------------------------------------- #
# SCENARIO EXECUTOR
# --------------------------------------------------------------------------- #
st.subheader("🧪 Scenario Executor")
exec_cols = st.columns([4, 1])
with exec_cols[0]:
    scenario_choice = st.radio(
        "Scenario",
        list(SCENARIO_OPTIONS.keys()),
        horizontal=True,
        label_visibility="collapsed",
    )
    scenario_meta = SCENARIO_OPTIONS[scenario_choice]
    scenario = scenario_meta["key"]
    st.caption(scenario_meta["description"])
with exec_cols[1]:
    run = st.button("▶️ Execute", type="primary", use_container_width=True)

st.divider()


# --------------------------------------------------------------------------- #
# CARDS
# --------------------------------------------------------------------------- #
def card(container, accent: str):
    """Yield a bordered container tagged with a colored accent border."""
    box = container.container(border=True)
    box.markdown(f'<span class="acc acc-{accent}"></span>', unsafe_allow_html=True)
    return box


def card_manifest(container, plan: dict, engine_note: str) -> None:
    args = plan.get("arguments", {})
    fits = bool(args.get("fits_goal"))
    box = card(container, "blue")
    box.subheader("① Manifest Discovery — Agent Reasoning")
    box.markdown(
        f'{chip(engine_note, "ok" if "live LLM" in engine_note else "warn")} '
        f'{chip("fits goal" if fits else "rejects goal", "ok" if fits else "bad")} '
        f'{chip("intent extraction only — no wallet access", "neutral")}',
        unsafe_allow_html=True,
    )
    box.write(f"**Reason:** {args.get('reason', '—')}")
    box.code(json.dumps(args, indent=2), language="json")


def card_intercept(
    container, challenge: dict, original_amount: int, original_mcc: str, note: str | None = None
) -> None:
    """`challenge` is the (possibly tampered) dict the gate will evaluate."""
    tampered = challenge["amount_paise"] != original_amount
    injected = challenge["mcc"] != original_mcc
    box = card(container, "amber" if (tampered or injected or note) else "slate")
    box.subheader("② HTTP 402 Intercept")
    if note:
        box.info(note)
    c1, c2, c3 = box.columns(3)
    c1.metric("Challenge amount", f"₹{original_amount / 100:.2f}")
    c2.metric(
        "Effective charge (to gate)",
        f"₹{challenge['amount_paise'] / 100:.2f}",
        delta="TAMPERED" if tampered else None,
        delta_color="inverse",
    )
    c3.metric("MCC presented", challenge["mcc"],
              delta="INJECTED" if injected else None, delta_color="inverse")
    box.markdown(f"**Invoice nonce** {mono(challenge['invoice_nonce'])}",
                 unsafe_allow_html=True)
    box.caption("Payload handed verbatim to `DeterministicPolicyGate.evaluate_and_lock` "
                "(x402-style `accepts[0]` payment requirement, flattened):")
    box.code(json.dumps(challenge, indent=2), language="json")


def card_gate(
    container, passed: bool, reason: str | None, spent_paise: int, pool_paise: int
) -> None:
    box = card(container, "green" if passed else "red")
    box.subheader("③ Deterministic Policy Gate")
    if passed:
        box.markdown(chip("🟢 PASS — all checks satisfied", "ok"), unsafe_allow_html=True)
        box.progress(
            min(spent_paise / pool_paise, 1.0) if pool_paise else 0.0,
            text=f"Pool used: ₹{spent_paise / 100:.2f} / ₹{pool_paise / 100:.2f}",
        )
    else:
        box.markdown(chip("🔴 BLOCKED — transaction halted", "bad"), unsafe_allow_html=True)
        box.error(f"**Policy error:** {reason}")
        box.caption(
            "No pool deduction, no nonce consumed — `evaluate_and_lock` raised before "
            "reaching its state-mutating lines. See tests/test_guardrails.py."
        )


def card_settlement(container, order_id: str | None, webhook_entry: dict | None) -> None:
    ok = bool(webhook_entry) and webhook_entry["status"] == "ok"
    box = card(container, "green" if ok else ("slate" if order_id is None else "amber"))
    box.subheader("④ Razorpay Settlement & HMAC Webhook")
    if order_id is None:
        box.info("Skipped — the gate blocked the transaction before settlement. "
                  "No Razorpay order was created and no webhook fired.")
        return
    box.markdown(f"**Order ID** {mono(order_id)}", unsafe_allow_html=True)
    if webhook_entry:
        detail = webhook_entry.get("detail", {})
        msg = (
            f"HMAC SHA-256 webhook {'verified ✅' if ok else 'rejected ❌'} "
            f"(HTTP {detail.get('http_status')}) → `{detail.get('body')}`"
        )
        (box.success if ok else box.error)(msg)
    box.link_button(
        "🔗 Verify in Razorpay Test Dashboard",
        f"{RAZORPAY_ORDERS_DASHBOARD}/{order_id}",
        use_container_width=False,
    )
    box.caption(f"Direct link opens order `{order_id}` in the Razorpay test dashboard.")


def card_result(container, resource: dict | None, failure_reason: str | None) -> None:
    box = card(container, "green" if resource is not None else "amber")
    box.subheader("⑤ Payload Delivery / Graceful Halt")
    if resource is not None:
        box.markdown(chip("resource unlocked & delivered", "ok"), unsafe_allow_html=True)
        box.code(json.dumps(resource, indent=2), language="json")
    else:
        box.markdown(chip("no resource delivered — halted gracefully", "warn"),
                     unsafe_allow_html=True)
        box.warning(failure_reason)


# --------------------------------------------------------------------------- #
# ORCHESTRATION
# --------------------------------------------------------------------------- #
def execute(scenario: str, mandate: SpendMandate, pool_paise: int) -> None:
    audit = AuditTrail()
    slots = [st.empty() for _ in range(5)]

    try:
        client = httpx.Client(base_url=MERCHANT_BASE_URL, timeout=10)
        manifest = client.get(MANIFEST_PATH).json()
    except Exception as exc:
        st.error(
            f"Cannot reach merchant server at {MERCHANT_BASE_URL}. "
            f"Start it with `uvicorn merchant_server:app`.\n\n{exc}"
        )
        return

    # ① manifest discovery — LLM does intent extraction ONLY; it never
    # touches Razorpay, the gate, or an amount that gets charged.
    plan = llm_plan("Find and purchase tech equity sentiment under ₹30", manifest, audit)
    engine = plan.get("engine", "unknown")
    engine_note = (
        f"Groq {engine} (live LLM)"
        if engine.startswith(("groq/", "llama", "openai/", "qwen/"))
        else f"heuristic fallback ({engine})"
    )
    card_manifest(slots[0], plan, engine_note)

    # ② 402 intercept
    resp = client.get(RESOURCE_PATH)
    if resp.status_code != 402:
        slots[1].error(f"Expected HTTP 402, got {resp.status_code}")
        return
    challenge = resp.json()
    original_amount = challenge["amount_paise"]
    original_mcc = challenge["mcc"]
    fresh_nonce = challenge["invoice_nonce"]
    gate = load_gate()
    note = None

    # Attack injection: rewrite the exact dict (or gate ledger) that
    # evaluate_and_lock will scrutinise.
    if scenario == "happy":
        challenge["amount_paise"] = 2500
    elif scenario == "tamper_price":
        # Re-price to an amount that ALWAYS exceeds the mandate's per-tx
        # ceiling, no matter what the sidebar widget is set to — otherwise a
        # user who raised "Max Per-Transaction Limit" to ₹500 would let the
        # tampered charge sail through and get debited.
        challenge["amount_paise"] = max(50_000, mandate.max_per_tx_paise + 5_000)
        note = (
            f"Merchant re-priced the ₹{original_amount / 100:.2f} resource to "
            f"₹{challenge['amount_paise'] / 100:,.2f} — strictly above your "
            f"₹{mandate.max_per_tx_paise / 100:,.2f} single-tx ceiling."
        )
    elif scenario == "unauthorized_mcc":
        challenge["mcc"] = "7995"
    elif scenario == "replay_nonce":
        challenge["invoice_nonce"] = st.session_state.last_nonce or fresh_nonce
        gate.seen_nonces.add(challenge["invoice_nonce"])
    elif scenario == "pool_exhaustion":
        challenge["amount_paise"] = 2500
        # Simulate prior spends having nearly emptied the pool: at most ₹10
        # of headroom left, regardless of the configured pool size.
        gate.consumed_pools = max(pool_paise - 1000, 0)
        note = (
            f"Simulated: ₹{gate.consumed_pools / 100:.2f} already consumed from "
            f"prior spends, leaving only ₹{max(pool_paise - gate.consumed_pools, 0) / 100:.2f} "
            "of headroom for this ₹25.00 charge."
        )

    st.session_state.last_nonce = fresh_nonce
    card_intercept(slots[1], challenge, original_amount, original_mcc, note)

    # ③ deterministic gate — evaluates the tampered payload verbatim.
    # Rejected transactions never deduct: the gate itself never mutates its
    # ledger before every check passes (see evaluate_and_lock), and here we
    # additionally never write the ledger back into st.session_state unless
    # result["status"] == "SUCCESS".
    try:
        gate.evaluate_and_lock(mandate, challenge)
        result = {"status": "SUCCESS", "reason": None, "deducted": challenge["amount_paise"]}
    except PolicyViolation as exc:
        result = {"status": "HALTED", "reason": str(exc), "deducted": 0}

    card_gate(slots[2], result["status"] == "SUCCESS", result["reason"], gate.spent_paise, pool_paise)

    if result["status"] == "HALTED":
        # Pool balance / consumed quota stay completely untouched.
        card_settlement(slots[3], None, None)
        card_result(slots[4], None, f"HALTED — blocked by the deterministic gate: {result['reason']}")
        return

    # Gate passed: only NOW is it safe to persist the debited ledger.
    st.session_state.spent_paise = gate.consumed_pools
    st.session_state.used_nonces = set(gate.seen_nonces)

    # ④ settle (gate passed, so challenge["amount_paise"] is within policy)
    order_id = create_test_order(result["deducted"], audit)
    fire_settlement_webhook(order_id, result["deducted"], audit)
    webhook_entry = next(
        (e for e in audit.as_list() if e["step"] == "settlement_webhook"), None
    )
    card_settlement(slots[3], order_id, webhook_entry)

    # ⑤ fetch unlocked resource
    unlocked = client.get(RESOURCE_PATH, headers={"X-Payment-Order-Id": order_id})
    if unlocked.status_code == 200:
        card_result(slots[4], unlocked.json(), None)
    else:
        card_result(slots[4], None, f"Merchant returned HTTP {unlocked.status_code}")


if run:
    execute(scenario, mandate, pool_paise)
    render_header()  # reflect any ledger deduction from this run immediately
else:
    st.info(
        "Configure the mandate on the left, pick a scenario above, then **Execute**."
    )
