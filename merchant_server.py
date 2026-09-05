"""Merchant server for the agentic settlement proxy.

Serves a paid intelligence API behind HTTP 402 Payment Required, discoverable
by AI buyers via an ``/.well-known/agentic-commerce.json`` manifest whose
payment-requirement shape follows the x402 pattern (``x402Version`` +
``accepts[]``) so any x402-aware agent can parse it without bespoke glue.
Access is granted only after Razorpay confirms payment via an HMAC SHA-256
signed ``order.paid`` webhook. No LLM is involved in any settlement decision
here -- this server only issues challenges and checks cryptographic proof of
payment; the buyer-side ``DeterministicPolicyGate`` is what a caller must
satisfy before it ever reaches this settlement step.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets

from dotenv import load_dotenv
from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse

load_dotenv()

WEBHOOK_SECRET = os.environ["RAZORPAY_WEBHOOK_SECRET"]

X402_VERSION = 1
API_PATH = "/api/v1/market-data"
AMOUNT_PAISE = 2500
CURRENCY = "INR"
MCC = "7372"
PAY_TO = os.environ.get("RAZORPAY_KEY_ID", "razorpay_test_merchant")

app = FastAPI(title="Agentic Settlement Proxy - Merchant Server")

# In-memory settlement state (process-lifetime only).
settled_orders: set[str] = set()
# Nonces we have handed out in 402 challenges, for optional correlation/debug.
issued_nonces: set[str] = set()


def _payment_requirement(invoice_nonce: str | None = None) -> dict:
    """An x402-shaped ``PaymentRequirements`` object for this resource.

    x402 (https://x402.org) defines a 402 body as ``{x402Version, accepts:
    [PaymentRequirements]}``, where each requirement names a ``scheme`` and
    ``network`` for settlement. Razorpay/INR test-mode orders aren't a native
    x402 "exact" EVM scheme, so we declare our own ``razorpay-inr`` scheme
    over the ``razorpay-test`` network and carry the India-specific fields
    (MCC, paise amount, invoice nonce) in ``extra`` -- the same extension
    point x402 itself uses for scheme-specific data.
    """
    requirement = {
        "scheme": "razorpay-inr",
        "network": "razorpay-test",
        "maxAmountRequired": str(AMOUNT_PAISE),
        "resource": API_PATH,
        "description": "Paid market intelligence: sentiment and signals.",
        "mimeType": "application/json",
        "payTo": PAY_TO,
        "maxTimeoutSeconds": 900,
        "asset": CURRENCY,
        "extra": {
            "mcc": MCC,
            "amount_paise": AMOUNT_PAISE,
            "currency": CURRENCY,
        },
    }
    if invoice_nonce is not None:
        requirement["extra"]["invoice_nonce"] = invoice_nonce
    return requirement


@app.get("/.well-known/agentic-commerce.json")
def agentic_commerce_manifest() -> dict:
    """Agentic-commerce discovery manifest with an x402-shaped catalog.

    Any AI buyer -- ours or a third party's -- can GET this once, read
    ``accepts[0]`` for price/MCC/settlement network, and know exactly what a
    call to ``resource`` will cost before it ever makes the request. This is
    the "agent-readable catalog" + "makes a merchant transactable by an AI
    buyer end to end" surface the track asks for.
    """
    return {
        "x402Version": X402_VERSION,
        "protocol": {
            "discovery": "agentic-commerce.json",
            "payment": "x402-inspired (razorpay-inr scheme)",
            "mandate": "AP2 / NPCI UAP-inspired delegated authorization "
                       "(Ed25519-signed SpendMandate, verified client-side by "
                       "DeterministicPolicyGate before any order is created)",
        },
        "provider": "Razorpay Agentic Settlement Proxy",
        "payTo": PAY_TO,
        "resources": [
            {
                "resource": API_PATH,
                "method": "GET",
                "name": "Market Sentiment API",
                "tags": ["market-data", "sentiment", "finance"],
                "description": "Paid market intelligence: sentiment and signals.",
                "accepts": [_payment_requirement()],
                # Legacy flat fields, kept for simple non-x402 consumers.
                "mcc": MCC,
                "amount_paise": AMOUNT_PAISE,
                "currency": CURRENCY,
            }
        ],
    }


@app.get(API_PATH)
def market_data(x_payment_order_id: str | None = Header(default=None)) -> JSONResponse:
    """Return market data only for a settled order; otherwise a 402 challenge."""
    if x_payment_order_id and x_payment_order_id in settled_orders:
        return JSONResponse(
            status_code=200,
            content={
                "resource": API_PATH,
                "order_id": x_payment_order_id,
                "as_of": "2026-09-04T00:00:00Z",
                "market_sentiment": {
                    "symbol": "NIFTY50",
                    "score": 0.62,
                    "label": "cautiously bullish",
                    "confidence": 0.71,
                    "signals": [
                        {"name": "momentum_14d", "value": 0.18},
                        {"name": "put_call_ratio", "value": 0.87},
                        {"name": "fii_flow_crore", "value": 1240.5},
                    ],
                },
            },
        )

    invoice_nonce = secrets.token_hex(16)
    issued_nonces.add(invoice_nonce)
    return JSONResponse(
        status_code=402,
        content={
            "x402Version": X402_VERSION,
            "error": "payment_required",
            "accepts": [_payment_requirement(invoice_nonce)],
            # Legacy flat fields -- exactly what DeterministicPolicyGate.evaluate_and_lock
            # consumes as its `challenge` dict.
            "amount_paise": AMOUNT_PAISE,
            "currency": CURRENCY,
            "mcc": MCC,
            "invoice_nonce": invoice_nonce,
            "manifest": "/.well-known/agentic-commerce.json",
        },
    )


@app.post("/api/v1/razorpay-webhook")
async def razorpay_webhook(
    request: Request,
    x_razorpay_signature: str | None = Header(default=None),
) -> JSONResponse:
    """Verify the Razorpay HMAC SHA-256 signature and settle paid orders."""
    raw_body = await request.body()

    if not x_razorpay_signature:
        return JSONResponse(status_code=400, content={"error": "missing signature"})

    expected = hmac.new(
        WEBHOOK_SECRET.encode("utf-8"), raw_body, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, x_razorpay_signature):
        return JSONResponse(status_code=400, content={"error": "invalid signature"})

    payload = await request.json()
    if payload.get("event") != "order.paid":
        return JSONResponse(status_code=200, content={"status": "ignored"})

    order_entity = (
        payload.get("payload", {}).get("order", {}).get("entity", {})
    )
    order_id = order_entity.get("id")
    if not order_id:
        return JSONResponse(status_code=400, content={"error": "missing order id"})

    settled_orders.add(order_id)
    return JSONResponse(status_code=200, content={"status": "settled", "order_id": order_id})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
