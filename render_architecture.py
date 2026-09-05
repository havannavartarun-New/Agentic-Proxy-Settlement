"""Regenerate architecture.png for the Razorpay Agentic Settlement Proxy.

    pip install matplotlib
    python render_architecture.py

Edit the block()/arrow() calls below and re-run to update the diagram.
"""
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "architecture.png")

C_LLM   = "#FEF3C7"; E_LLM   = "#B45309"
C_GATE  = "#DCFCE7"; E_GATE  = "#15803D"
C_MERCH = "#DBEAFE"; E_MERCH = "#1D4ED8"
C_RAIL  = "#EDE9FE"; E_RAIL  = "#6D28D9"
C_HALT  = "#FEE2E2"; E_HALT  = "#DC2626"
C_NEUT  = "#F1F5F9"; E_NEUT  = "#334155"
C_MAND  = "#E0E7FF"; E_MAND  = "#4338CA"
INK = "#0f172a"

fig, ax = plt.subplots(figsize=(16.5, 13.0))
ax.set_xlim(0, 140)
ax.set_ylim(0, 100)
ax.axis("off")


def block(cx, cy, w, h, title, body="", fc=C_NEUT, ec=E_NEUT,
          tsize=11.5, bsize=8.2, lw=2, ls=1.55, title_only=False):
    x0, y0 = cx - w / 2, cy - h / 2
    ax.add_patch(FancyBboxPatch((x0, y0), w, h,
                 boxstyle="round,pad=0.15,rounding_size=0.7",
                 linewidth=lw, edgecolor=ec, facecolor=fc, zorder=2))
    if body:
        ax.text(cx, y0 + h - 1.4, title, ha="center", va="top", fontsize=tsize,
                fontweight="bold", color=INK, zorder=3)
        ax.text(cx, y0 + h - 3.6, body, ha="center", va="top",
                fontsize=bsize, color="#1e293b", zorder=3, linespacing=ls)
    else:
        ax.text(cx, cy, title, ha="center", va="center", fontsize=tsize,
                fontweight="bold", color=INK, zorder=3, linespacing=1.4)


def arrow(p0, p1, label="", color="#334155", lw=2.4, rad=0.0, ls="-", fs=8,
          lpos=None, double=False):
    style = "<|-|>" if double else "-|>"
    ax.add_patch(FancyArrowPatch(p0, p1, connectionstyle=f"arc3,rad={rad}",
                 arrowstyle=style, mutation_scale=20, linewidth=lw, color=color,
                 linestyle=ls, zorder=1))
    if label:
        mx, my = lpos if lpos else ((p0[0] + p1[0]) / 2, (p0[1] + p1[1]) / 2)
        ax.text(mx, my, label, ha="center", va="center", fontsize=fs,
                color="#334155", zorder=4, linespacing=1.35,
                bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="#e2e8f0", alpha=0.96))


# ---------- title ----------
ax.text(62, 98.6, "Razorpay Agentic Settlement Proxy  \u2014  Architecture",
        ha="center", fontsize=17.5, fontweight="bold", color=INK)
ax.text(62, 96.2, "Track 01 \u00b7 AI Growth & Agentic Commerce      \u00b7      "
                  "x402 / AP2 delegation",
        ha="center", fontsize=10, color="#475569")

# ---------- legend (top-right, above the merchant swimlane) ----------
ax.add_patch(FancyBboxPatch((105.5, 88.0), 31.5, 9.6,
             boxstyle="round,pad=0.2,rounding_size=0.5",
             lw=1.2, edgecolor="#cbd5e1", facecolor="white", zorder=2))
ax.text(121, 96.6, "LEGEND", ha="center", fontsize=9, fontweight="bold", color=INK, zorder=3)
for i, (fc, ec, txt) in enumerate([
        (C_LLM, E_LLM, "probabilistic (LLM)"),
        (C_GATE, E_GATE, "deterministic money gate"),
        (C_MERCH, E_MERCH, "merchant / HTTP surface"),
        (C_RAIL, E_RAIL, "Razorpay test rail"),
        (C_HALT, E_HALT, "graceful halt")]):
    yy = 94.7 - i * 1.4
    ax.add_patch(FancyBboxPatch((107.2, yy - 0.45), 1.7, 0.9, boxstyle="round,pad=0.02",
                 lw=1.3, edgecolor=ec, facecolor=fc, zorder=3))
    ax.text(109.7, yy, txt, ha="left", va="center", fontsize=7.6, color="#1e293b", zorder=3)

# ---------- layout anchors ----------
CX = 68        # centre spine
LX = 18        # left column
RX = 122       # right column (merchant swimlane)
SW = 42        # spine box width

# ---------- centre spine ----------
block(CX, 92.5, 26, 5.0, "USER")
block(CX, 83.0, SW, 6.6,
      "BUYER AGENT   (buyer_agent.py \u00b7 app.py)",
      "orchestrates:  discovery \u2192 policy gate \u2192 settlement",
      tsize=11, bsize=8.3)
block(CX, 69.0, SW, 7.0,
      "HTTP 402 CHALLENGE  \u2014  intercepted",
      "accepts[]  \u00b7  amount_paise  \u00b7  mcc  \u00b7  invoice_nonce",
      fc=C_MERCH, ec=E_MERCH, tsize=10.5, bsize=8.3)
block(CX, 51.5, SW + 2, 15.5,
      "DETERMINISTIC POLICY GATE",
      "crypto_guardrails.py     \u00b7     zero-LLM  \u00b7  pure  \u00b7  synchronous\n\n"
      "\u2460 Ed25519 signature     \u2461 nonce replay     \u2462 expiry\n"
      "\u2463 MCC allow-list       \u2464 per-tx ceiling     \u2465 pool budget\n\n"
      "state mutates ONLY after all six checks pass",
      fc=C_GATE, ec=E_GATE, tsize=13, bsize=8.6, lw=2.8)
block(CX, 33.5, SW - 4, 6.6,
      "RAZORPAY  \u00b7  TEST MODE",
      "rzp.order.create   \u2192   order_id",
      fc=C_RAIL, ec=E_RAIL, tsize=10.5, bsize=8.3)
block(CX, 24.0, SW, 6.6,
      "HMAC SHA-256 WEBHOOK",
      "order.paid signature verified  \u2192  order settled",
      fc=C_MERCH, ec=E_MERCH, tsize=10, bsize=8.3)
block(CX, 14.5, SW, 6.6,
      "RESOURCE DELIVERED",
      "GET market-data + X-Payment-Order-Id  \u2192  200 + payload",
      fc=C_MERCH, ec=E_MERCH, tsize=10, bsize=8.0)
block(70, 5.0, 134, 5.6,
      "AUDIT TRAIL",
      "every step timestamped + human-readable reason      \u00b7      "
      "5 live cards in app.py      \u00b7      JSON audit[] in buyer_agent.py",
      tsize=10.5, bsize=8.3)

# ---------- left column ----------
block(LX, 82.5, 31, 13.0,
      "GROQ  LLM",
      "PROBABILISTIC  \u00b7  discovery &\nintent extraction ONLY\n\n"
      "manifest \u2192 { fits_goal, reason }\n"
      "no amount \u00b7 no wallet \u00b7 no gate",
      fc=C_LLM, ec=E_LLM, tsize=11, bsize=7.7)
block(LX, 55.0, 31, 13.5,
      "USER SPEND MANDATE",
      "AP2 / NPCI UAP\u2013style\ndelegated authorization\n\n"
      "Ed25519-signed \u00b7 valid_until\npool + per-tx ceilings \u00b7 MCC bind",
      fc=C_MAND, ec=E_MAND, tsize=10, bsize=7.7)
block(LX, 33.0, 31, 17.0,
      "GRACEFUL HALT",
      "PolicyViolation raised\n\n"
      "status = HALTED  ·  deducted = 0\n"
      "pool ledger untouched\n"
      "payment rails never touched\n\n"
      "e.g.  THRESHOLD BREACH ·\nPOOL EXHAUSTED ·  replay",
      fc=C_HALT, ec=E_HALT, tsize=10.5, bsize=7.6, ls=1.5)

# ---------- right column (merchant swimlane) ----------
block(RX, 48.0, 30, 74.0,
      "MERCHANT SERVER",
      "(merchant_server.py)\n\n\n"
      "\u2460  GET /.well-known/\n     agentic-commerce.json\n"
      "     \u2192  x402 catalog\n"
      "        price \u00b7 MCC \u00b7 resource\n\n\n"
      "\u2462  GET /api/v1/market-data\n"
      "     \u2192  HTTP 402 Payment\n        Required\n\n\n"
      "\u2464  POST /api/v1/\n     razorpay-webhook\n"
      "     \u2192  HMAC SHA-256 verify\n\n\n"
      "\u2465  resource delivery\n"
      "     \u2192  200 + payload",
      fc=C_MERCH, ec=E_MERCH, tsize=12, bsize=8.4)

# ---------- arrows ----------
arrow((CX, 89.9), (CX, 86.4),
      label='user goal:  "\u2026 sentiment under \u20b930"', fs=7.6, lpos=(CX, 88.1))
# buyer <-> groq
arrow((CX - SW / 2, 84.2), (LX + 15, 84.2), label="\u2461  manifest + goal",
      rad=0, fs=7.8, lpos=(42.5, 86.0))
arrow((LX + 15, 81.6), (CX - SW / 2, 81.6), label="{ fits_goal, reason }",
      rad=0, fs=7.8, lpos=(42.5, 79.8))
# buyer -> merchant discovery
arrow((CX + SW / 2, 84.0), (RX - 15, 79.0),
      label="\u2460  GET manifest\n\u2192  x402 catalog", fs=7.6, lpos=(99, 85.5))
# buyer -> 402 (request) ; merchant -> 402 (response)
arrow((CX, 79.7), (CX, 72.6), label="\u2462  GET /api/v1/market-data",
      fs=7.8, lpos=(CX, 76.0))
arrow((RX - 15, 66.0), (CX + SW / 2, 69.0),
      label="\u2462  HTTP 402\n     response", fs=7.6, lpos=(99, 63.5))
# 402 -> gate
arrow((CX, 65.4), (CX, 59.4),
      label="challenge  { amount, mcc, invoice_nonce }", fs=7.8, lpos=(CX, 62.5))
# mandate -> gate
arrow((LX + 15.5, 54.0), (CX - SW / 2 - 1, 53.0), label="presents\nsigned mandate",
      fs=7.6, lpos=(39.5, 58.0))
# gate -> halt  (FAIL)
arrow((CX - SW / 2 - 1, 48.5), (LX + 15.5, 38.5), label="\u2717  any check FAILS",
      color=E_HALT, fs=8.2, lpos=(42, 44.0))
# gate -> razorpay (PASS)
arrow((CX, 43.6), (CX, 37.0),
      label="PASS \u2713   lock nonce  +  debit pool", color=E_GATE, fs=8.2,
      lpos=(CX, 40.4))
# razorpay -> webhook
arrow((CX, 30.1), (CX, 27.4), label="order_id", fs=7.6, lpos=(CX + 9, 28.7))
# merchant -> webhook
arrow((RX - 15, 24.0), (CX + SW / 2, 24.0), label="verifies\nwebhook HMAC",
      fs=7.4, lpos=(99, 27.0))
# webhook -> resource
arrow((CX, 20.6), (CX, 17.9))
# merchant -> resource
arrow((RX - 15, 14.5), (CX + SW / 2, 14.5), label="200 + payload", fs=7.4,
      lpos=(99, 17.2))
# resource -> audit
arrow((CX, 11.1), (CX, 8.0), label="stage-by-stage logging", fs=7.6,
      lpos=(CX, 9.6))
# halt -> audit (dashed)
arrow((LX - 2, 24.5), (48, 7.9), label="halt is logged\n+ shown too", color=E_HALT,
      ls="--", lw=1.9, rad=-0.30, fs=7.4, lpos=(22, 15.5))

fig.savefig(OUT, dpi=170, bbox_inches="tight", facecolor="white", pad_inches=0.3)
print("wrote", OUT)
