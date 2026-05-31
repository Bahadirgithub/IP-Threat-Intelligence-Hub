"""
pages/provider_research.py
--------------------------
Streamlit page for grey-hosting provider research.

Layout:
  1. Table of UNRESEARCHED grey-hosting IPs (those waiting for an agent run)
  2. ASN input + Research button
  3. Result panel with colored score bar + explanation

Save this file as: pages/provider_research.py
"""

import json
from typing import Optional
import streamlit as st
import pandas as pd

from provider_research_agent import research_provider, GEMINI_API_KEY
from provider_intel_db import (
    save_research_result, is_researched, load_intel,
)
from grey_check import (
    add_grey_scores, explain_intel_contribution, project_asn_tier_from_intel,
    _asn_to_int,
)
from database import save_grey

st.set_page_config(page_title="Provider Research", layout="wide", page_icon="🔍")
st.title("🔍 Provider Research")
st.page_link("app.py", label="← Home Page")
st.divider()


# ── How the agent works (informational) ──────────────────────────────────────
with st.expander("ℹ️  How this agent works (trusted sources only)"):
    st.markdown("""
The agent uses **Gemini 2.0 Flash + Google Search grounding + DuckDuckGo + bgpview.io + RDAP**
to gather provider intel. All free. No manual review needed because:

- **Provider self-claims are rejected.** A hosting company's own page saying "we are ISO certified" is NOT trusted.
- **Trusted sources only.** Each claim must come from one of:
  - **ISO 27001:** iso.org, bsigroup.com, tuvsud.com, dnv.com, dekra.com, sgs.com, ...
  - **SOC 2:** aicpa.org or Big-4 auditor (deloitte, ey, kpmg, pwc)
  - **FedRAMP:** marketplace.fedramp.gov ONLY
  - **Public company:** sec.gov, en.wikipedia.org, nyse.com, nasdaq.com
  - **Negative press:** krebsonsecurity.com, correctiv.org, spamhaus.org, domaintools.com, ...
- **Untrusted → null.** If no trusted source is found, the field is `null` (unknown).
- **Python post-validates.** Even if the LLM bypasses the rule, the response is filtered before saving.
- **Crypto payment is the only exception** — provider's own checkout page is acceptable.

Once researched, an ASN is **never re-queried** (deduplicated automatically).
""")


# ── Helpers ──────────────────────────────────────────────────────────────────

def _normalize_asn_input(text: str) -> Optional[int]:
    s = (text or "").upper().strip().replace("AS", "")
    try:
        return int(s)
    except (ValueError, TypeError):
        return None


def _render_score_bar(score: float, tier: str, label_extra: str = ""):
    """Render a colored horizontal bar based on tier."""
    colors = {
        "grey_high": ("#e74c3c", "HIGH — block candidate"),
        "grey_mid":  ("#f39c12", "MID — review queue"),
        "grey_low":  ("#27ae60", "LOW — monitor only"),
        "unknown":   ("#95a5a6", "UNKNOWN"),
    }
    color, label = colors.get(tier, ("#95a5a6", "UNKNOWN"))
    pct = max(2.0, min(100.0, (score / 10.0) * 100.0))   # min 2% so empty bar isn't invisible

    html = f"""
    <div style="background:#f0f0f0; border-radius: 10px; padding: 6px; margin: 14px 0;">
        <div style="background:{color}; width:{pct}%; padding: 16px 22px; border-radius: 6px; color: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
            <div style="font-size: 28px; font-weight: bold; line-height:1;">{score:.1f} <span style="font-size:16px; opacity:0.85;">/ 10</span></div>
            <div style="font-size: 13px; margin-top: 6px; letter-spacing: 0.5px;">{label}{(' · ' + label_extra) if label_extra else ''}</div>
        </div>
    </div>
    """
    st.markdown(html, unsafe_allow_html=True)


def _yes_no(v):
    if v == 1: return "✅ Yes"
    if v == 0: return "❌ No"
    return "❓ Unknown"


def _rescore_session_grey(asn_int: int):
    """After research: rescore IPs from this ASN in current session + save to DB."""
    if "grey_ips" not in st.session_state:
        return 0
    df = st.session_state["grey_ips"]
    if df.empty:
        return 0

    mask = df["asn"].apply(_asn_to_int) == asn_int
    if not mask.any():
        return 0

    rescored = add_grey_scores(df[mask].copy())
    # Update session_state with new scores
    for idx in rescored.index:
        df.at[idx, "grey_score"]    = rescored.at[idx, "grey_score"]
        df.at[idx, "grey_sub_tier"] = rescored.at[idx, "grey_sub_tier"]
        df.at[idx, "grey_signals"]  = rescored.at[idx, "grey_signals"]

    save_grey(rescored)
    st.session_state["grey_ips"] = df
    return int(mask.sum())


# ── Pre-flight checks ────────────────────────────────────────────────────────
if not GEMINI_API_KEY:
    st.error("`GEMINI_API_KEY` not set in `.env`. Get a free key at https://aistudio.google.com/app/apikey")
    st.stop()

if "grey_ips" not in st.session_state or st.session_state["grey_ips"].empty:
    st.info("Run the main pipeline first (Fetch & Process Data) to populate grey-hosting data.")
    st.stop()


# ── 1. UNRESEARCHED IPs TABLE ───────────────────────────────────────────────
st.subheader("1️⃣ Unresearched Grey Hosting IPs")

df_grey = st.session_state["grey_ips"]
df_unknown = df_grey[df_grey["grey_sub_tier"] == "unknown"].copy()

if df_unknown.empty:
    st.success("✅ All grey-hosting ASNs in the current batch have been researched.")
else:
    st.caption(
        f"📋 {len(df_unknown):,} IPs across **{df_unknown['asn'].nunique()}** distinct ASNs are waiting to be researched. "
        f"Pick an ASN from the table below and paste it into the input."
    )

    UNK_COLS = [
        "ipAddress", "provider", "asn", "organisation",
        "country", "city", "hostname",
        "proxy", "vpn", "tor",
        "totalReports", "numDistinctUsers",
    ]
    st.dataframe(
        df_unknown[[c for c in UNK_COLS if c in df_unknown.columns]],
        use_container_width=True,
        hide_index=True,
        height=350,
    )

st.divider()


# ── 2. RESEARCH INPUT ───────────────────────────────────────────────────────
st.subheader("2️⃣ Research an ASN")

col_in, col_btn = st.columns([3, 1])
with col_in:
    asn_input = st.text_input(
        "Enter the ASN you want to research:",
        placeholder="e.g.  24940    or    AS24940",
        label_visibility="collapsed",
    )
with col_btn:
    do_research = st.button("🚀 Research", type="primary", use_container_width=True)


if do_research:
    asn_int = _normalize_asn_input(asn_input)

    if asn_int is None:
        st.error("Invalid ASN. Type a number like `24940` or `AS24940`.")
    elif is_researched(asn_int):
        st.warning(f"ℹ️ AS{asn_int} is already researched. Result is shown below.")
        st.session_state["last_research_asn"] = asn_int
    else:
        # Try to pull a name hint from the current grey batch
        hint = ""
        if not df_unknown.empty:
            match = df_unknown[df_unknown["asn"].apply(_asn_to_int) == asn_int]
            if not match.empty:
                hint = match.iloc[0].get("organisation") or ""

        with st.spinner(f"Researching AS{asn_int} via Gemini + DuckDuckGo + bgpview.io..."):
            try:
                result = research_provider(asn_int, hint)
                save_research_result(result)
                # Rescore current session IPs from this ASN
                rescored_count = _rescore_session_grey(asn_int)
                st.success(
                    f"✅ AS{asn_int} researched. "
                    f"{rescored_count} IP(s) in the current batch rescored."
                )
                st.session_state["last_research_asn"] = asn_int
            except Exception as e:
                st.error(f"Research failed: {e}")


# ── 3. RESULT PANEL ──────────────────────────────────────────────────────────
if "last_research_asn" in st.session_state:
    asn_int = st.session_state["last_research_asn"]
    intel = load_intel(asn_int)

    st.divider()
    st.subheader(f"3️⃣ Result — AS{asn_int}")

    if not intel:
        st.warning("No intel found for this ASN.")
    else:
        # ── Score bar ───────────────────────────────────────────────────────
        projected_score, projected_tier = project_asn_tier_from_intel(intel)
        _render_score_bar(
            projected_score, projected_tier,
            label_extra=f"projected baseline for {intel.get('provider_name') or 'AS' + str(asn_int)}",
        )

        st.caption(
            "👆 This is the **baseline projected score** from provider intel alone. "
            "Each individual IP from this ASN may add +0 to +3 from IP-specific signals "
            "(PTR pattern, AbuseIPDB report count, ProxyCheck flags)."
        )

        # ── Provider facts ──────────────────────────────────────────────────
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("##### 📋 Provider facts")
            st.write(f"- **Name:** {intel.get('provider_name') or '—'}")
            st.write(f"- **Website:** {intel.get('website') or '—'}")
            st.write(f"- **Country:** {intel.get('country_code') or '—'}")
            st.write(f"- **ASN age:** {intel.get('asn_age_years') or '—'} years")
            st.write(f"- **Abuse mailbox:** {intel.get('abuse_mailbox') or '—'}")

        with c2:
            st.markdown("##### 🛡️ Compliance & payments")
            st.write(f"- **ISO 27001:** {_yes_no(intel.get('iso_27001'))}")
            st.write(f"- **SOC 2:** {_yes_no(intel.get('soc2'))}")
            st.write(f"- **FedRAMP:** {_yes_no(intel.get('fedramp'))}")
            st.write(f"- **Crypto:** {_yes_no(intel.get('accepts_crypto'))} ({intel.get('crypto_coins') or '—'})")
            st.write(f"- **Public co:** {_yes_no(intel.get('public_company'))} ({intel.get('company_ticker') or '—'})")
            st.write(f"- **Negative press:** {intel.get('negative_press_count') or 0}")

        # ── Negative press details ──────────────────────────────────────────
        try:
            neg = json.loads(intel.get("negative_press_json") or "[]")
            if neg:
                st.markdown("##### 🚨 Negative press (trusted sources only)")
                for n in neg:
                    domain = n.get("source_domain") or "source"
                    url = n.get("url", "")
                    summary = n.get("summary", "")
                    st.markdown(f"- [{domain}]({url}) — {summary[:300]}")
        except Exception:
            pass

        # ── Score breakdown ─────────────────────────────────────────────────
        st.markdown("##### 🧮 How the score was computed")
        contributions = explain_intel_contribution(intel)

        if not contributions:
            st.write("No intel signals fired — score is purely 5.0 (neutral baseline).")
        else:
            breakdown = []
            for sig, val in contributions:
                sign = "↓" if val < 0 else "↑"
                color = "green" if val < 0 else "red"
                breakdown.append({
                    "signal": sig,
                    "direction": sign,
                    "contribution": f"{val:+.1f}",
                })
            df_break = pd.DataFrame(breakdown)
            st.dataframe(df_break, use_container_width=True, hide_index=True)

            total_intel = sum(v for _, v in contributions)
            st.markdown(
                f"**Intel total:** `{total_intel:+.1f}`  →  "
                f"baseline = `max(0, min(10, total + 5))` = **{projected_score:.1f}**"
            )

        # ── Tier meaning ────────────────────────────────────────────────────
        with st.expander("ℹ️ What do the tiers mean?"):
            st.markdown("""
| Score | Tier | Meaning | Action |
|-------|------|---------|--------|
| **0 – 3** | 🟢 **grey_low** | Behaves like mainstream cloud — mature provider, certified, good jurisdiction | Monitor only, no block |
| **3 – 6** | 🟡 **grey_mid** | Mixed signals — neither clearly safe nor clearly bad | Manual review per IP |
| **6 – 10** | 🔴 **grey_high** | Multiple bulletproof-leaning signals — high abuse rate, weak compliance, negative press | Blacklist candidate |

**Score formula:**
```
score = clip(intel_contribution + ip_level_signals + 5, 0, 10)
```

**Negative contributions** (lower score, mainstream-leaning):
- OECD country: -1.0
- ISO 27001 / SOC 2 certified: -1.0 each
- FedRAMP certified: -1.5
- ASN age > 10 years: -1.0
- Public company: -1.0
- Doesn't accept crypto: -0.5
- Has valid abuse mailbox: -0.3

**Positive contributions** (higher score, bulletproof-leaning):
- Higher-risk country (RU, CN, MD, etc.): +2.0
- Young ASN (<2 years): +1.0
- Accepts crypto: +1.0
- Negative press articles: +1.0 to +2.0
- Random/algorithmic PTR: +1.5
- Generic PTR (`vps-…`, `unmanaged.…`): +0.5
- High ASN share in current batch: +1.0 to +2.0
- High AbuseIPDB report count: +0.5 to +1.0
- ProxyCheck flags (compromised, scraper, proxy): +0.5 to +1.0 each
""")

        # ── Raw research JSON for audit ─────────────────────────────────────
        with st.popover("📄 Raw research JSON (audit)"):
            try:
                raw = json.loads(intel.get("raw_intel_json") or "{}")
                st.json(raw)
            except Exception:
                st.code(intel.get("raw_intel_json") or "")