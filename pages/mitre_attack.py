"""
pages/mitre_attack.py
─────────────────────
MITRE ATT&CK technique mapping page.
Shows technique cards per tactic and maps live session data to each technique.
"""

import streamlit as st
import pandas as pd

st.set_page_config(
    page_title="MITRE ATT&CK — ThreatWatch",
    layout="wide",
    page_icon="🎯",
)

# ── CSS ────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
/* Tactic header banners */
.tactic-banner {
    padding: 14px 22px;
    border-radius: 10px;
    margin-bottom: 6px;
    display: flex;
    align-items: center;
    gap: 12px;
}
.banner-ra { background: linear-gradient(135deg,#c0392b,#e74c3c); }
.banner-cc { background: linear-gradient(135deg,#1a237e,#283593); }
.banner-rc { background: linear-gradient(135deg,#1b5e20,#2e7d32); }
.banner-title {
    color: white;
    font-size: 17px;
    font-weight: 700;
    letter-spacing: .4px;
    margin: 0;
}
.banner-sub {
    color: rgba(255,255,255,.75);
    font-size: 12px;
    margin: 0;
}

/* Technique cards */
.tech-card {
    border-radius: 10px;
    padding: 16px 18px 14px;
    border-left: 5px solid;
    min-height: 120px;
    box-shadow: 0 2px 10px rgba(0,0,0,.08);
    position: relative;
    margin-bottom: 4px;
}
.tc-ra { border-color:#e74c3c; background:rgba(231,76,60,.06); }
.tc-cc { border-color:#283593; background:rgba(40,53,147,.06); }

/* ID badge */
.tid {
    font-family: 'Courier New', monospace;
    font-size: 11px;
    font-weight: 700;
    padding: 3px 9px;
    border-radius: 5px;
    letter-spacing: .4px;
    display: inline-block;
    margin-bottom: 8px;
}
.tid-ra { background:#fde8e8; color:#c0392b; border:1px solid #f1b0ab; }
.tid-cc { background:#e8eaf6; color:#1a237e; border:1px solid #9fa8da; }

/* Count pill */
.cpill {
    float: right;
    font-size: 11px;
    font-weight: 700;
    padding: 3px 10px;
    border-radius: 12px;
    color: white;
    margin-top: 1px;
}
.cp-ra { background:#c0392b; }
.cp-cc { background:#1a237e; }
.cp-zero { background:#aaa; }

/* Text */
.tname { font-size:14px; font-weight:600; margin-bottom:5px; }
.tdesc { font-size:12px; color:#777; line-height:1.5; }

/* Source chip */
.src-chip {
    display: inline-block;
    font-size: 10px;
    padding: 2px 7px;
    border-radius: 4px;
    margin-top: 8px;
    background: rgba(0,0,0,.07);
    color: #555;
}

/* Sub-group headers (T1583 / T1584) */
.sub-header {
    padding: 7px 14px;
    border-radius: 7px;
    margin: 14px 0 10px;
    display: inline-block;
    font-size: 13px;
    font-weight: 700;
    letter-spacing: .3px;
}
.sh-acquire    { background:#fde8e8; color:#c0392b; border:1px solid #f1b0ab; }
.sh-compromise { background:#fef3e2; color:#a04000; border:1px solid #f0c080; }
.sh-recon      { background:#e8f5e9; color:#1b5e20; border:1px solid #a5d6a7; }
.tc-rc { border-color:#2e7d32; background:rgba(46,125,50,.06); }
.tid-rc { background:#e8f5e9; color:#1b5e20; border:1px solid #a5d6a7; }
.cp-rc { background:#2e7d32; }
</style>
""", unsafe_allow_html=True)


# ── Helpers ────────────────────────────────────────────────────────────────────
def _safe_count(df: pd.DataFrame, col: str) -> int:
    if df.empty or col not in df.columns:
        return 0
    return int(df[col].fillna(0).astype(bool).sum())


def _get(key: str) -> pd.DataFrame:
    return st.session_state.get(key, pd.DataFrame())


def _pill(count, style: str) -> str:
    if count == 0:
        return f'<span class="cpill cp-zero">0 IPs</span>'
    return f'<span class="cpill {style}">{count:,} IPs</span>'


def card(tid: str, name: str, desc: str, source: str,
         count: int, tc_cls: str, tid_cls: str, pill_cls: str) -> str:
    return f"""
<div class="tech-card {tc_cls}">
  <div>
    <span class="tid {tid_cls}">{tid}</span>
    {_pill(count, pill_cls)}
  </div>
  <div class="tname">{name}</div>
  <div class="tdesc">{desc}</div>
  <span class="src-chip">📌 {source}</span>
</div>"""


def _hosting_ips(df: pd.DataFrame) -> pd.DataFrame:
    """Return only Hosting/Host rows from the existing grey-hosting set."""
    if df.empty or "type" not in df.columns:
        return df.iloc[0:0].copy()
    types = df["type"].fillna("").astype(str).str.strip().str.lower()
    return df.loc[types.isin({"host", "hosting"})].copy()


def _true_mask(series: pd.Series) -> pd.Series:
    """Handle boolean values and string representations such as 'True' safely."""
    if pd.api.types.is_bool_dtype(series):
        return series.fillna(False)
    return series.fillna("").astype(str).str.strip().str.lower().isin({"true", "1", "yes"})


# ── Live counts from session ───────────────────────────────────────────────────
all_ips = _get("all_ips")
grey_ips = _get("grey_ips")
grey_hosting_ips = _hosting_ips(grey_ips)

has_data = not all_ips.empty or not grey_ips.empty

compromised_grey_hosting_count = 0
if not grey_hosting_ips.empty and "compromised" in grey_hosting_ips.columns:
    compromised_grey_hosting_count = int(
        _true_mask(grey_hosting_ips["compromised"]).sum()
    )

cnt = {
    # TA0042 — Acquire Infrastructure
    "T1583.003": len(grey_hosting_ips),
    # TA0042 — Compromise Infrastructure
    "T1584.003": compromised_grey_hosting_count,
    # TA0043 — Reconnaissance (kept as before)
    "T1595.001": _safe_count(all_ips, "scraper"),
    "T1595.002": _safe_count(all_ips, "scraper"),
}


# ── Page header ────────────────────────────────────────────────────────────────
st.title("🎯 MITRE ATT&CK — Technique Mapping")
if has_data:
    total_flagged = sum(cnt.values())
    st.caption(
        f"**{total_flagged:,} total IP-technique hits** across the latest pipeline run. "
        "Counts update automatically when you re-run the pipeline."
    )
else:
    st.info(
        "💡 Run the pipeline on the main page first — "
        "IP counts will appear on each technique card."
    )

st.divider()


# ══════════════════════════════════════════════════════════════════════════════
# TA0042 — Resource Development
# ══════════════════════════════════════════════════════════════════════════════
st.markdown("""
<div class="tactic-banner banner-ra">
  <div>
    <p class="banner-title">⚒️ TA0042 — Resource Development</p>
    <p class="banner-sub">
      Adversary acquires infrastructure, accounts and capabilities before the attack.
    </p>
  </div>
</div>
""", unsafe_allow_html=True)

# ── T1583 Acquire Infrastructure ──────────────────────────────────────────────
st.markdown(
    '<span class="sub-header sh-acquire">⬆ T1583 — Acquire Infrastructure</span>',
    unsafe_allow_html=True,
)
st.markdown(card(
    "T1583.003", "Virtual Private Server",
    "Hosting IPs in the grey-hosting dataset are counted under this technique.",
    "Grey Hosting IPs with type=Hosting",
    cnt["T1583.003"], "tc-ra", "tid-ra", "cp-ra",
), unsafe_allow_html=True)

# ── T1584 Compromise Infrastructure ───────────────────────────────────────────
st.markdown(
    '<span class="sub-header sh-compromise">⚠ T1584 — Compromise Infrastructure</span>',
    unsafe_allow_html=True,
)
st.markdown(card(
    "T1584.003", "Virtual Private Server",
    "Grey-hosting Hosting IPs are counted here only when compromised=True.",
    "Grey Hosting IPs with type=Hosting and compromised=True",
    cnt["T1584.003"], "tc-ra", "tid-ra", "cp-ra",
), unsafe_allow_html=True)

st.divider()


# ══════════════════════════════════════════════════════════════════════════════
# TA0043 — Reconnaissance
# ══════════════════════════════════════════════════════════════════════════════
st.markdown("""
<div class="tactic-banner banner-rc">
  <div>
    <p class="banner-title">🔍 TA0043 — Reconnaissance</p>
    <p class="banner-sub">
      Adversary collects information to plan future operations — scanning, probing, fingerprinting.
    </p>
  </div>
</div>
""", unsafe_allow_html=True)

# ── T1595 Active Scanning ──────────────────────────────────────────────────────
st.markdown(
    '<span class="sub-header sh-recon">🔎 T1595 — Active Scanning</span>',
    unsafe_allow_html=True,
)

c1, c2, c3 = st.columns(3)

with c1:
    st.markdown(card(
        "T1595.001", "Scanning IP Blocks",
        "Adversary scans IP ranges to identify live hosts and open ports. "
        "Scraper IPs and port-scan flagged IPs map here.",
        "scraper flag",
        cnt["T1595.001"], "tc-rc", "tid-rc", "cp-rc",
    ), unsafe_allow_html=True)

with c2:
    st.markdown(card(
        "T1595.002", "Vulnerability Scanning",
        "Adversary scans for known vulnerabilities in exposed services. "
        "Often precedes CVE exploitation — links to KEV database.",
        "scraper flag",
        cnt["T1595.002"], "tc-rc", "tid-rc", "cp-rc",
    ), unsafe_allow_html=True)

with c3:
    st.empty()

st.divider()

st.caption(
    "Source: [MITRE ATT&CK® Enterprise Matrix](https://attack.mitre.org/) · "
    "Technique descriptions are adapted for network threat intelligence context."
)
