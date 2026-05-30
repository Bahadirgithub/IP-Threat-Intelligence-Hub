"""
pages/hosting.py
----------------
Hosting detail page.
Shows:
  - Mainstream Cloud Provider IPs  (current session only)
  - Grey Hosting IPs               (current session only — with score or 'unknown')

Both tables read from st.session_state populated by the main page's
'Fetch & Process Data' button. They do NOT load from the database on page open.
"""

import streamlit as st
import pandas as pd

st.set_page_config(page_title="Hosting Detail", layout="wide", page_icon="🖥️")

st.title("🖥️ Hosting Detail")
st.page_link("app.py", label="← Home Page")
st.divider()


# Pre-flight: require a current-session fetch
if "all_ips" not in st.session_state:
    st.info("ℹ️ No fetched data in this session yet. Go to the Home page and click "
            "**Fetch & Process Data** to populate the tables.")
    st.stop()


# ── 1. MAINSTREAM CLOUD PROVIDERS ─────────────────────────────────────────────
df_cloud = st.session_state.get("cloud_ips", pd.DataFrame())

st.subheader(f"☁️ Mainstream Cloud Provider IPs ({len(df_cloud):,})")

if df_cloud.empty:
    st.info("No cloud provider IPs in the current fetch.")
else:
    CLOUD_COLS = [
        "ipAddress", "provider", "asn", "hostname", "organisation", "city", "type",
        "proxy", "vpn", "tor", "hosting", "compromised", "scraper", "anonymous",
        "operator_name", "operator_url", "operator_anonymity",
    ]
    st.dataframe(
        df_cloud[[c for c in CLOUD_COLS if c in df_cloud.columns]],
        use_container_width=True,
        hide_index=True,
    )

st.divider()


# ── 2. GREY HOSTING ───────────────────────────────────────────────────────────
df_grey = st.session_state.get("grey_ips", pd.DataFrame()).copy()

if df_grey.empty:
    st.info("No grey-hosting IPs in the current fetch.")
else:
    # Build display column for score
    def _score_display(row):
        s = row.get("grey_score")
        t = row.get("grey_sub_tier")
        if pd.isna(s) or s is None or t == "unknown":
            return "❓ Research needed"
        emoji = {"grey_high": "🔴", "grey_mid": "🟡", "grey_low": "🟢"}.get(t, "")
        return f"{emoji} {float(s):.1f}"

    df_grey["score_display"] = df_grey.apply(_score_display, axis=1)

    col1, col2, col3 = st.columns([4, 2, 1])
    with col1:
        st.subheader(f"🖥️ Grey Hosting IPs ({len(df_grey):,})")
    with col2:
        tier_filter = st.selectbox(
            "Sub-tier filter:",
            ["all", "unknown", "grey_high", "grey_mid", "grey_low"],
            label_visibility="collapsed",
        )
    with col3:
        st.page_link("pages/provider_research.py", label="🔍 Research →")

    df_view = df_grey if tier_filter == "all" else df_grey[df_grey["grey_sub_tier"] == tier_filter]

    # Distribution
    dist = df_grey["grey_sub_tier"].value_counts().to_dict()
    st.caption(
        f"📊 Distribution → "
        f"❓ unknown: {dist.get('unknown', 0):,}  |  "
        f"🔴 high: {dist.get('grey_high', 0):,}  |  "
        f"🟡 mid: {dist.get('grey_mid', 0):,}  |  "
        f"🟢 low: {dist.get('grey_low', 0):,}    "
        f"→ Use the **🔍 Research** page to score unknown ASNs."
    )

    GREY_COLS = [
        "ipAddress", "score_display", "provider", "asn",
        "organisation", "country", "city", "hostname",
        "proxy", "vpn", "tor",
        "totalReports", "numDistinctUsers",
        "grey_signals",
    ]
    st.dataframe(
        df_view[[c for c in GREY_COLS if c in df_view.columns]],
        use_container_width=True,
        hide_index=True,
        column_config={
            "score_display": st.column_config.TextColumn(
                "Score",
                help="ASNs not yet researched show '❓ Research needed'. "
                     "Go to the Provider Research page to score them.",
                width="medium",
            ),
            "grey_signals": st.column_config.TextColumn("Signals", width="large"),
        },
    )

