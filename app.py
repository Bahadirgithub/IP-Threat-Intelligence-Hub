"""
app.py
------
ThreatWatch — Main Streamlit Dashboard.
Pipeline: AbuseIPDB -> ProxyCheck -> Whitelist -> ip-api Cross-Check
"""

import streamlit as st
import pandas as pd

pd.set_option("styler.render.max_elements", 500000)

from ingestion import fetch_blacklist
from enrichment import enrich
from database import save, save_whitelist, save_wireless, record_count
from whitelist import check_whitelist
from cross_check import verify_business_ips

st.set_page_config(page_title="ThreatWatch", layout="wide", page_icon="🛡️")
st.title("🛡️ ThreatWatch — Security Dashboard")


def highlight_corrected_type(data):
    """Highlights 'type' cell orange if corrected by ipapi.is."""
    styles = pd.DataFrame('', index=data.index, columns=data.columns)
    if '_api_corrected' in data.columns:
        mask = data['_api_corrected'] == True
        styles.loc[mask, 'type'] = 'background-color: #FFA500; color: white; font-weight: bold;'
    return styles


if st.button("Fetch & Process Data"):
    with st.spinner("Running pipeline: AbuseIPDB → ProxyCheck → Whitelist → ip-api..."):
        try:
            df_raw      = fetch_blacklist()
            df_enriched = enrich(df_raw)

            df_white, wl_cnt, _ = check_whitelist(df_enriched)
            df_final = verify_business_ips(df_enriched, df_white)

            # Wireless extraction — after cross_check so types are corrected
            df_wireless = df_final[
                df_final["type"].fillna("").str.lower() == "wireless"
                ].copy()

            save(df_final.drop(columns=["_api_corrected"]))
            save_whitelist(df_white)
            save_wireless(df_wireless)

            white_ip_set = set(df_white["ipAddress"].unique()) if not df_white.empty else set()
            st.session_state["all_ips"] = df_final[~df_final["ipAddress"].isin(white_ip_set)].copy()
            st.session_state["white_ips"]   = df_white
            st.session_state["wireless_ips"] = df_wireless
            st.session_state["wl_cnt"]      = wl_cnt

            st.success(f"Done! Total records in DB: {record_count():,}")

        except Exception as e:
            st.error(f"Error: {e}")


# ── MAIN TABLE ────────────────────────────────────────────────────────────────
if "all_ips" in st.session_state:
    st.subheader("⚠️ Latest Malicious Detections")
    st.dataframe(
        st.session_state["all_ips"].style.apply(highlight_corrected_type, axis=None),
        column_order=[c for c in st.session_state["all_ips"].columns if c != "_api_corrected"],
        use_container_width=True,
        hide_index=True,
    )
    st.divider()

# ── WIRELESS TABLE ────────────────────────────────────────────────────────────
if "wireless_ips" in st.session_state:
    df_wl = st.session_state["wireless_ips"]
    st.subheader(f"📡 Wireless IPs ({len(df_wl):,})")
    WIRELESS_COLS = [
        "ipAddress", "provider", "organisation", "asn", "type",
        "proxy", "vpn", "anonymous", "tor", "operator_name"
    ]
    st.dataframe(
        df_wl[[c for c in WIRELESS_COLS if c in df_wl.columns]],
        use_container_width=True,
        hide_index=True,
    )
    st.divider()

# ── WHITELIST TABLE ───────────────────────────────────────────────────────────
if "white_ips" in st.session_state:
    df_w = st.session_state["white_ips"]
    st.subheader(f"✅ Trusted Scanners ({st.session_state.get('wl_cnt', 0):,})")
    WHITELIST_COLS = ["ipAddress", "asn", "provider", "organisation", "country", "abuseConfidenceScore"]
    st.dataframe(
        df_w[[c for c in WHITELIST_COLS if c in df_w.columns]],
        use_container_width=True,
        hide_index=True,
    )