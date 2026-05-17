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
from database import save, save_whitelist, record_count
from whitelist import check_whitelist
from cross_check import verify_business_ips

st.set_page_config(page_title="ThreatWatch", layout="wide", page_icon="🛡️")
st.title("🛡️ ThreatWatch — Security Dashboard")


def highlight_corrected_type(data):
    """Highlights 'type' cell orange if corrected by ip-api."""
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

            df_white, asn_cnt, gn_cnt = check_whitelist(df_enriched)
            df_final = verify_business_ips(df_enriched, df_white)

            save(df_final.drop(columns=["_api_corrected"]))
            save_whitelist(df_white)

            st.session_state["all_ips"]   = df_final
            st.session_state["white_ips"] = df_white
            st.session_state["counts"]    = {"asn": asn_cnt, "gn": gn_cnt}

            st.success(f"Done! Total records in DB: {record_count():,}")

        except Exception as e:
            st.error(f"Error: {e}")


if "all_ips" in st.session_state:
    st.subheader("⚠️ Latest Malicious Detections")
    st.dataframe(
        st.session_state["all_ips"].style.apply(highlight_corrected_type, axis=None),
        column_order=[c for c in st.session_state["all_ips"].columns if c != "_api_corrected"],
        use_container_width=True,
        hide_index=True,
    )

    st.divider()

if "white_ips" in st.session_state:
    st.subheader("✅ Whitelist Analysis")

    counts = st.session_state.get("counts", {"asn": 0, "gn": 0})
    m1, m2 = st.columns(2)
    m1.metric("Whitelist Matches", counts["asn"])
    m2.metric("Total Trusted IPs", counts["asn"])

    df_w = st.session_state["white_ips"]
    if not df_w.empty:
        WHITELIST_COLS = ["ipAddress", "asn", "provider", "organisation", "country", "abuseConfidenceScore"]
        st.dataframe(
            df_w[[c for c in WHITELIST_COLS if c in df_w.columns]],
            use_container_width=True,
            hide_index=True,
        )