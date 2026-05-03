"""
app.py
------
Fetches data via ingestion.py and displays it as a table.
"""

import streamlit as st
from ingestion import fetch_blacklist
from enrichment import enrich

st.set_page_config(page_title="ThreatWatch", page_icon="🛡️", layout="wide")

st.title("🛡️ ThreatWatch — Malicious IPs (Score 100, Last 24h)")

if st.button("Fetch Data"):
    with st.spinner("Fetching from AbuseIPDB..."):
        try:
            df = fetch_blacklist()
            df = enrich(df)
            st.session_state["df"] = df
        except Exception as e:
            st.error(f"Error: {e}")

if "df" in st.session_state:
    df = st.session_state["df"]
    st.success(f"{len(df):,} malicious IPs found in the last 24 hours")
    st.data_editor(df, use_container_width=True, hide_index=True, disabled=True)