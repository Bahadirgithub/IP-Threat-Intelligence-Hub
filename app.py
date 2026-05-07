"""
app.py
------
Streamlit dashboard.
Fetches data via ingestion.py + enrichment.py, saves to database.py.
"""

import streamlit as st
from ingestion import fetch_blacklist
from enrichment import enrich
from database import save, record_count

st.set_page_config(page_title="ThreatWatch", page_icon="🛡️", layout="wide")

st.title("🛡️ ThreatWatch — Malicious IPs (Score 100, Last 24h)")

if st.button("Fetch Data"):
    with st.spinner("Fetching from AbuseIPDB and ProxyCheckio"):
        try:
            df = fetch_blacklist()
            df = enrich(df)
            save(df)
            st.session_state["df"] = df
            st.success(f"{len(df):,} IPs fetched and saved — Total in DB: {record_count():,}")
        except Exception as e:
            st.error(f"Error: {e}")

if "df" in st.session_state:
    df = st.session_state["df"]
    st.data_editor(df, use_container_width=True, hide_index=True, disabled=True)