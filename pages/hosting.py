"""
pages/hosting.py
----------------
Hosting detail page.
Shows: Mainstream Cloud Provider IPs (and more tables to come).
"""

import streamlit as st
import pandas as pd
from database import load_cloud

st.set_page_config(page_title="Hosting Detail", layout="wide", page_icon="🖥️")

st.title("🖥️ Hosting Detail")
st.page_link("app.py", label="← Home Page")
st.divider()

# ── MAINSTREAM CLOUD PROVIDERS ────────────────────────────────────────────────
df_cloud = load_cloud()

st.subheader(f"☁️ Mainstream Cloud Provider IPs ({len(df_cloud):,})")

if df_cloud.empty:
    st.info("No cloud provider data yet. Fetch data from the main page.")
else:
    CLOUD_COLS = [
        "ipAddress", "provider", "asn", "hostname", "organisation", "city", "type",
        "proxy", "vpn", "tor", "hosting", "compromised", "scraper", "anonymous",
        "operator_name", "operator_url", "operator_anonymity", "detected_at",
    ]
    st.dataframe(
        df_cloud[[c for c in CLOUD_COLS if c in df_cloud.columns]],
        use_container_width=True,
        hide_index=True,
    )

st.divider()


