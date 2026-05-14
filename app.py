import streamlit as st
from ingestion import fetch_blacklist
from enrichment import enrich
from database import save, save_whitelist, record_count, load_whitelist
from whitelist import check_whitelist

st.set_page_config(page_title="ThreatWatch", page_icon="🛡️", layout="wide")

st.title("🛡️ ThreatWatch — Malicious IPs (Score 100, Last 24h)")

if st.button("Fetch Data"):
    with st.spinner("Fetching from AbuseIPDB and ProxyCheckio..."):
        try:
            df = fetch_blacklist()
            df = enrich(df)
            save(df)

            # Whitelist logic
            df_white = check_whitelist(df)
            save_whitelist(df_white)

            st.session_state["df"] = df
            st.session_state["df_white"] = df_white
            st.success(f"{len(df):,} IPs fetched and saved — Total in DB: {record_count():,}")
        except Exception as e:
            st.error(f"Error: {e}")

if "df" in st.session_state:
    st.subheader("⚠️ All Detected IPs")
    st.data_editor(st.session_state["df"], use_container_width=True, hide_index=True, disabled=True)

    st.divider()

    # Whitelist Table Display
    df_w = st.session_state.get("df_white", load_whitelist())
    if not df_w.empty:
        st.subheader(f"✅ Trusted Scanners ({len(df_w)} matches)")
        st.dataframe(df_w[["ipAddress", "asn", "provider", "organisation"]], use_container_width=True, hide_index=True)