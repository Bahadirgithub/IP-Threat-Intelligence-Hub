"""
app.py
------
ThreatWatch — Main Streamlit Dashboard.
Pipeline: AbuseIPDB -> ProxyCheck -> Whitelist -> ip-api -> Cloud -> CDN -> Bulletproof -> Grey
"""

import streamlit as st
import pandas as pd

pd.set_option("styler.render.max_elements", 500000)

from ingestion import fetch_blacklist
from enrichment import enrich
from database import (
    save, save_whitelist, save_wireless,
    save_cloud, save_cdn, save_bulletproof, save_grey,
    record_count
)
from whitelist import check_whitelist
from cross_check import verify_business_ips
from cloud_check import check_cloud_providers, check_cdn_providers, check_bulletproof
from grey_check import check_grey_hosting

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
    with st.spinner("Running pipeline: AbuseIPDB → ProxyCheck → Whitelist → ip-api → Cloud → CDN → Bulletproof → Grey..."):
        try:
            df_raw      = fetch_blacklist()
            df_enriched = enrich(df_raw)

            df_white, wl_cnt, _ = check_whitelist(df_enriched)
            df_final = verify_business_ips(df_enriched, df_white)

            # Wireless extraction — after cross_check so types are corrected
            df_wireless = df_final[
                df_final["type"].fillna("").str.lower() == "wireless"
                ].copy()

            # Cloud, CDN, Bulletproof extraction
            df_cloud = check_cloud_providers(df_final)
            df_cdn   = check_cdn_providers(df_final)
            df_bp    = check_bulletproof(df_final)

            # Grey hosting — everything that's hosting but not cloud/cdn/bp
            df_grey  = check_grey_hosting(df_final, df_cloud, df_cdn, df_bp)

            save(df_final.drop(columns=["_api_corrected"]))
            save_whitelist(df_white)
            save_wireless(df_wireless)
            save_cloud(df_cloud)
            save_cdn(df_cdn)
            save_bulletproof(df_bp)
            save_grey(df_grey)

            white_ip_set = set(df_white["ipAddress"].unique()) if not df_white.empty else set()
            st.session_state["all_ips"]      = df_final[~df_final["ipAddress"].isin(white_ip_set)].copy()
            st.session_state["white_ips"]    = df_white
            st.session_state["wireless_ips"] = df_wireless
            st.session_state["cloud_ips"]    = df_cloud
            st.session_state["cdn_ips"]      = df_cdn
            st.session_state["bp_ips"]       = df_bp
            st.session_state["grey_ips"]     = df_grey
            st.session_state["wl_cnt"]       = wl_cnt

            st.success(f"Done! Total records in DB: {record_count():,}")

        except Exception as e:
            st.error(f"Error: {e}")


# ── MAIN TABLE ────────────────────────────────────────────────────────────────
if "all_ips" in st.session_state:
    st.subheader("⚠️ Latest Malicious Detections")

    EXCLUDE_COLS = {
        "_api_corrected",
        "proxy", "compromised", "vpn", "scraper", "tor", "hosting", "anonymous",
        "operator_name", "operator_url", "operator_anonymity", "operator_popularity",
        "operator_services", "operator_protocols", "operator_additional",
    }

    main_cols = [c for c in st.session_state["all_ips"].columns if c not in EXCLUDE_COLS]

    st.dataframe(
        st.session_state["all_ips"].style.apply(highlight_corrected_type, axis=None),
        column_order=main_cols,
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


# ── HOSTING SUMMARY (link to detail page) ─────────────────────────────────────
if "grey_ips" in st.session_state and not st.session_state["grey_ips"].empty:
    df_grey = st.session_state["grey_ips"]

    col1, col2 = st.columns([6, 1])
    with col1:
        st.subheader(f"🖥️ Hosting IPs ({len(df_grey):,})")
    with col2:
        st.page_link("pages/hosting.py", label="🔍 Clicken →")

    dist = df_grey["grey_sub_tier"].value_counts().to_dict()
    st.caption(
        f"📊 Distribution → "
        f"❓ unknown: {dist.get('unknown', 0):,}  |  "
        f"🔴 high: {dist.get('grey_high', 0):,}  |  "
        f"🟡 mid: {dist.get('grey_mid', 0):,}  |  "
        f"🟢 low: {dist.get('grey_low', 0):,}    "
        f"→ Open the Hosting detail page to see the full breakdown."
    )
    st.divider()


# ── CDN EDGE TABLE ────────────────────────────────────────────────────────────
if "cdn_ips" in st.session_state:
    df_cdn = st.session_state["cdn_ips"]
    st.subheader(f"🌐 CDN Edge IPs ({len(df_cdn):,})")
    CDN_COLS = [
        "ipAddress", "provider", "asn", "hostname", "organisation", "city", "type",
        "proxy", "vpn", "tor", "hosting", "compromised", "scraper", "anonymous",
        "operator_name", "operator_url", "operator_anonymity",
    ]
    st.dataframe(
        df_cdn[[c for c in CDN_COLS if c in df_cdn.columns]],
        use_container_width=True,
        hide_index=True,
    )
    st.divider()


# ── BULLETPROOF HOSTING TABLE ─────────────────────────────────────────────────
if "bp_ips" in st.session_state:
    df_bp = st.session_state["bp_ips"]
    st.subheader(f"🚨 Bulletproof Hosting IPs ({len(df_bp):,})")
    BP_COLS = [
        "ipAddress", "provider", "asn", "hostname", "organisation", "city", "type",
        "proxy", "vpn", "tor", "operator_name", "operator_url", "operator_anonymity",
    ]
    st.dataframe(
        df_bp[[c for c in BP_COLS if c in df_bp.columns]],
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