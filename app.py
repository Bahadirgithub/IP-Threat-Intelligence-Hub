"""
app.py
------
ThreatWatch — Main Streamlit Dashboard.
Pipeline: AbuseIPDB -> ProxyCheck -> Whitelist -> ip-api -> Cloud -> CDN -> Bulletproof -> Grey -> Anonymization
"""

import streamlit as st
import pandas as pd

pd.set_option("styler.render.max_elements", 500000)

from ingestion import fetch_blacklist
from enrichment import enrich
from database import (
    save, save_whitelist, save_wireless,
    save_cloud, save_cdn, save_bulletproof, save_grey,
    record_count,
)
from whitelist import check_whitelist
from cross_check import verify_business_ips
from cloud_check import check_cloud_providers, check_cdn_providers, check_bulletproof
from grey_check import check_grey_hosting
from anonymization_check import classify_anonymization

st.set_page_config(page_title="ThreatWatch", layout="wide", page_icon="🛡️")
st.title("🛡️ ThreatWatch — Security Dashboard")



if st.button("Fetch & Process Data"):
    with st.spinner("Running pipeline: AbuseIPDB → ProxyCheck → Whitelist → ip-api → Cloud → CDN → Bulletproof → Grey → Anonymization..."):
        try:
            df_raw = fetch_blacklist()
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

            # Grey hosting — everything that's hosting but not cloud/CDN/bulletproof
            df_grey = check_grey_hosting(df_final, df_cloud, df_cdn, df_bp)

            # Anonymization categories — proxy / VPN / Tor
            white_ip_set = set(df_white["ipAddress"].unique()) if not df_white.empty else set()
            anon = classify_anonymization(df_final, exclude_ips=white_ip_set)

            save(df_final.drop(columns=["_api_corrected"]))
            save_whitelist(df_white)
            save_wireless(df_wireless)
            save_cloud(df_cloud)
            save_cdn(df_cdn)
            save_bulletproof(df_bp)
            save_grey(df_grey)

            st.session_state["all_ips"]          = df_final[~df_final["ipAddress"].isin(white_ip_set)].copy()
            st.session_state["white_ips"]         = df_white
            st.session_state["wireless_ips"]      = df_wireless
            st.session_state["cloud_ips"]         = df_cloud
            st.session_state["cdn_ips"]           = df_cdn
            st.session_state["bp_ips"]            = df_bp
            st.session_state["grey_ips"]          = df_grey
            st.session_state["wl_cnt"]            = wl_cnt
            st.session_state["tor_ips"]           = anon["tor"]
            st.session_state["residential_proxy"] = anon["residential_proxy"]
            st.session_state["public_proxy"]      = anon["public_proxy"]
            st.session_state["selfhosted_proxy"]  = anon["selfhosted_proxy"]
            st.session_state["commercial_vpn"]    = anon["commercial_vpn"]
            st.session_state["private_vpn"]       = anon["private_vpn"]

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
        st.session_state["all_ips"],
        column_order=main_cols,
        use_container_width=True,
        hide_index=True,
    )
    st.markdown(
        '<hr style="border:none; border-top:2px solid #e74c3c; margin:6px 0 18px 0;">',
        unsafe_allow_html=True,
    )


# ── WIRELESS TABLE ────────────────────────────────────────────────────────────
if "wireless_ips" in st.session_state:
    df_wl = st.session_state["wireless_ips"]
    st.subheader(f"📡 Wireless IPs ({len(df_wl):,})")
    WIRELESS_COLS = [
        "ipAddress", "provider", "organisation", "asn", "type",
        "proxy", "vpn", "anonymous", "tor", "operator_name",
    ]
    st.dataframe(
        df_wl[[c for c in WIRELESS_COLS if c in df_wl.columns]],
        use_container_width=True,
        hide_index=True,
    )
    st.divider()


# ── HOSTING SUMMARY ───────────────────────────────────────────────────────────
if "grey_ips" in st.session_state and not st.session_state["grey_ips"].empty:
    df_grey = st.session_state["grey_ips"]

    col1, col2 = st.columns([6, 1])
    with col1:
        st.subheader(f"🖥️ Hosting IPs ({len(df_grey):,})")
    with col2:
        st.page_link("pages/hosting.py", label="🔍 Clicken →")

    if "grey_sub_tier" in df_grey.columns:
        dist = df_grey["grey_sub_tier"].value_counts().to_dict()
        st.caption(
            "📊 Distribution → "
            f"❓ unknown: {dist.get('unknown', 0):,}  |  "
            f"🔴 high: {dist.get('grey_high', 0):,}  |  "
            f"🟡 mid: {dist.get('grey_mid', 0):,}  |  "
            f"🟢 low: {dist.get('grey_low', 0):,}    "
            "→ Open the Hosting detail page to see the full breakdown."
        )
    else:
        unique_asns = (
            int(df_grey["asn_int"].nunique())
            if "asn_int" in df_grey.columns
            else (int(df_grey["asn"].nunique()) if "asn" in df_grey.columns else 0)
        )
        st.caption(
            f"📊 {len(df_grey):,} Grey Hosting IPs across {unique_asns:,} ASNs. "
            "Provider research runs on demand from the Hosting detail page."
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
    st.divider()


# ── TOR EXIT NODES ────────────────────────────────────────────────────────────
if "tor_ips" in st.session_state and not st.session_state["tor_ips"].empty:
    df_tor = st.session_state["tor_ips"]
    st.subheader(f"🧅 Tor Exit Nodes ({len(df_tor):,})")
    TOR_COLS = [
        "ipAddress", "abuseConfidenceScore", "totalReports",
        "asn", "provider", "organisation", "country", "city", "type",
        "tor", "anonymous", "operator_name",
    ]
    st.dataframe(
        df_tor[[c for c in TOR_COLS if c in df_tor.columns]],
        use_container_width=True,
        hide_index=True,
    )
    st.divider()


# ── RESIDENTIAL PROXIES ───────────────────────────────────────────────────────
if "residential_proxy" in st.session_state and not st.session_state["residential_proxy"].empty:
    df_rp = st.session_state["residential_proxy"]
    st.subheader(f"🏠 Residential Proxies ({len(df_rp):,})")
    RP_COLS = [
        "ipAddress", "abuseConfidenceScore", "totalReports",
        "asn", "provider", "organisation", "country", "city", "type",
        "proxy", "anonymous", "operator_name", "operator_url", "operator_anonymity",
    ]
    st.dataframe(
        df_rp[[c for c in RP_COLS if c in df_rp.columns]],
        use_container_width=True,
        hide_index=True,
    )
    st.divider()


# ── PUBLIC PROXIES ────────────────────────────────────────────────────────────
if "public_proxy" in st.session_state and not st.session_state["public_proxy"].empty:
    df_pp = st.session_state["public_proxy"]
    st.subheader(f"🌐 Public Proxies ({len(df_pp):,})")
    PP_COLS = [
        "ipAddress", "abuseConfidenceScore", "totalReports",
        "asn", "provider", "organisation", "country", "city", "type",
        "proxy", "anonymous", "operator_name", "operator_url", "operator_anonymity",
    ]
    st.dataframe(
        df_pp[[c for c in PP_COLS if c in df_pp.columns]],
        use_container_width=True,
        hide_index=True,
    )
    st.divider()


# ── SELF-HOSTED PROXIES ───────────────────────────────────────────────────────
if "selfhosted_proxy" in st.session_state and not st.session_state["selfhosted_proxy"].empty:
    df_sp = st.session_state["selfhosted_proxy"]
    st.subheader(f"🖥️ Self-hosted Proxies ({len(df_sp):,})")
    SP_COLS = [
        "ipAddress", "abuseConfidenceScore", "totalReports",
        "asn", "provider", "organisation", "country", "city", "type",
        "proxy", "anonymous", "operator_name", "operator_url", "operator_anonymity",
    ]
    st.dataframe(
        df_sp[[c for c in SP_COLS if c in df_sp.columns]],
        use_container_width=True,
        hide_index=True,
    )
    st.divider()


# ── COMMERCIAL VPNs ───────────────────────────────────────────────────────────
if "commercial_vpn" in st.session_state and not st.session_state["commercial_vpn"].empty:
    df_cv = st.session_state["commercial_vpn"]
    st.subheader(f"🔒 Commercial VPNs ({len(df_cv):,})")
    CV_COLS = [
        "ipAddress", "abuseConfidenceScore", "totalReports",
        "asn", "provider", "organisation", "country", "city", "type",
        "vpn", "anonymous", "operator_name", "operator_url",
        "operator_anonymity", "operator_services",
    ]
    st.dataframe(
        df_cv[[c for c in CV_COLS if c in df_cv.columns]],
        use_container_width=True,
        hide_index=True,
    )
    st.divider()


# ── PRIVATE VPNs ──────────────────────────────────────────────────────────────
if "private_vpn" in st.session_state and not st.session_state["private_vpn"].empty:
    df_pv = st.session_state["private_vpn"]
    st.subheader(f"🔐 Private VPNs ({len(df_pv):,})")
    PV_COLS = [
        "ipAddress", "abuseConfidenceScore", "totalReports",
        "asn", "provider", "organisation", "country", "city", "type",
        "vpn", "anonymous", "operator_name", "operator_url", "operator_anonymity",
    ]
    st.dataframe(
        df_pv[[c for c in PV_COLS if c in df_pv.columns]],
        use_container_width=True,
        hide_index=True,
    )