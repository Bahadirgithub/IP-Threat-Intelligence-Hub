"""Hosting detail page for cloud and grey-hosting providers."""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pandas as pd
import requests
import streamlit as st
from dotenv import load_dotenv

from grey_check import get_grey_asns

load_dotenv()

st.set_page_config(page_title="Hosting Detail", layout="wide", page_icon="🖥️")

RESEARCH_SERVICE_URL = os.getenv(
    "PROVIDER_RESEARCH_SERVICE_URL", "http://127.0.0.1:8001"
).rstrip("/")
RESEARCH_TIMEOUT = (5, 150)  # connect timeout, response/read timeout


def _optional_text(value) -> str | None:
    """Convert a value to display text without leaking NaN / pandas NA."""
    try:
        if pd.isna(value):
            return None
    except (TypeError, ValueError):
        pass
    text = str(value).strip()
    return text or None

st.title("🖥️ Hosting Detail")
st.page_link("app.py", label="← Home Page")
st.divider()


# The main page populates these tables when the data pipeline is run.
if "all_ips" not in st.session_state:
    st.info(
        "No fetched data in this session yet. Go to the Home page and click "
        "**Fetch & Process Data** to populate the tables."
    )
    st.stop()


# ── 1. MAINSTREAM CLOUD PROVIDERS ─────────────────────────────────────────────
df_cloud = st.session_state.get("cloud_ips", pd.DataFrame())
st.subheader(f"☁️ Mainstream Cloud Provider IPs ({len(df_cloud):,})")

if df_cloud.empty:
    st.info("No cloud provider IPs in the current fetch.")
else:
    cloud_cols = [
        "ipAddress", "provider", "asn", "hostname", "organisation", "city", "type",
        "proxy", "vpn", "tor", "hosting", "compromised", "scraper", "anonymous",
        "operator_name", "operator_url", "operator_anonymity",
    ]
    st.dataframe(
        df_cloud[[c for c in cloud_cols if c in df_cloud.columns]],
        use_container_width=True,
        hide_index=True,
    )

st.divider()


# ── 2. GREY HOSTING / PROVIDER SELECTION ───────────────────────────────────────
df_grey = st.session_state.get("grey_ips", pd.DataFrame()).copy()
st.subheader(f"🖥️ Grey Hosting Providers ({len(df_grey):,} IPs)")

if df_grey.empty:
    st.info("No grey-hosting IPs in the current fetch.")
else:
    provider_table = get_grey_asns(df_grey)

    if provider_table.empty:
        st.warning("Grey-hosting IPs were found, but no valid ASN could be extracted.")
    else:
        research_history = st.session_state.setdefault("provider_research_results", {})
        display_rows: list[dict] = []

        for _, provider_row in provider_table.iterrows():
            asn_number = int(provider_row["asn_int"])
            asn_key = str(asn_number)
            saved_entry = research_history.get(asn_key, {})
            full_result = saved_entry.get("result", {})
            verdict_data = full_result.get("verdict", {})
            if not isinstance(verdict_data, dict):
                verdict_data = {}

            score = verdict_data.get("risk_score")
            organisation = _optional_text(provider_row.get("organisation"))
            try:
                score_display = f"{float(score):.1f}/10" if score is not None else "Not researched"
            except (TypeError, ValueError):
                score_display = "Not researched"

            display_rows.append(
                {
                    "ASN": f"AS{asn_number}",
                    "Organisation": organisation or "Unknown",
                    "Grey-hosting IPs": int(provider_row["ip_count"]),
                    "Risk score": score_display,
                    "Verdict": verdict_data.get("verdict") or "Not researched",
                }
            )

        df_display = pd.DataFrame(display_rows)
        st.caption(
            f"{len(provider_table):,} unique ASNs found. Select a provider row, "
            "then click **Research** to run the ASN research microservice."
        )

        # Row selection is supported by current Streamlit releases.
        try:
            table_event = st.dataframe(
                df_display,
                use_container_width=True,
                hide_index=True,
                on_select="rerun",
                selection_mode="single-row",
                key="grey_asn_provider_table",
                column_config={
                    "ASN": st.column_config.TextColumn("ASN", width="small"),
                    "Organisation": st.column_config.TextColumn("Organisation", width="large"),
                    "Grey-hosting IPs": st.column_config.NumberColumn("Grey-hosting IPs", format="%d"),
                    "Risk score": st.column_config.TextColumn("Risk score"),
                    "Verdict": st.column_config.TextColumn("Verdict"),
                },
            )
            selected_rows = table_event.selection.rows
        except TypeError:
            # Older Streamlit versions do not support dataframe row selection.
            st.warning(
                "Your Streamlit version does not support selecting table rows. "
                "Upgrade with `pip install --upgrade streamlit` to enable row-click selection."
            )
            st.dataframe(df_display, use_container_width=True, hide_index=True)
            selected_asn_option = st.selectbox(
                "Select a provider ASN:",
                options=[row["ASN"] for row in display_rows],
                key="grey_asn_fallback_select",
            )
            selected_rows = [
                next(i for i, row in enumerate(display_rows) if row["ASN"] == selected_asn_option)
            ]

        if selected_rows:
            selected_index = selected_rows[0]
            selected_provider = provider_table.iloc[selected_index]
            selected_asn = int(selected_provider["asn_int"])
            selected_org = _optional_text(selected_provider.get("organisation"))
            ip_count = int(selected_provider["ip_count"])

            st.info(
                f"Selected provider: **AS{selected_asn}** · "
                f"Organisation: **{selected_org or 'Unknown'}** · "
                f"Grey-hosting IPs: **{ip_count:,}**"
            )

            # RPKI must be checked only for the prefix containing one concrete
            # AbuseIPDB IP associated with this ASN. This reuses the existing
            # POST /research endpoint; no new external API is introduced.
            if "asn_int" in df_grey.columns:
                ip_rows = df_grey[df_grey["asn_int"] == selected_asn].copy()
            else:
                ip_rows = df_grey[
                    df_grey["asn"].astype(str).str.upper().str.replace("AS", "", regex=False).str.strip()
                    == str(selected_asn)
                    ].copy()

            if ip_rows.empty or "ipAddress" not in ip_rows.columns:
                st.warning("No AbuseIPDB IP is available for this ASN, so target-prefix RPKI cannot be checked.")
                selected_abused_ip = None
            else:
                ip_rows["ipAddress"] = ip_rows["ipAddress"].astype(str)
                if "totalReports" in ip_rows.columns:
                    ip_rows = ip_rows.sort_values("totalReports", ascending=False, na_position="last")
                ip_options = ip_rows["ipAddress"].dropna().drop_duplicates().tolist()
                report_lookup = {}
                if "totalReports" in ip_rows.columns:
                    report_lookup = {
                        str(row["ipAddress"]): row.get("totalReports")
                        for _, row in ip_rows.iterrows()
                    }
                selected_abused_ip = st.selectbox(
                    "Abuse IP for the RPKI check:",
                    options=ip_options,
                    format_func=lambda ip: (
                        f"{ip} · {report_lookup.get(ip)} reports"
                        if report_lookup.get(ip) is not None and pd.notna(report_lookup.get(ip))
                        else ip
                    ),
                    key=f"target_abuse_ip_{selected_asn}",
                    help="Only the RIPE RPKI result for the prefix containing this selected IP will be checked.",
                )

            if st.button(
                    f"🔍 Research AS{selected_asn}",
                    type="primary",
                    key="research_selected_provider",
            ):
                try:
                    with st.spinner(
                            f"Researching AS{selected_asn}… The microservice is collecting data and evaluating the provider."
                    ):
                        if not selected_abused_ip:
                            st.error("Select an AbuseIPDB IP before starting target-prefix RPKI research.")
                            st.stop()
                        response = requests.post(
                            f"{RESEARCH_SERVICE_URL}/research",
                            json={"asn": str(selected_asn), "ip": selected_abused_ip},
                            timeout=RESEARCH_TIMEOUT,
                        )
                        response.raise_for_status()
                        result = response.json()
                        if not isinstance(result, dict):
                            raise ValueError("The research service returned an unexpected response format.")

                    research_history[str(selected_asn)] = {
                        "asn": str(selected_asn),
                        "ip": selected_abused_ip,
                        "organisation": selected_org,
                        "ip_count": ip_count,
                        "result": result,
                        "researched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    }
                    st.session_state["provider_research_results"] = research_history
                    st.session_state["active_provider_research_asn"] = str(selected_asn)
                    st.switch_page("pages/provider_research.py")

                except requests.exceptions.HTTPError as exc:
                    response_text = ""
                    if exc.response is not None:
                        response_text = exc.response.text[:1000]
                    st.error(
                        f"Research service returned an HTTP error: {exc}. "
                        f"{response_text}"
                    )
                except requests.exceptions.RequestException as exc:
                    st.error(
                        "Could not reach the research microservice at "
                        f"`{RESEARCH_SERVICE_URL}`. Make sure it is running with "
                        "`uvicorn microservice:app --host 0.0.0.0 --port 8001`. "
                        f"Details: {exc}"
                    )
                except (ValueError, TypeError) as exc:
                    st.error(f"Could not read the research response: {exc}")

    with st.expander("Show grey-hosting IP details"):
        detail_cols = [
            "ipAddress", "provider", "asn", "organisation", "country", "city", "hostname",
            "proxy", "vpn", "tor", "totalReports", "numDistinctUsers", "grey_signals",
        ]
        st.dataframe(
            df_grey[[c for c in detail_cols if c in df_grey.columns]],
            use_container_width=True,
            hide_index=True,
            column_config={
                "grey_signals": st.column_config.TextColumn("Signals", width="large"),
            },
        )
