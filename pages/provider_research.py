"""Provider Research page: displays the grouped ASN microservice result."""

from __future__ import annotations

import json
import pandas as pd
import streamlit as st

st.set_page_config(page_title="Provider Research", layout="wide", page_icon="🔍")

st.title("🔍 Provider Research")
st.page_link("pages/hosting.py", label="← Back to Hosting Detail")
st.divider()

research_history = st.session_state.get("provider_research_results", {})
if not research_history:
    st.info(
        "No provider research results in this session yet. Open Hosting Detail, "
        "select a Grey Hosting provider, and click **Research**."
    )
    st.stop()

active_asn = st.session_state.get("active_provider_research_asn")
ordered_asns = sorted(
    research_history.keys(),
    key=lambda asn: research_history[asn].get("researched_at", ""),
    reverse=True,
)
selected_asn = st.selectbox(
    "Research history — select a provider:",
    options=ordered_asns,
    index=ordered_asns.index(active_asn) if active_asn in ordered_asns else 0,
    format_func=lambda asn: (
        f"AS{asn} · "
        f"{research_history[asn].get('organisation') or 'Unknown organisation'}"
    ),
)
st.session_state["active_provider_research_asn"] = selected_asn

entry = research_history[selected_asn]
result = entry.get("result", {}) or {}
verdict_data = result.get("verdict", {}) or {}
if not isinstance(verdict_data, dict):
    verdict_data = {}

identity = result.get("identity", {}) or {}
abuse = result.get("abuse", {}) or {}
network = result.get("network", {}) or {}
website = result.get("website", {}) or {}
source_evidence = result.get("source_evidence", {}) or {}

provider_name = identity.get("provider_name") or entry.get("organisation") or "Unknown provider"
country = identity.get("country") or "Unknown"
website_url = website.get("url") or identity.get("website_url")
risk_score = verdict_data.get("risk_score")
verdict = verdict_data.get("verdict") or "unknown"
researched_at = entry.get("researched_at", "Unknown")
abused_ip = entry.get("ip") or result.get("abused_ip")
rpki_prefix = network.get("rpki_target_prefix")

st.header(f"{provider_name} — AS{selected_asn}")
if website_url:
    st.markdown(f"Website: [{website_url}]({website_url})")
st.caption(f"Research timestamp (UTC): {researched_at}")
if abused_ip:
    st.write(f"**Abuse IP researched:** `{abused_ip}`")
if rpki_prefix:
    st.write(f"**RPKI prefix checked:** `{rpki_prefix}`")

metric1, metric2, metric3, metric4 = st.columns(4)
metric1.metric("Risk score", f"{risk_score}/10" if risk_score is not None else "N/A")
metric2.metric("Verdict", str(verdict).replace("_", " ").title())
metric3.metric("Country", country)
age = network.get("asn_age_years")
metric4.metric("ASN age", f"{age} years" if age is not None else "Unknown")

summary = verdict_data.get("summary")
if summary:
    st.subheader("Assessment summary")
    st.write(summary)
elif verdict_data.get("error"):
    st.error(f"The model evaluation failed: {verdict_data['error']}")

left, right = st.columns(2)
with left:
    st.subheader("⚠️ Risk factors")
    for factor in verdict_data.get("risk_factors") or []:
        st.markdown(f"- {factor}")
    if not verdict_data.get("risk_factors"):
        st.caption("No risk factors were returned.")

with right:
    st.subheader("✅ Positive factors")
    for factor in verdict_data.get("positive_factors") or []:
        st.markdown(f"- {factor}")
    if not verdict_data.get("positive_factors"):
        st.caption("No positive factors were returned.")

st.subheader("Technical signals")
signals = {
    "Abuse contact": abuse.get("email"),
    "Abuse contact lookup": abuse.get("contact_status"),
    "Abuse domain resolves": abuse.get("domain_resolves"),
    "Abuse domain DNS status": abuse.get("domain_status"),
    "Abuse MX valid": abuse.get("mx_valid"),
    "Abuse MX lookup status": abuse.get("mx_status"),
    "RPKI target prefix": rpki_prefix,
    "Announced prefix count": network.get("prefix_count"),
    "Prefix churn score": network.get("prefix_churn_score"),
    "Prefix churn status": network.get("prefix_churn_status"),
    "Accepts crypto (website keyword check)": website.get("accepts_crypto"),
    "Crypto check status": website.get("crypto_check_status"),
    "PTR sample": ", ".join(network.get("sample_ptr_records") or []),
}
st.dataframe(
    pd.DataFrame([
        {"Signal": key, "Result": "Unknown / not checked" if value is None else value}
        for key, value in signals.items()
    ]),
    width="stretch",
    hide_index=True,
)

rpki_assessments = verdict_data.get("rpki_prefix_assessment") or []
if rpki_assessments:
    st.subheader("RPKI assessment for the abused IP prefix")
    st.dataframe(pd.DataFrame(rpki_assessments), width="stretch", hide_index=True)
elif abused_ip:
    st.info("No RPKI prefix assessment was returned. Check the source evidence; unrelated prefixes are not sampled.")

with st.expander("Show grouped source evidence (JSON)"):
    st.code(json.dumps(source_evidence, indent=2, ensure_ascii=False), language="json")

with st.expander("Show complete microservice response (JSON)"):
    st.code(json.dumps(result, indent=2, ensure_ascii=False), language="json")
