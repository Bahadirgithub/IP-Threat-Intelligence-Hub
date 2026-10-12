"""Provider Research page for raw-source grouped results."""
from __future__ import annotations

import json
import streamlit as st

st.set_page_config(page_title="Provider Research", layout="wide", page_icon="🔍")
st.title("🔍 Provider Research")
st.page_link("pages/hosting.py", label="← Back to Hosting Detail")
st.divider()

history = st.session_state.get("provider_research_results", {})
if not history:
    st.info(
        "No research result in this session yet. Open Hosting Detail, select a Grey Hosting provider, "
        "and click Research."
    )
    st.stop()

active_asn = st.session_state.get("active_provider_research_asn")
ordered_asns = sorted(
    history.keys(),
    key=lambda item: history[item].get("researched_at", ""),
    reverse=True,
)
selected_asn = st.selectbox(
    "Research history — select a provider:",
    options=ordered_asns,
    index=ordered_asns.index(active_asn) if active_asn in ordered_asns else 0,
    format_func=lambda item: f"AS{item} · {history[item].get('organisation') or 'Unknown organisation'}",
)
st.session_state["active_provider_research_asn"] = selected_asn

entry = history[selected_asn]
result = entry.get("result", {}) or {}
verdict_data = result.get("verdict", {}) or {}
if not isinstance(verdict_data, dict):
    verdict_data = {}

st.header(f"Provider Research — AS{selected_asn}")
st.caption(f"Research timestamp (UTC): {entry.get('researched_at', 'Unknown')}")
abused_ip = entry.get("ip") or result.get("abused_ip")
if abused_ip:
    st.write(f"**Abuse IP researched:** `{abused_ip}`")

network = result.get("network", {}) or {}
target = network.get("abused_ip_prefix", {}) if isinstance(network, dict) else {}
if isinstance(target, dict) and target.get("prefix"):
    st.write(f"**RPKI prefix queried:** `{target['prefix']}`")

score = verdict_data.get("risk_score")
verdict = verdict_data.get("verdict", "unknown")
col1, col2 = st.columns(2)
col1.metric("Risk score", f"{score}/10" if score is not None else "N/A")
col2.metric("Verdict", str(verdict).replace("_", " ").title())

if verdict_data.get("summary"):
    st.subheader("LLM Assessment")
    st.write(verdict_data["summary"])
elif verdict_data.get("error"):
    st.error(f"The model evaluation failed: {verdict_data['error']}")

left, right = st.columns(2)
with left:
    st.subheader("Risk factors")
    for item in verdict_data.get("risk_factors") or []:
        st.markdown(f"- {item}")
    if not verdict_data.get("risk_factors"):
        st.caption("No risk factors returned.")
with right:
    st.subheader("Positive factors")
    for item in verdict_data.get("positive_factors") or []:
        st.markdown(f"- {item}")
    if not verdict_data.get("positive_factors"):
        st.caption("No positive factors returned.")

rpki = verdict_data.get("rpki_prefix_assessment") or []
if rpki:
    st.subheader("LLM assessment of target-prefix RPKI")
    st.json(rpki)

st.subheader("Raw source data sent for evaluation")
for key, label in (
        ("identity", "Identity — BGPView, RIPE WHOIS, RDAP"),
        ("abuse", "Abuse contact and raw DNS queries"),
        ("network", "Routing, announced prefixes, target RPKI, PTR"),
        ("website", "Website candidates and fetched response"),
):
    with st.expander(label):
        st.code(json.dumps(result.get(key, {}), indent=2, ensure_ascii=False), language="json")

with st.expander("Complete microservice response (JSON)"):
    st.code(json.dumps(result, indent=2, ensure_ascii=False), language="json")