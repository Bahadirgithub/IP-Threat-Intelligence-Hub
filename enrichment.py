"""
enrichment.py
-------------
Sole responsibility: enrich IPs from ingestion.py
using proxy-check.io API in batches of 100.
"""

import os
import requests
import pandas as pd
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("PROXYCHECK_API_KEY")
BATCH_SIZE = 1000


def enrich(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df

    ips = df["ip"].tolist()
    results = {}

    for i in range(0, len(ips), BATCH_SIZE):
        batch = ips[i:i + BATCH_SIZE]
        batch_results = _query_batch(batch)
        results.update(batch_results)

    enriched_rows = [results.get(ip, {}) for ip in ips]
    enriched_df = pd.DataFrame(enriched_rows, index=df.index)

    return pd.concat([df, enriched_df], axis=1)


def _query_batch(ips: list) -> dict:
    try:
        response = requests.post(
            "https://proxycheck.io/v2/",
            params={
                "key": API_KEY,
                "vpn": 1,
                "asn": 1,
                "risk": 1,
                "seen": 1,
            },
            data={"ips": ",".join(ips)},
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
        print("API RESPONSE:", data)
    except Exception as e:
        raise RuntimeError(f"proxy-check.io error: {e}")

    results = {}
    for ip in ips:
        ip_data = data.get(ip, {})
        if not ip_data:
            results[ip] = _empty_row()
            continue

        results[ip] = {
            "pc_hostname": ip_data.get("hostname", "unknown"),
            "pc_proxy":         ip_data.get("proxy", "unknown"),
            "pc_type":          ip_data.get("type", "unknown"),
            "pc_risk":          ip_data.get("risk", None),
            "pc_provider":      ip_data.get("provider", "unknown"),
            "pc_organisation":  ip_data.get("organisation", "unknown"),
            "pc_continent":     ip_data.get("continent", "unknown"),

            "pc_country":       ip_data.get("country", "unknown"),


            "pc_city":          ip_data.get("city", "unknown"),
            "pc_operator_name":     ip_data.get("operator", {}).get("name", "unknown") if isinstance(ip_data.get("operator"), dict) else "unknown",
            "pc_operator_url":      ip_data.get("operator", {}).get("url", "unknown") if isinstance(ip_data.get("operator"), dict) else "unknown",
            "pc_operator_anonymity":ip_data.get("operator", {}).get("anonymity", "unknown") if isinstance(ip_data.get("operator"), dict) else "unknown",
            "pc_operator_popularity":ip_data.get("operator", {}).get("popularity", "unknown") if isinstance(ip_data.get("operator"), dict) else "unknown",

            "pc_asn":           ip_data.get("asn", "unknown"),
            "pc_range":         ip_data.get("range", "unknown"),
            "pc_last_seen":     ip_data.get("last seen human", "unknown"),
        }

    return results


def _empty_row() -> dict:
    return {
        "pc_hostname":      "unknown",
        "pc_proxy":         "unknown",
        "pc_type":          "unknown",
        "pc_risk":          None,
        "pc_provider":      "unknown",
        "pc_organisation":  "unknown",
        "pc_continent":     "unknown",
        "pc_country":       "unknown",


        "pc_city":          "unknown",
        "pc_operator_name":      "unknown",
        "pc_operator_url":       "unknown",
        "pc_operator_anonymity": "unknown",
        "pc_operator_popularity":"unknown",
        "pc_asn":           "unknown",
        "pc_range":         "unknown",
        "pc_last_seen":     "unknown",
    }