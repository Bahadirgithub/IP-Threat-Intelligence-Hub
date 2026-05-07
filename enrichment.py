"""
enrichment.py
-------------
Enriches IPs from ingestion.py using proxy-check.io API.
Returns original API field names.
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

    ips = df["ipAddress"].tolist()
    results = {}

    for i in range(0, len(ips), BATCH_SIZE):
        batch = ips[i:i + BATCH_SIZE]
        results.update(_query_batch(batch))

    enriched_rows = [results.get(ip, _empty_row()) for ip in ips]
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
    except Exception as e:
        raise RuntimeError(f"proxy-check.io error: {e}")

    results = {}
    for ip in ips:
        ip_data = data.get(ip, {})
        if not ip_data:
            results[ip] = _empty_row()
            continue

        operator = ip_data.get("operator", {}) or {}

        results[ip] = {
            "hostname":           ip_data.get("hostname", "unknown"),
            "proxy":              ip_data.get("proxy", "unknown"),
            "type":               ip_data.get("type", "unknown"),
            "risk":               ip_data.get("risk", None),
            "provider":           ip_data.get("provider", "unknown"),
            "organisation":       ip_data.get("organisation", "unknown"),
            "country":            ip_data.get("country", "unknown"),
            "city":               ip_data.get("city", "unknown"),
            "asn":                ip_data.get("asn", "unknown"),
            "range":              ip_data.get("range", "unknown"),
            "last seen":          ip_data.get("last seen human", "unknown"),
            "operator name":      operator.get("name", "unknown"),
            "operator url":       operator.get("url", "unknown"),
            "operator anonymity": operator.get("anonymity", "unknown"),
            "operator popularity":operator.get("popularity", "unknown"),
        }

    return results


def _empty_row() -> dict:
    return {
        "hostname":            "unknown",
        "proxy":               "unknown",
        "type":                "unknown",
        "risk":                None,
        "provider":            "unknown",
        "organisation":        "unknown",
        "country":             "unknown",
        "city":                "unknown",
        "asn":                 "unknown",
        "range":               "unknown",
        "last seen":           "unknown",
        "operator name":       "unknown",
        "operator url":        "unknown",
        "operator anonymity":  "unknown",
        "operator popularity": "unknown",
    }