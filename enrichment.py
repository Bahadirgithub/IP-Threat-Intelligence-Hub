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
            "pc_proxy":         ip_data.get("proxy", "unknown"),
            "pc_type":          ip_data.get("type", "unknown"),
            "pc_risk":          ip_data.get("risk", None),
            "pc_provider":      ip_data.get("provider", "unknown"),
            "pc_organisation":  ip_data.get("organisation", "unknown"),
            "pc_continent":     ip_data.get("continent", "unknown"),
            "pc_continentcode": ip_data.get("continentcode", "unknown"),
            "pc_country":       ip_data.get("country", "unknown"),
            "pc_isocode":       ip_data.get("isocode", "unknown"),
            "pc_region":        ip_data.get("region", "unknown"),
            "pc_regioncode":    ip_data.get("regioncode", "unknown"),
            "pc_timezone":      ip_data.get("timezone", "unknown"),
            "pc_city":          ip_data.get("city", "unknown"),
            "pc_postcode":      ip_data.get("postcode", "unknown"),
            "pc_latitude":      ip_data.get("latitude", None),
            "pc_longitude":     ip_data.get("longitude", None),
            "pc_asn":           ip_data.get("asn", "unknown"),
            "pc_range":         ip_data.get("range", "unknown"),
            "pc_last_seen":     ip_data.get("last seen human", "unknown"),
        }

    return results


def _empty_row() -> dict:
    return {
        "pc_proxy": "unknown", "pc_type": "unknown", "pc_risk": None,
        "pc_provider": "unknown", "pc_organisation": "unknown",
        "pc_continent": "unknown", "pc_continentcode": "unknown",
        "pc_country": "unknown", "pc_isocode": "unknown",
        "pc_region": "unknown", "pc_regioncode": "unknown",
        "pc_timezone": "unknown", "pc_city": "unknown",
        "pc_postcode": "unknown", "pc_latitude": None, "pc_longitude": None,
        "pc_asn": "unknown", "pc_range": "unknown", "pc_last_seen": "unknown",
    }