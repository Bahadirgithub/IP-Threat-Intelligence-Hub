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
BATCH_SIZE = 100


def enrich(df: pd.DataFrame) -> pd.DataFrame:
    """
    Takes DataFrame from ingestion.py.
    Queries proxy-check.io for all IPs in batches of 100.
    Returns original DataFrame with new columns added.
    """

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
    """
    Sends a batch of up to 100 IPs to proxy-check.io.
    Returns dict: { ip: { attribute: value, ... } }
    """

    try:
        response = requests.post(
            "https://proxycheck.io/v2/",
            params={
                "key": API_KEY,
                "vpn": 1,
                "asn": 1,
                "risk": 1,
                "port": 1,
                "seen": 1,
                "days": 1,
            },
            data={"ips": "\n".join(ips)},
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
            "pc_proxy":        ip_data.get("proxy", "unknown"),
            "pc_vpn":          ip_data.get("vpn", "unknown"),
            "pc_type":         ip_data.get("type", "unknown"),
            "pc_risk":         ip_data.get("risk", None),
            "pc_isp":          ip_data.get("isp", "unknown"),
            "pc_provider":     ip_data.get("provider", "unknown"),
            "pc_continent":    ip_data.get("continent", "unknown"),
            "pc_country":      ip_data.get("country", "unknown"),
            "pc_isocode":      ip_data.get("isocode", "unknown"),
            "pc_region":       ip_data.get("region", "unknown"),
            "pc_regioncode":   ip_data.get("regioncode", "unknown"),
            "pc_city":         ip_data.get("city", "unknown"),
            "pc_postcode":     ip_data.get("postcode", "unknown"),
            "pc_latitude":     ip_data.get("latitude", None),
            "pc_longitude":    ip_data.get("longitude", None),
            "pc_asn":          ip_data.get("asn", "unknown"),
            "pc_organisation": ip_data.get("organisation", "unknown"),
            "pc_last_seen":    ip_data.get("last seen human", "unknown"),
            "pc_days_since":   ip_data.get("days since last seen", None),
            "pc_port":         ip_data.get("port", "unknown"),
        }

    return results


def _empty_row() -> dict:
    return {
        "pc_proxy": "unknown", "pc_vpn": "unknown", "pc_type": "unknown",
        "pc_risk": None, "pc_isp": "unknown", "pc_provider": "unknown",
        "pc_continent": "unknown", "pc_country": "unknown", "pc_isocode": "unknown",
        "pc_region": "unknown", "pc_regioncode": "unknown", "pc_city": "unknown",
        "pc_postcode": "unknown", "pc_latitude": None, "pc_longitude": None,
        "pc_asn": "unknown", "pc_organisation": "unknown",
        "pc_last_seen": "unknown", "pc_days_since": None, "pc_port": "unknown",
    }