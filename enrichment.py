"""
enrichment.py
-------------
Enriches IPs using proxy-check.io v3 API.
Batch: up to 1,000 IPs per request via POST.
"""

import os
import requests
import pandas as pd
from dotenv import load_dotenv

load_dotenv()

API_KEY    = os.getenv("PROXYCHECK_API_KEY")
BATCH_SIZE = 1000


def enrich(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df

    ips     = df["ipAddress"].tolist()
    results = {}

    for i in range(0, len(ips), BATCH_SIZE):
        batch = ips[i:i + BATCH_SIZE]
        results.update(_query_batch(batch))

    enriched_rows = [results.get(ip, _empty_row()) for ip in ips]
    enriched_df   = pd.DataFrame(enriched_rows, index=df.index)

    return pd.concat([df, enriched_df], axis=1)


def _query_batch(ips: list) -> dict:
    try:
        response = requests.post(
            "https://proxycheck.io/v3/",
            params={"key": API_KEY},
            data={"ips": ",".join(ips)},
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        raise RuntimeError(f"proxy-check.io v3 error: {e}")

    results = {}
    for ip in ips:
        ip_data = data.get(ip)
        if not ip_data:
            results[ip] = _empty_row()
            continue

        network          = ip_data.get("network")           or {}
        location         = ip_data.get("location")          or {}
        detections       = ip_data.get("detections")        or {}
        attack_history   = ip_data.get("attack_history")
        operator         = ip_data.get("operator")          or {}

        results[ip] = {
            # Network
            "asn":                       network.get("asn"),
            "hostname":                  network.get("hostname"),
            "provider":                  network.get("provider"),
            "organisation":              network.get("organisation"),
            "type":                      network.get("type"),
            # Location
            "country":                   location.get("country_name"),
            "city":                      location.get("city_name"),
            # Detections
            "proxy":                     detections.get("proxy"),
            "vpn":                       detections.get("vpn"),
            "compromised":               detections.get("compromised"),
            "scraper":                   detections.get("scraper"),
            "tor":                       detections.get("tor"),
            "hosting":                   detections.get("hosting"),
            "anonymous":                 detections.get("anonymous"),
            # Operator
            "operator_name":             operator.get("name"),
            "operator_url":              operator.get("url"),
            "operator_anonymity":        operator.get("anonymity"),
            "operator_popularity":       operator.get("popularity"),
            "operator_services":         str(operator.get("services"))             if operator.get("services")             else None,
            "operator_protocols":        str(operator.get("protocols"))            if operator.get("protocols")            else None,
            "operator_additional":       str(operator.get("additional_operators")) if operator.get("additional_operators") else None,
        }

    return results


def _empty_row() -> dict:
    return {
        "asn": None, "hostname": None, "provider": None,
        "organisation": None, "type": None,
        "country": None, "city": None,
        "proxy": None, "vpn": None, "compromised": None,
        "scraper": None, "tor": None, "hosting": None, "anonymous": None,
        "operator_name": None, "operator_url": None,
        "operator_anonymity": None, "operator_popularity": None,
        "operator_services": None, "operator_protocols": None,
        "operator_additional": None,
    }