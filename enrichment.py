import os
import requests
import pandas as pd
from dotenv import load_dotenv

load_dotenv()

API_KEY    = os.getenv("PROXYCHECK_API_KEY")
BATCH_SIZE = 1000

def enrich(df: pd.DataFrame) -> pd.DataFrame:
    """Enriches IPs using proxy-check.io v3 API with all original fields preserved."""
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
    """Internal POST request to proxy-check.io for batch processing."""
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
        detection_history= ip_data.get("detection_history") or {}
        attack_history   = ip_data.get("attack_history")
        operator         = ip_data.get("operator")          or {}
        policies         = operator.get("policies")         or {}

        results[ip] = {
            "asn":                       network.get("asn"),
            "range":                     network.get("range"),
            "hostname":                  network.get("hostname"),
            "provider":                  network.get("provider"),
            "organisation":              network.get("organisation"),
            "type":                      network.get("type"),
            "country":                   location.get("country_name"),
            "city":                      location.get("city_name"),
            "proxy":                     detections.get("proxy"),
            "vpn":                       detections.get("vpn"),
            "compromised":               detections.get("compromised"),
            "scraper":                   detections.get("scraper"),
            "tor":                       detections.get("tor"),
            "hosting":                   detections.get("hosting"),
            "anonymous":                 detections.get("anonymous"),
            "risk":                      detections.get("risk"),
            "confidence":                detections.get("confidence"),
            "pc_first_seen":             detections.get("first_seen"),
            "pc_last_seen":              detections.get("last_seen"),
            "delisted":                  detection_history.get("delisted"),
            "delist_date":               detection_history.get("delist_datetime"),
            "attack_history":            str(attack_history) if attack_history else None,
            "last_updated":              ip_data.get("last_updated"),
            "operator_name":             operator.get("name"),
            "operator_url":              operator.get("url"),
            "operator_anonymity":        operator.get("anonymity"),
            "operator_popularity":       operator.get("popularity"),
            "operator_services":         str(operator.get("services"))            if operator.get("services")            else None,
            "operator_protocols":        str(operator.get("protocols"))           if operator.get("protocols")           else None,
            "operator_additional":       str(operator.get("additional_operators"))if operator.get("additional_operators") else None,
            "policy_ad_filtering":       policies.get("ad_filtering"),
            "policy_free_access":        policies.get("free_access"),
            "policy_paid_access":        policies.get("paid_access"),
            "policy_port_forwarding":    policies.get("port_forwarding"),
            "policy_logging":            policies.get("logging"),
            "policy_anonymous_payments": policies.get("anonymous_payments"),
            "policy_crypto_payments":    policies.get("crypto_payments"),
            "policy_traceable_ownership":policies.get("traceable_ownership"),
        }
    return results

def _empty_row() -> dict:
    """Returns a full dictionary with None values for missing IPs."""
    return {
        "asn": None, "range": None, "hostname": None, "provider": None, "organisation": None, "type": None,
        "country": None, "city": None, "proxy": None, "vpn": None, "compromised": None, "scraper": None,
        "tor": None, "hosting": None, "anonymous": None, "risk": None, "confidence": None, "pc_first_seen": None,
        "pc_last_seen": None, "delisted": None, "delist_date": None, "attack_history": None, "last_updated": None,
        "operator_name": None, "operator_url": None, "operator_anonymity": None, "operator_popularity": None,
        "operator_services": None, "operator_protocols": None, "operator_additional": None, "policy_ad_filtering": None,
        "policy_free_access": None, "policy_paid_access": None, "policy_port_forwarding": None, "policy_logging": None,
        "policy_anonymous_payments": None, "policy_crypto_payments": None, "policy_traceable_ownership": None,
    }