"""
cloud_check.py
--------------
Checks enriched IPs against:
  1. Cloud Provider IP ranges  → cloud_ranges/*.txt
  2. CDN Edge IP ranges        → cdn_ranges/*.txt
Uses binary search (bisect) for fast O(log n) prefix lookups.
No external dependencies — stdlib only.
"""

import os
import bisect
import ipaddress
import pandas as pd

CLOUD_RANGES_DIR = "cloud_ranges"
CDN_RANGES_DIR   = "cdn_ranges"


def _load_ranges_from_dir(directory: str) -> tuple[list, list]:
    entries = []

    if not os.path.isdir(directory):
        print(f"[cloud_check] Directory '{directory}' not found.")
        return [], []

    total = 0
    for filename in sorted(os.listdir(directory)):
        if not filename.endswith(".txt"):
            continue

        provider = filename.replace(".txt", "")
        filepath = os.path.join(directory, filename)
        count    = 0

        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    net = ipaddress.ip_network(line, strict=False)
                    entries.append((
                        int(net.network_address),
                        int(net.broadcast_address),
                        provider,
                    ))
                    count += 1
                except ValueError:
                    pass

        print(f"[cloud_check] {provider}: {count:,} ranges loaded ({directory})")
        total += count

    entries.sort(key=lambda x: x[0])
    net_keys = [e[0] for e in entries]

    print(f"[cloud_check] Total {total:,} ranges loaded ({directory})")
    return entries, net_keys


# ── Load at import time ───────────────────────────────────────────────────────
_CLOUD_NETWORKS, _CLOUD_KEYS = _load_ranges_from_dir(CLOUD_RANGES_DIR)
_CDN_NETWORKS,   _CDN_KEYS   = _load_ranges_from_dir(CDN_RANGES_DIR)


# ── Lookup ────────────────────────────────────────────────────────────────────
def _lookup(ip: str, networks: list, keys: list) -> str | None:
    try:
        ip_int = int(ipaddress.ip_address(ip))
        idx = bisect.bisect_right(keys, ip_int) - 1
        if idx >= 0:
            net_addr, bcast_addr, provider = networks[idx]
            if ip_int <= bcast_addr:
                return provider
        return None
    except ValueError:
        return None


# ── Shared row builder ────────────────────────────────────────────────────────
def _build_rows(df: pd.DataFrame, networks: list, keys: list) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame()

    rows = []
    for _, row in df.iterrows():
        provider = _lookup(str(row.get("ipAddress", "")), networks, keys)
        if provider:
            rows.append({
                "ipAddress":          row.get("ipAddress"),
                "provider":           provider,
                "asn":                row.get("asn"),
                "hostname":           row.get("hostname"),
                "organisation":       row.get("organisation"),
                "city":               row.get("city"),
                "type":               row.get("type"),
                "proxy":              row.get("proxy"),
                "vpn":                row.get("vpn"),
                "tor":                row.get("tor"),
                "hosting":            row.get("hosting"),
                "compromised":        row.get("compromised"),
                "scraper":            row.get("scraper"),
                "anonymous":          row.get("anonymous"),
                "operator_name":      row.get("operator_name"),
                "operator_url":       row.get("operator_url"),
                "operator_anonymity": row.get("operator_anonymity"),
            })

    return pd.DataFrame(rows) if rows else pd.DataFrame()


# ── Public API ────────────────────────────────────────────────────────────────
def check_cloud_providers(df: pd.DataFrame) -> pd.DataFrame:
    return _build_rows(df, _CLOUD_NETWORKS, _CLOUD_KEYS)


def check_cdn_providers(df: pd.DataFrame) -> pd.DataFrame:
    return _build_rows(df, _CDN_NETWORKS, _CDN_KEYS)