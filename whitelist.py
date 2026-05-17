"""
whitelist.py
------------
Checks IPs against:
  1. Manual ASN whitelist
  2. Manual IP whitelist
  3. Manual IP range whitelist
"""

import ipaddress
import pandas as pd
from whitelist_data import WHITELIST_ASNS, WHITELIST_IPS, WHITELIST_RANGES

# Pre-compute network objects once
_NETWORKS = [ipaddress.ip_network(r, strict=False) for r in WHITELIST_RANGES]


def _is_in_range(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in net for net in _NETWORKS)
    except ValueError:
        return False


def check_whitelist(df: pd.DataFrame) -> tuple:
    if df.empty:
        return pd.DataFrame(), 0, 0

    def is_whitelisted(row):
        ip = str(row.get("ipAddress", ""))

        # 1. IP Check
        if ip in WHITELIST_IPS:
            return True

        # 2. ASN Check
        raw_asn = str(row.get("asn", ""))
        clean_asn = "".join(filter(str.isdigit, raw_asn))
        if clean_asn and int(clean_asn) in WHITELIST_ASNS:
            return True

        # 3. IP Range Check
        if _is_in_range(ip):
            return True

        return False

    df_match = df[df.apply(is_whitelisted, axis=1)].copy()
    match_count = len(df_match)

    return df_match, match_count, 0