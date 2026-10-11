"""
Grey Hosting Classifier
-----------------------
Identifies IPs that are hosting-type but not already classified as
Cloud / CDN / Bulletproof.

What this file does NOT do anymore:
  - No scoring (removed — done by provider_agent microservice on demand)
  - No provider_intel DB lookups
  - No batch research calls

Flow:
  1. check_grey_hosting()  →  filter grey IPs from the main DataFrame
  2. get_grey_asns()       →  unique ASNs with IP counts (for the UI table)
"""

from __future__ import annotations

import pandas as pd
from typing import Optional


# ── Helpers ────────────────────────────────────────────────────────────────────

def _asn_to_int(asn_val) -> Optional[int]:
    """Safely convert any ASN representation to int. Returns None on failure."""
    if asn_val is None:
        return None
    try:
        s = str(asn_val).upper().lstrip("AS").strip()
        return int(s)
    except (ValueError, AttributeError):
        return None


# ── Classification ─────────────────────────────────────────────────────────────

def check_grey_hosting(
        df_final: pd.DataFrame,
        df_cloud: pd.DataFrame,
        df_cdn:   pd.DataFrame,
        df_bp:    pd.DataFrame,
) -> pd.DataFrame:
    """
    Return a DataFrame of grey-hosting IPs.

    Grey = usageType/type is "hosting"
           AND the IP is NOT already in cloud / CDN / bulletproof sets.

    Parameters
    ----------
    df_final : enriched IP DataFrame (all IPs from the current pipeline run)
    df_cloud : cloud-provider IPs
    df_cdn   : CDN edge IPs
    df_bp    : bulletproof-hosting IPs

    Returns
    -------
    df_grey : subset of df_final with an extra column `asn_int` (int or NaN)
    """
    if df_final.empty:
        return pd.DataFrame()

    # Build exclusion set
    cloud_ips = set(df_cloud["ipAddress"].unique()) if not df_cloud.empty else set()
    cdn_ips   = set(df_cdn["ipAddress"].unique())   if not df_cdn.empty   else set()
    bp_ips    = set(df_bp["ipAddress"].unique())     if not df_bp.empty    else set()
    excluded  = cloud_ips | cdn_ips | bp_ips

    # Filter: hosting type + not excluded
    df_grey = df_final[
        (df_final["type"].fillna("").str.lower() == "hosting") &
        (~df_final["ipAddress"].isin(excluded))
        ].copy()

    if df_grey.empty:
        print("[grey_check] No grey-hosting IPs found.")
        return pd.DataFrame()

    # Add a clean integer ASN column for easy grouping
    df_grey["asn_int"] = df_grey["asn"].apply(_asn_to_int)

    print(f"[grey_check] {len(df_grey)} grey-hosting IPs from "
          f"{df_grey['asn_int'].nunique()} unique ASNs")

    return df_grey


# ── ASN Summary ────────────────────────────────────────────────────────────────

def get_grey_asns(df_grey: pd.DataFrame) -> pd.DataFrame:
    """
    Return one summary row per ASN, sorted by the number of grey-hosting IPs.

    Columns: asn_int, organisation, ip_count
    """
    empty = pd.DataFrame(columns=["asn_int", "organisation", "ip_count"])
    if df_grey.empty or "asn_int" not in df_grey.columns:
        return empty

    valid = df_grey.dropna(subset=["asn_int"]).copy()
    if valid.empty:
        return empty

    valid["asn_int"] = valid["asn_int"].astype(int)

    if "ipAddress" in valid.columns:
        counts = (
            valid.groupby("asn_int")["ipAddress"]
            .nunique()
            .rename("ip_count")
            .reset_index()
        )
    else:
        counts = valid.groupby("asn_int").size().rename("ip_count").reset_index()

    if "organisation" in valid.columns:
        def first_organisation(values: pd.Series):
            for value in values:
                if pd.isna(value):
                    continue
                text = str(value).strip()
                if text:
                    return text
            return None

        organisations = valid.groupby("asn_int")["organisation"].agg(first_organisation)
        counts["organisation"] = counts["asn_int"].map(organisations)
    else:
        counts["organisation"] = None

    return counts[["asn_int", "organisation", "ip_count"]].sort_values(
        "ip_count", ascending=False
    ).reset_index(drop=True)
