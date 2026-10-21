"""
anonymization_check.py
-----------------------
Classifies IPs into anonymization sub-categories based on ProxyCheck v3 data.

Priority order (no overlaps):
  1. Tor Exit Node        — tor=True                              (highest priority)
  2. Residential Proxy   — proxy=True + type=residential
  3. Public Proxy        — proxy=True + type=hosting + operator known
  4. Self-hosted Proxy   — proxy=True + type=hosting + operator unknown
  5. Commercial VPN      — vpn=True  + operator known
  6. Private VPN         — vpn=True  + operator unknown

An IP is assigned to exactly ONE category (first match wins).
"""

from __future__ import annotations
import pandas as pd
from typing import Optional


# ── Columns to display per category ───────────────────────────────────────────

BASE_COLS = [
    "ipAddress", "abuseConfidenceScore", "totalReports",
    "asn", "provider", "organisation", "country", "city", "type",
]

PROXY_COLS = BASE_COLS + [
    "proxy", "anonymous",
    "operator_name", "operator_url", "operator_anonymity",
]

VPN_COLS = BASE_COLS + [
    "vpn", "anonymous",
    "operator_name", "operator_url", "operator_anonymity", "operator_services",
]

TOR_COLS = BASE_COLS + ["tor", "anonymous", "operator_name"]


# ── Helpers ────────────────────────────────────────────────────────────────────

def _flag(val) -> bool:
    """Safely coerce any truthy representation to bool."""
    if val is None or (isinstance(val, float) and pd.isna(val)):
        return False
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return int(val) == 1
    if isinstance(val, str):
        return val.strip().lower() in ("true", "1", "yes")
    return False


def _has_operator(row: pd.Series) -> bool:
    """True if operator_name is a non-empty, non-null string."""
    name = row.get("operator_name")
    if name is None or (isinstance(name, float) and pd.isna(name)):
        return False
    return bool(str(name).strip())


def _col_subset(df: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
    return df[[c for c in cols if c in df.columns]].copy()


def _ip_type(row: pd.Series) -> str:
    return str(row.get("type", "") or "").lower().strip()


# ── Main classifier ────────────────────────────────────────────────────────────

def classify_anonymization(
        df: pd.DataFrame,
        exclude_ips: set[str] | None = None,
) -> dict[str, pd.DataFrame]:
    """
    Parameters
    ----------
    df          : Enriched IP DataFrame (output of enrich() / verify_business_ips())
    exclude_ips : Set of IP addresses to skip (e.g. whitelisted scanners)

    Returns
    -------
    dict with keys:
        "tor"              → Tor Exit Nodes
        "residential_proxy"→ Residential Proxies
        "public_proxy"     → Public Proxies (hosting + known operator)
        "selfhosted_proxy" → Self-hosted Proxies (hosting + unknown operator)
        "commercial_vpn"   → Commercial VPNs (known operator)
        "private_vpn"      → Private VPNs (unknown operator)
    """
    empty: dict[str, pd.DataFrame] = {
        "tor":               pd.DataFrame(),
        "residential_proxy": pd.DataFrame(),
        "public_proxy":      pd.DataFrame(),
        "selfhosted_proxy":  pd.DataFrame(),
        "commercial_vpn":    pd.DataFrame(),
        "private_vpn":       pd.DataFrame(),
    }

    if df.empty:
        return empty

    # Drop internal columns + apply global exclusion
    work = df.copy()
    if "_api_corrected" in work.columns:
        work = work.drop(columns=["_api_corrected"])
    if exclude_ips:
        work = work[~work["ipAddress"].isin(exclude_ips)]
    if work.empty:
        return empty

    # Pre-compute boolean series for speed
    is_tor   = work.apply(lambda r: _flag(r.get("tor")),   axis=1)
    is_proxy = work.apply(lambda r: _flag(r.get("proxy")), axis=1)
    is_vpn   = work.apply(lambda r: _flag(r.get("vpn")),   axis=1)
    is_res   = work.apply(lambda r: _ip_type(r) == "residential", axis=1)
    is_host  = work.apply(lambda r: _ip_type(r) == "hosting",     axis=1)
    has_op   = work.apply(_has_operator, axis=1)

    classified: set[str] = set()

    def _pick(mask: pd.Series) -> pd.DataFrame:
        """Apply mask, exclude already-classified IPs, record new ones."""
        subset = work[mask & ~work["ipAddress"].isin(classified)]
        classified.update(subset["ipAddress"].tolist())
        return subset

    results: dict[str, pd.DataFrame] = {}

    # 1. Tor Exit Node ──────────────────────────────────────────────────────────
    df_tor = _pick(is_tor)
    results["tor"] = _col_subset(df_tor, TOR_COLS) if not df_tor.empty else pd.DataFrame()
    _log("Tor Exit Node", results["tor"])

    # 2. Residential Proxy ──────────────────────────────────────────────────────
    df_rp = _pick(is_proxy & is_res)
    results["residential_proxy"] = _col_subset(df_rp, PROXY_COLS) if not df_rp.empty else pd.DataFrame()
    _log("Residential Proxy", results["residential_proxy"])

    # 3. Public Proxy  (hosting + operator known) ───────────────────────────────
    df_pp = _pick(is_proxy & is_host & has_op)
    results["public_proxy"] = _col_subset(df_pp, PROXY_COLS) if not df_pp.empty else pd.DataFrame()
    _log("Public Proxy", results["public_proxy"])

    # 4. Self-hosted Proxy  (hosting + operator unknown) ────────────────────────
    df_sp = _pick(is_proxy & is_host & ~has_op)
    results["selfhosted_proxy"] = _col_subset(df_sp, PROXY_COLS) if not df_sp.empty else pd.DataFrame()
    _log("Self-hosted Proxy", results["selfhosted_proxy"])

    # 5. Commercial VPN  (operator known) ───────────────────────────────────────
    df_cv = _pick(is_vpn & has_op)
    results["commercial_vpn"] = _col_subset(df_cv, VPN_COLS) if not df_cv.empty else pd.DataFrame()
    _log("Commercial VPN", results["commercial_vpn"])

    # 6. Private VPN  (operator unknown) ────────────────────────────────────────
    df_pv = _pick(is_vpn & ~has_op)
    results["private_vpn"] = _col_subset(df_pv, VPN_COLS) if not df_pv.empty else pd.DataFrame()
    _log("Private VPN", results["private_vpn"])

    total = sum(len(v) for v in results.values())
    print(f"[anon_check] Total anonymization IPs classified: {total}")

    return results


def _log(label: str, df: pd.DataFrame) -> None:
    if not df.empty:
        print(f"[anon_check] {label}: {len(df)}")