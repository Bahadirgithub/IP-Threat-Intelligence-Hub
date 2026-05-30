"""
grey_check.py
-------------
Grey-hosting extraction + scoring.

Grey = hosting type, NOT in cloud / CDN / bulletproof buckets.
For each grey IP we compute a 0-10 score using:
  - ProxyCheck v3 enrichment columns (already in df)
  - ipapi.is corrections (already applied to type column)
  - Provider intel from research agent (provider_intel table)
  - In-batch ASN abuse-share

Sub-tier:
  0-3   → grey_low    (close to mainstream — monitor only)
  >3-6  → grey_mid    (manual review queue)
  >6-10 → grey_high   (blacklist candidate)
"""

import pandas as pd
from typing import Optional

from provider_intel_db import load_all_approved


# ── Country risk maps (ProxyCheck returns full country_name) ──────────────────

OECD_LOW_RISK = {
    "Germany", "Netherlands", "France", "United States",
    "Canada", "United Kingdom", "Sweden", "Finland", "Japan",
    "Australia", "Switzerland", "Norway", "Denmark", "Ireland",
    "Belgium", "Austria", "Spain", "Italy", "Iceland", "Luxembourg",
    "New Zealand", "South Korea", "Portugal", "Czechia",
}

HIGHER_RISK = {
    "Russia", "Belarus", "Ukraine", "Moldova", "Romania",
    "Bulgaria", "China", "Hong Kong", "Seychelles", "Belize",
    "Panama", "Kazakhstan", "Iran", "North Korea", "Venezuela",
}

# Same sets via 2-letter codes (bgpview.io country_code)
OECD_LOW_RISK_CC = {"DE","NL","FR","US","CA","GB","SE","FI","JP","AU",
                    "CH","NO","DK","IE","BE","AT","ES","IT","IS","LU",
                    "NZ","KR","PT","CZ"}
HIGHER_RISK_CC   = {"RU","BY","UA","MD","RO","BG","CN","HK","SC","BZ",
                    "PA","KZ","IR","KP","VE"}


# ── PTR heuristics ────────────────────────────────────────────────────────────

RESIDENTIAL_PTR_TOKENS = [
    "dynamic", "dhcp", "adsl", "broadband", "cable", "dsl",
    "pool", "ppp", "client", "subscriber", "fttx", "fttp", "fiber",
]

GENERIC_HOSTING_PTR_TOKENS = [
    "unmanaged", "vps-", "static.", "no-rdns",
    "ded.", "server-", "srv-", "host-",
]


def _is_random_ptr(ptr: Optional[str]) -> bool:
    """Detect algorithmically-generated random hostnames (e.g., 'mail.ymmmeui.cn')."""
    if not ptr:
        return False

    parts = str(ptr).lower().strip().split(".")
    if len(parts) < 2:
        return False

    # Look at the main domain (parts[-2]) and the leftmost label
    candidates = {parts[-2], parts[0]}

    for core in candidates:
        if len(core) < 5:
            continue
        # Repetition / low uniqueness
        if len(set(core)) < 4:
            return True
        # Vowel ratio anomaly
        vowels = sum(1 for c in core if c in "aeiouy")
        cons = sum(1 for c in core if c.isalpha() and c not in "aeiouy")
        if vowels + cons > 0:
            ratio = vowels / (vowels + cons)
            if ratio < 0.15 or ratio > 0.75:
                return True
        # Excessive digits
        if sum(c.isdigit() for c in core) > len(core) / 3:
            return True

    return False


def _is_generic_ptr(ptr: Optional[str]) -> bool:
    if not ptr:
        return True  # no PTR is itself a weak generic signal
    ptr_lower = str(ptr).lower()
    return any(t in ptr_lower for t in GENERIC_HOSTING_PTR_TOKENS)


# ── ASN normalization ─────────────────────────────────────────────────────────

def _asn_to_int(asn_val) -> Optional[int]:
    if asn_val is None:
        return None
    s = str(asn_val).upper().strip().replace("AS", "")
    try:
        return int(s)
    except (ValueError, TypeError):
        return None


# ── In-batch ASN share (precomputed per fetch) ────────────────────────────────

_asn_share_cache: dict = {}


def compute_asn_share(df: pd.DataFrame) -> dict:
    """Share of IPs per ASN within the current batch (0..1)."""
    global _asn_share_cache
    if df.empty or "asn" not in df.columns:
        _asn_share_cache = {}
        return {}
    total = len(df)
    counts = df.groupby("asn").size().to_dict()
    _asn_share_cache = {k: v / total for k, v in counts.items()}
    return _asn_share_cache


def _get_asn_share(asn) -> Optional[float]:
    if asn in _asn_share_cache:
        return _asn_share_cache[asn]
    # Try normalized variants
    for k in (str(asn).upper(), str(asn).upper().replace("AS", ""), f"AS{asn}"):
        if k in _asn_share_cache:
            return _asn_share_cache[k]
    return None


# ── Score computation ─────────────────────────────────────────────────────────

def grey_score(row, intel_cache: dict = None) -> tuple:
    """
    Returns (score: float [0..10], signals: list[str], sub_tier: str)
    """
    intel_cache = intel_cache or {}
    score = 0.0
    signals = []

    asn_int = _asn_to_int(row.get("asn"))
    intel = intel_cache.get(asn_int, {}) if asn_int else {}

    # ── Country signal (full name preferred, fallback to intel code) ──
    country = row.get("country") or ""
    cc = (intel.get("country_code") or "").upper()

    if country in OECD_LOW_RISK or cc in OECD_LOW_RISK_CC:
        score -= 1.0; signals.append("oecd_country")
    elif country in HIGHER_RISK or cc in HIGHER_RISK_CC:
        score += 2.0; signals.append("higher_risk_country")

    # ── Compliance certifications (from intel) ──
    if intel.get("iso_27001") == 1:
        score -= 1.0; signals.append("iso_27001")
    if intel.get("soc2") == 1:
        score -= 1.0; signals.append("soc2")
    if intel.get("fedramp") == 1:
        score -= 1.5; signals.append("fedramp")

    # ── ASN age ──
    age = intel.get("asn_age_years")
    if age is not None:
        if age > 10:
            score -= 1.0; signals.append("mature_asn_10y")
        elif age > 5:
            score -= 0.5; signals.append("established_asn_5y")
        elif age < 2:
            score += 1.0; signals.append("young_asn_lt2y")

    # ── Public company ──
    if intel.get("public_company") == 1:
        score -= 1.0; signals.append("public_company")

    # ── Crypto payment ──
    crypto = intel.get("accepts_crypto")
    if crypto == 1:
        score += 1.0; signals.append("crypto_accepted")
    elif crypto == 0:
        score -= 0.5; signals.append("no_crypto")

    # ── Abuse contact ──
    if intel.get("abuse_mailbox"):
        score -= 0.3; signals.append("has_abuse_mailbox")

    # ── Negative press ──
    npc = intel.get("negative_press_count") or 0
    if npc >= 3:
        score += 2.0; signals.append(f"heavy_negative_press_{npc}")
    elif npc >= 1:
        score += 1.0; signals.append(f"some_negative_press_{npc}")

    # ── PTR analysis (ProxyCheck.hostname) ──
    ptr = row.get("hostname")
    if _is_random_ptr(ptr):
        score += 1.5; signals.append("random_ptr")
    if _is_generic_ptr(ptr):
        score += 0.5; signals.append("generic_ptr")

    # ── In-batch ASN share ──
    share = _get_asn_share(row.get("asn"))
    if share is not None:
        if share > 0.05:
            score += 2.0; signals.append("very_high_asn_share")
        elif share > 0.01:
            score += 1.0; signals.append("high_asn_share")
        elif share < 0.001:
            score -= 0.5; signals.append("low_asn_share")

    # ── AbuseIPDB report intensity ──
    reports = int(row.get("totalReports") or 0)
    if reports >= 50:
        score += 1.0; signals.append(f"reports_{reports}")
    elif reports >= 20:
        score += 0.5; signals.append(f"reports_{reports}")
    distinct = int(row.get("numDistinctUsers") or 0)
    if distinct >= 20:
        score += 0.5; signals.append(f"reporters_{distinct}")

    # ── ProxyCheck detection booleans ──
    if row.get("proxy") is True:
        score += 0.5; signals.append("pc_proxy")
    if row.get("compromised") is True:
        score += 1.0; signals.append("pc_compromised")
    if row.get("scraper") is True:
        score += 0.5; signals.append("pc_scraper")
    if row.get("anonymous") is True:
        score += 0.5; signals.append("pc_anonymous")

    # Operator known (Tor, VPN, etc. but typed Hosting → suspicious mix)
    if row.get("operator_name"):
        score += 0.5; signals.append("known_operator")

    # ── Normalize to 0-10 with +5 base offset ──
    final = max(0.0, min(10.0, score + 5.0))

    if final <= 3.0:
        sub_tier = "grey_low"
    elif final <= 6.0:
        sub_tier = "grey_mid"
    else:
        sub_tier = "grey_high"

    return final, signals, sub_tier


def add_grey_scores(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add grey_score, grey_sub_tier, grey_signals columns.
    Score is ONLY computed for IPs whose ASN has been researched by the agent.
    Unresearched ASNs get score=None, sub_tier='unknown', signals=''.
    """
    if df.empty:
        return df

    df = df.copy()
    intel_cache = load_all_approved()   # {asn_int: intel_dict}
    compute_asn_share(df)

    scores, tiers, sigs = [], [], []
    for _, row in df.iterrows():
        asn_int = _asn_to_int(row.get("asn"))

        # Not researched yet → unknown, no score
        if asn_int is None or asn_int not in intel_cache:
            scores.append(None)
            tiers.append("unknown")
            sigs.append("")
            continue

        # Researched → full score
        s, sig, t = grey_score(row, intel_cache)
        scores.append(round(s, 2))
        tiers.append(t)
        sigs.append(",".join(sig))

    df["grey_score"]    = scores
    df["grey_sub_tier"] = tiers
    df["grey_signals"]  = sigs
    return df


def explain_intel_contribution(intel: dict) -> list:
    """
    Given an intel dict (from provider_intel_db), return the list of
    (signal_name, contribution) tuples that would fire from this intel alone.
    Used by the Provider Research page to show 'score breakdown'.
    """
    contributions = []

    cc = (intel.get("country_code") or "").upper()
    if cc in OECD_LOW_RISK_CC:
        contributions.append(("oecd_country", -1.0))
    elif cc in HIGHER_RISK_CC:
        contributions.append(("higher_risk_country", +2.0))

    if intel.get("iso_27001") == 1:
        contributions.append(("iso_27001 certified", -1.0))
    if intel.get("soc2") == 1:
        contributions.append(("soc2 certified", -1.0))
    if intel.get("fedramp") == 1:
        contributions.append(("fedramp certified", -1.5))

    age = intel.get("asn_age_years")
    if age is not None:
        if age > 10:
            contributions.append((f"mature_asn ({age:.0f}y)", -1.0))
        elif age > 5:
            contributions.append((f"established_asn ({age:.0f}y)", -0.5))
        elif age < 2:
            contributions.append((f"young_asn ({age:.1f}y)", +1.0))

    if intel.get("public_company") == 1:
        contributions.append(("public_company", -1.0))

    crypto = intel.get("accepts_crypto")
    if crypto == 1:
        contributions.append(("crypto_accepted", +1.0))
    elif crypto == 0:
        contributions.append(("no_crypto", -0.5))

    if intel.get("abuse_mailbox"):
        contributions.append(("has_abuse_mailbox", -0.3))

    npc = intel.get("negative_press_count") or 0
    if npc >= 3:
        contributions.append((f"heavy_negative_press ({npc})", +2.0))
    elif npc >= 1:
        contributions.append((f"some_negative_press ({npc})", +1.0))

    return contributions


def project_asn_tier_from_intel(intel: dict) -> tuple:
    """
    Project the expected sub-tier for IPs from this ASN based on intel only.
    Returns (projected_score, sub_tier).
    IP-level signals (PTR, AbuseIPDB count, ProxyCheck flags) typically add
    +0 to +3 on top of this baseline.
    """
    contributions = explain_intel_contribution(intel)
    total = sum(v for _, v in contributions)
    projected = max(0.0, min(10.0, total + 5.0))

    if projected <= 3.0:   tier = "grey_low"
    elif projected <= 6.0: tier = "grey_mid"
    else:                  tier = "grey_high"

    return projected, tier


# ── Public extraction API (mirrors cloud_check.py shape) ──────────────────────

def check_grey_hosting(df_final: pd.DataFrame,
                       df_cloud: pd.DataFrame,
                       df_cdn:   pd.DataFrame,
                       df_bp:    pd.DataFrame) -> pd.DataFrame:
    """
    Return grey-hosting DataFrame with score columns.
    Grey = type=hosting AND NOT in cloud/cdn/bulletproof IP sets.
    """
    if df_final.empty:
        return pd.DataFrame()

    cloud_ips = set(df_cloud["ipAddress"].unique()) if not df_cloud.empty else set()
    cdn_ips   = set(df_cdn["ipAddress"].unique())   if not df_cdn.empty   else set()
    bp_ips    = set(df_bp["ipAddress"].unique())    if not df_bp.empty    else set()
    excluded  = cloud_ips | cdn_ips | bp_ips

    df_grey = df_final[
        (df_final["type"].fillna("").str.lower() == "hosting") &
        (~df_final["ipAddress"].isin(excluded))
        ].copy()

    if df_grey.empty:
        return pd.DataFrame()

    print(f"[grey_check] {len(df_grey)} grey-hosting IPs extracted")
    df_grey = add_grey_scores(df_grey)

    # Quick distribution log
    dist = df_grey["grey_sub_tier"].value_counts().to_dict()
    print(f"[grey_check] Sub-tier distribution: {dist}")
    return df_grey


# ── Discovery: ASNs in current batch that have no intel yet ───────────────────

def discover_unknown_asns(df_grey: pd.DataFrame, top_n: int = 30) -> list:
    """
    Return top-N grey ASNs (by IP count) that have NO record in provider_intel.
    Use this to feed batch_research().
    """
    from provider_intel_db import list_researched_asns

    if df_grey.empty or "asn" not in df_grey.columns:
        return []

    researched = list_researched_asns()

    counts = (
        df_grey.assign(_asn_int=df_grey["asn"].apply(_asn_to_int))
        .dropna(subset=["_asn_int"])
        .groupby(["_asn_int", "organisation"])
        .size()
        .reset_index(name="ip_count")
        .sort_values("ip_count", ascending=False)
    )

    out = []
    for _, r in counts.iterrows():
        asn_int = int(r["_asn_int"])
        if asn_int in researched:
            continue
        out.append({
            "asn": asn_int,
            "organisation": r["organisation"],
            "ip_count": int(r["ip_count"]),
        })
        if len(out) >= top_n:
            break

    return out