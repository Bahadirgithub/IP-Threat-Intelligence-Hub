"""
ingestion.py
------------
Sole responsibility: fetch IPs with abuse score 100
from AbuseIPDB and return them as a clean DataFrame.
"""

import os
import requests
import pandas as pd
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("ABUSEIPDB_API_KEY")


def fetch_blacklist() -> pd.DataFrame:
    """
    Fetches IPs with confidence score 100 from AbuseIPDB.
    Filters to last 24 hours based on lastReportedAt.
    Returns a clean DataFrame, or empty DataFrame on error.
    """

    if not API_KEY:
        raise ValueError("ABUSEIPDB_API_KEY not found in .env")

    response = requests.get(
        "https://api.abuseipdb.com/api/v2/blacklist",
        headers={"Key": API_KEY, "Accept": "application/json"},
        params={"confidenceMinimum": 100},
        timeout=30,
    )
    response.raise_for_status()

    raw = response.json().get("data", [])

    if not raw:
        return pd.DataFrame()

    df = pd.DataFrame(raw)

    # Rename columns to snake_case
    df.rename(columns={
        "ipAddress":            "ip",
        "abuseConfidenceScore": "abuse_score",
        "countryCode":          "country_code",
        "usageType":            "usage_type",
        "totalReports":         "total_reports",
        "numDistinctUsers":     "num_distinct_users",
        "lastReportedAt":       "last_reported_at",
    }, inplace=True)

    # Parse datetime
    df["last_reported_at"] = pd.to_datetime(df["last_reported_at"], utc=True, errors="coerce")

    # Filter: last 24 hours only
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    df = df[df["last_reported_at"] >= cutoff].copy()

    # Clean nulls
    for col, default in [("usage_type", "Unknown"), ("country_code", "XX"),
                         ("isp", "Unknown"), ("domain", "—")]:
        if col not in df.columns:
            df[col] = default
        else:
            df[col] = df[col].fillna(default)

    return df.reset_index(drop=True)