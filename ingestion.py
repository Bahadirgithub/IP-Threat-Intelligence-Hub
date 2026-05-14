import os
import requests
import pandas as pd
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("ABUSEIPDB_API_KEY")

def fetch_blacklist() -> pd.DataFrame:
    """Fetches IPs with abuse score 100 from AbuseIPDB and filters for the last 24h."""
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

    # Keep only needed columns as per original code
    keep = ["ipAddress", "abuseConfidenceScore", "lastReportedAt",
            "totalReports", "numDistinctUsers"]
    df = df[[c for c in keep if c in df.columns]]

    df["lastReportedAt"] = pd.to_datetime(df["lastReportedAt"], utc=True, errors="coerce")

    # Filter: last 24 hours only
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    df = df[df["lastReportedAt"] >= cutoff].copy()

    return df.reset_index(drop=True)
