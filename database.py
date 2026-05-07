"""
database.py
-----------
Stores and retrieves IP records from SQLite.
Uses original API field names.
"""

import sqlite3
import pandas as pd
from datetime import datetime, timezone, timedelta

DB_PATH = "threat_intel.db"


def init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS ip_records (
            -- Tracking
            first_seen          TEXT,
            last_seen           TEXT,
            times_seen          INTEGER DEFAULT 1,

            -- AbuseIPDB
            ipAddress           TEXT,
            abuseConfidenceScore INTEGER,
            totalReports        INTEGER,
            numDistinctUsers    INTEGER,
            lastReportedAt      TEXT,

            -- proxy-check.io
            hostname            TEXT,
            proxy               TEXT,
            type                TEXT,
            risk                INTEGER,
            provider            TEXT,
            organisation        TEXT,
            country             TEXT,
            city                TEXT,
            asn                 TEXT,
            range               TEXT,
            "last seen"         TEXT,
            "operator name"     TEXT,
            "operator url"      TEXT,
            "operator anonymity" TEXT,
            "operator popularity" TEXT,

            PRIMARY KEY (ipAddress, provider, organisation, hostname)
        )
    """)
    con.commit()
    con.close()


def save(df: pd.DataFrame):
    if df.empty:
        return

    init_db()
    now = datetime.now(timezone.utc).isoformat()
    con = sqlite3.connect(DB_PATH)

    for _, row in df.iterrows():
        ip       = row.get("ipAddress", "unknown")
        provider = row.get("provider", "unknown")
        org      = row.get("organisation", "unknown")
        hostname = row.get("hostname", "unknown")

        existing = con.execute("""
            SELECT times_seen FROM ip_records
            WHERE ipAddress = ? AND provider = ? AND organisation = ? AND hostname = ?
        """, (ip, provider, org, hostname)).fetchone()

        if existing:
            con.execute("""
                UPDATE ip_records
                SET last_seen      = ?,
                    lastReportedAt = ?,
                    times_seen     = times_seen + 1
                WHERE ipAddress = ? AND provider = ? AND organisation = ? AND hostname = ?
            """, (now, str(row.get("lastReportedAt", "")), ip, provider, org, hostname))
        else:
            con.execute("""
                INSERT INTO ip_records (
                    first_seen, last_seen, times_seen,
                    ipAddress, abuseConfidenceScore, totalReports, numDistinctUsers, lastReportedAt,
                    hostname, proxy, type, risk, provider, organisation,
                    country, city, asn, range, "last seen",
                    "operator name", "operator url", "operator anonymity", "operator popularity"
                ) VALUES (
                    ?, ?, 1,
                    ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?,
                    ?, ?, ?, ?
                )
            """, (
                now, now,
                ip,
                row.get("abuseConfidenceScore"),
                row.get("totalReports"),
                row.get("numDistinctUsers"),
                str(row.get("lastReportedAt", "")),
                hostname,
                row.get("proxy"),
                row.get("type"),
                row.get("risk"),
                provider,
                org,
                row.get("country"),
                row.get("city"),
                row.get("asn"),
                row.get("range"),
                row.get("last seen"),
                row.get("operator name"),
                row.get("operator url"),
                row.get("operator anonymity"),
                row.get("operator popularity"),
            ))

    con.commit()
    con.close()


def load(days: int = 0) -> pd.DataFrame:
    try:
        con = sqlite3.connect(DB_PATH)
        if days > 0:
            cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
            df = pd.read_sql_query(
                "SELECT * FROM ip_records WHERE first_seen >= ? ORDER BY last_seen DESC",
                con, params=(cutoff,)
            )
        else:
            df = pd.read_sql_query(
                "SELECT * FROM ip_records ORDER BY last_seen DESC", con
            )
        con.close()
        return df
    except Exception:
        return pd.DataFrame()


def record_count() -> int:
    try:
        con = sqlite3.connect(DB_PATH)
        count = con.execute("SELECT COUNT(*) FROM ip_records").fetchone()[0]
        con.close()
        return count
    except Exception:
        return 0