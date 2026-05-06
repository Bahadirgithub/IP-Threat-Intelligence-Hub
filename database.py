"""
database.py
-----------
Sole responsibility: store and retrieve IP records from SQLite.
"""

import sqlite3
import pandas as pd
from datetime import datetime, timezone

DB_PATH = "threat_intel.db"


def init_db():
    """Creates the database and table if they don't exist."""
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS ip_records (
            -- Tracking
            first_seen          TEXT,
            last_seen           TEXT,
            times_seen          INTEGER DEFAULT 1,

            -- AbuseIPDB
            ip                  TEXT,
            abuse_score         INTEGER,
            country_code        TEXT,
            total_reports       INTEGER,
            num_distinct_users  INTEGER,
            last_reported_at    TEXT,

            -- proxy-check.io
            pc_proxy            TEXT,
            pc_type             TEXT,
            pc_risk             INTEGER,
            pc_provider         TEXT,
            pc_organisation     TEXT,
            pc_hostname         TEXT,
            pc_continent        TEXT,
            pc_country          TEXT,
           
           
            pc_city             TEXT,
            pc_asn              TEXT,
            pc_range            TEXT,
            pc_last_seen        TEXT,

            PRIMARY KEY (ip, pc_provider, pc_organisation, pc_hostname)
        )
    """)
    con.commit()
    con.close()


def save(df: pd.DataFrame):
    """
    Saves enriched DataFrame to database.
    - If ip + pc_provider + pc_organisation + pc_hostname already exists:
        → updates last_seen, last_reported_at, times_seen only
    - If combination is new:
        → inserts as new record
    """
    if df.empty:
        return

    init_db()
    now = datetime.now(timezone.utc).isoformat()
    con = sqlite3.connect(DB_PATH)

    for _, row in df.iterrows():
        ip           = row.get("ip", "unknown")
        pc_provider  = row.get("pc_provider", "unknown")
        pc_org       = row.get("pc_organisation", "unknown")
        pc_hostname  = row.get("pc_hostname", "unknown")

        # Check if record exists
        existing = con.execute("""
            SELECT times_seen FROM ip_records
            WHERE ip = ? AND pc_provider = ? AND pc_organisation = ? AND pc_hostname = ?
        """, (ip, pc_provider, pc_org, pc_hostname)).fetchone()

        if existing:
            # Update only last_seen, last_reported_at, times_seen
            con.execute("""
                UPDATE ip_records
                SET last_seen        = ?,
                    last_reported_at = ?,
                    times_seen       = times_seen + 1
                WHERE ip = ? AND pc_provider = ? AND pc_organisation = ? AND pc_hostname = ?
            """, (
                now,
                str(row.get("last_reported_at", "")),
                ip, pc_provider, pc_org, pc_hostname,
            ))
        else:
            # Insert new record
            con.execute("""
                INSERT INTO ip_records (
                    first_seen, last_seen, times_seen,
                    ip, abuse_score, country_code, total_reports,
                    num_distinct_users, last_reported_at,
                    pc_proxy, pc_type, pc_risk, pc_provider, pc_organisation,
                    pc_hostname, pc_continent, pc_country,
                    pc_city, pc_asn, pc_range, pc_last_seen
                ) VALUES (
                    ?, ?, 1,
                    ?, ?, ?, ?,
                    ?, ?,
                    ?, ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?, ?, ?
                )
            """, (
                now, now,
                ip,
                row.get("abuse_score"),
                row.get("country_code"),
                row.get("total_reports"),
                row.get("num_distinct_users"),
                str(row.get("last_reported_at", "")),
                row.get("pc_proxy"),
                row.get("pc_type"),
                row.get("pc_risk"),
                pc_provider,
                pc_org,
                pc_hostname,
                row.get("pc_continent"),
                row.get("pc_country"),


                row.get("pc_city"),
                row.get("pc_asn"),
                row.get("pc_range"),
                row.get("pc_last_seen"),
            ))

    con.commit()
    con.close()


def load(days: int = 0) -> pd.DataFrame:
    """
    Loads records from database.
    days=0 → all records
    days=7 → last 7 days
    days=30 → last 30 days
    """
    try:
        con = sqlite3.connect(DB_PATH)
        if days > 0:
            cutoff = datetime.now(timezone.utc).replace(
                hour=0, minute=0, second=0
            )
            from datetime import timedelta
            cutoff = (cutoff - timedelta(days=days)).isoformat()
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
    """Returns total number of records in database."""
    try:
        con = sqlite3.connect(DB_PATH)
        count = con.execute("SELECT COUNT(*) FROM ip_records").fetchone()[0]
        con.close()
        return count
    except Exception:
        return 0