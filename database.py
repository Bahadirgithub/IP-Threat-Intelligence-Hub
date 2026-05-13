"""
database.py
-----------
Stores and retrieves IP records from SQLite.
Same record = same ipAddress + provider + organisation + hostname +
              proxy + vpn + scraper + tor + hosting + anonymous
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
            first_seen_db               TEXT,
            last_seen_db                TEXT,
            times_seen                  INTEGER DEFAULT 1,

            -- AbuseIPDB
            ipAddress                   TEXT,
            abuseConfidenceScore        INTEGER,
            totalReports                INTEGER,
            numDistinctUsers            INTEGER,
            lastReportedAt              TEXT,

            -- Network
            asn                         TEXT,
            range                       TEXT,
            hostname                    TEXT,
            provider                    TEXT,
            organisation                TEXT,
            type                        TEXT,

            -- Location
            country                     TEXT,
            city                        TEXT,

            -- Detections
            proxy                       INTEGER,
            vpn                         INTEGER,
            compromised                 INTEGER,
            scraper                     INTEGER,
            tor                         INTEGER,
            hosting                     INTEGER,
            anonymous                   INTEGER,
            risk                        INTEGER,
            confidence                  INTEGER,
            pc_first_seen               TEXT,
            pc_last_seen                TEXT,

            -- Detection History
            delisted                    INTEGER,
            delist_date                 TEXT,

            -- Attack History
            attack_history              TEXT,

            -- Last Updated
            last_updated                TEXT,

            -- Operator
            operator_name               TEXT,
            operator_url                TEXT,
            operator_anonymity          TEXT,
            operator_popularity         TEXT,
            operator_services           TEXT,
            operator_protocols          TEXT,
            operator_additional         TEXT,

            -- Operator Policies
            policy_ad_filtering         INTEGER,
            policy_free_access          INTEGER,
            policy_paid_access          INTEGER,
            policy_port_forwarding      INTEGER,
            policy_logging              INTEGER,
            policy_anonymous_payments   INTEGER,
            policy_crypto_payments      INTEGER,
            policy_traceable_ownership  INTEGER,

            PRIMARY KEY (
                ipAddress, provider, organisation, hostname,
                proxy, vpn, scraper, tor, hosting, anonymous
            )
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
        ip        = row.get("ipAddress", "unknown")
        provider  = row.get("provider")      or "unknown"
        org       = row.get("organisation")  or "unknown"
        hostname  = row.get("hostname")      or "unknown"
        proxy     = row.get("proxy")
        vpn       = row.get("vpn")
        scraper   = row.get("scraper")
        tor       = row.get("tor")
        hosting   = row.get("hosting")
        anonymous = row.get("anonymous")

        existing = con.execute("""
            SELECT times_seen FROM ip_records
            WHERE ipAddress    = ?
              AND provider     = ?
              AND organisation = ?
              AND hostname     = ?
              AND proxy     IS ?
              AND vpn       IS ?
              AND scraper   IS ?
              AND tor       IS ?
              AND hosting   IS ?
              AND anonymous IS ?
        """, (ip, provider, org, hostname,
              proxy, vpn, scraper, tor, hosting, anonymous)).fetchone()

        if existing:
            con.execute("""
                UPDATE ip_records
                SET last_seen_db   = ?,
                    lastReportedAt = ?,
                    times_seen     = times_seen + 1
                WHERE ipAddress    = ?
                  AND provider     = ?
                  AND organisation = ?
                  AND hostname     = ?
                  AND proxy     IS ?
                  AND vpn       IS ?
                  AND scraper   IS ?
                  AND tor       IS ?
                  AND hosting   IS ?
                  AND anonymous IS ?
            """, (
                now, str(row.get("lastReportedAt", "")),
                ip, provider, org, hostname,
                proxy, vpn, scraper, tor, hosting, anonymous,
            ))
        else:
            con.execute("""
                INSERT INTO ip_records (
                    first_seen_db, last_seen_db, times_seen,
                    ipAddress, abuseConfidenceScore, totalReports, numDistinctUsers, lastReportedAt,
                    asn, range, hostname, provider, organisation, type,
                    country, city,
                    proxy, vpn, compromised, scraper, tor, hosting, anonymous,
                    risk, confidence, pc_first_seen, pc_last_seen,
                    delisted, delist_date,
                    attack_history, last_updated,
                    operator_name, operator_url, operator_anonymity, operator_popularity,
                    operator_services, operator_protocols, operator_additional,
                    policy_ad_filtering, policy_free_access, policy_paid_access,
                    policy_port_forwarding, policy_logging, policy_anonymous_payments,
                    policy_crypto_payments, policy_traceable_ownership
                ) VALUES (
                    ?, ?, 1,
                    ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?,
                    ?, ?,
                    ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?,
                    ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?,
                    ?, ?
                )
            """, (
                now, now,
                ip,
                row.get("abuseConfidenceScore"),
                row.get("totalReports"),
                row.get("numDistinctUsers"),
                str(row.get("lastReportedAt", "")),
                row.get("asn"),
                row.get("range"),
                hostname,
                provider,
                org,
                row.get("type"),
                row.get("country"),
                row.get("city"),
                proxy,
                vpn,
                row.get("compromised"),
                scraper,
                tor,
                hosting,
                anonymous,
                row.get("risk"),
                row.get("confidence"),
                row.get("pc_first_seen"),
                row.get("pc_last_seen"),
                row.get("delisted"),
                row.get("delist_date"),
                row.get("attack_history"),
                row.get("last_updated"),
                row.get("operator_name"),
                row.get("operator_url"),
                row.get("operator_anonymity"),
                row.get("operator_popularity"),
                row.get("operator_services"),
                row.get("operator_protocols"),
                row.get("operator_additional"),
                row.get("policy_ad_filtering"),
                row.get("policy_free_access"),
                row.get("policy_paid_access"),
                row.get("policy_port_forwarding"),
                row.get("policy_logging"),
                row.get("policy_anonymous_payments"),
                row.get("policy_crypto_payments"),
                row.get("policy_traceable_ownership"),
            ))

    con.commit()
    con.close()


def load(days: int = 0) -> pd.DataFrame:
    try:
        con = sqlite3.connect(DB_PATH)
        if days > 0:
            cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
            df = pd.read_sql_query(
                "SELECT * FROM ip_records WHERE first_seen_db >= ? ORDER BY last_seen_db DESC",
                con, params=(cutoff,)
            )
        else:
            df = pd.read_sql_query(
                "SELECT * FROM ip_records ORDER BY last_seen_db DESC", con
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