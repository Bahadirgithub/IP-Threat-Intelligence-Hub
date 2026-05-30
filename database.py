"""
database.py
-----------
Stores and retrieves IP records from SQLite.
Tables: ip_records, whitelist_matches, wireless_ips,
        cloud_provider_ips, cdn_edge_ips, bulletproof_hosting, grey_hosting
"""

import sqlite3
import pandas as pd
from datetime import datetime, timezone, timedelta

DB_PATH = "threat_intel.db"


def init_db():
    con = sqlite3.connect(DB_PATH)

    con.execute("""
        CREATE TABLE IF NOT EXISTS ip_records (
            last_seen_db         TEXT,
            ipAddress            TEXT,
            abuseConfidenceScore INTEGER,
            totalReports         INTEGER,
            numDistinctUsers     INTEGER,
            lastReportedAt       TEXT,
            asn                  TEXT,
            hostname             TEXT,
            provider             TEXT,
            organisation         TEXT,
            type                 TEXT,
            country              TEXT,
            city                 TEXT,
            proxy                INTEGER,
            vpn                  INTEGER,
            compromised          INTEGER,
            scraper              INTEGER,
            tor                  INTEGER,
            hosting              INTEGER,
            anonymous            INTEGER,
            operator_name        TEXT,
            operator_url         TEXT,
            operator_anonymity   TEXT,
            operator_popularity  TEXT,
            operator_services    TEXT,
            operator_protocols   TEXT,
            operator_additional  TEXT,
            PRIMARY KEY (ipAddress, provider, organisation, hostname, proxy, vpn, tor, hosting)
        )
    """)

    con.execute("""
        CREATE TABLE IF NOT EXISTS whitelist_matches (
            ipAddress    TEXT PRIMARY KEY,
            asn          TEXT,
            provider     TEXT,
            organisation TEXT,
            matched_at   TEXT
        )
    """)

    con.execute("""
        CREATE TABLE IF NOT EXISTS wireless_ips (
            ipAddress     TEXT PRIMARY KEY,
            provider      TEXT,
            organisation  TEXT,
            asn           TEXT,
            type          TEXT,
            proxy         INTEGER,
            vpn           INTEGER,
            anonymous     INTEGER,
            tor           INTEGER,
            operator_name TEXT,
            detected_at   TEXT
        )
    """)

    con.execute("""
        CREATE TABLE IF NOT EXISTS cloud_provider_ips (
            ipAddress          TEXT PRIMARY KEY,
            provider           TEXT,
            asn                TEXT,
            hostname           TEXT,
            organisation       TEXT,
            city               TEXT,
            type               TEXT,
            proxy              INTEGER,
            vpn                INTEGER,
            tor                INTEGER,
            hosting            INTEGER,
            compromised        INTEGER,
            scraper            INTEGER,
            anonymous          INTEGER,
            operator_name      TEXT,
            operator_url       TEXT,
            operator_anonymity TEXT,
            detected_at        TEXT
        )
    """)

    con.execute("""
        CREATE TABLE IF NOT EXISTS cdn_edge_ips (
            ipAddress          TEXT PRIMARY KEY,
            provider           TEXT,
            asn                TEXT,
            hostname           TEXT,
            organisation       TEXT,
            city               TEXT,
            type               TEXT,
            proxy              INTEGER,
            vpn                INTEGER,
            tor                INTEGER,
            hosting            INTEGER,
            compromised        INTEGER,
            scraper            INTEGER,
            anonymous          INTEGER,
            operator_name      TEXT,
            operator_url       TEXT,
            operator_anonymity TEXT,
            detected_at        TEXT
        )
    """)

    con.execute("""
        CREATE TABLE IF NOT EXISTS bulletproof_hosting (
            ipAddress          TEXT PRIMARY KEY,
            provider           TEXT,
            asn                TEXT,
            hostname           TEXT,
            organisation       TEXT,
            city               TEXT,
            type               TEXT,
            proxy              INTEGER,
            vpn                INTEGER,
            tor                INTEGER,
            operator_name      TEXT,
            operator_url       TEXT,
            operator_anonymity TEXT,
            detected_at        TEXT
        )
    """)

    con.execute("""
        CREATE TABLE IF NOT EXISTS grey_hosting (
            ipAddress          TEXT PRIMARY KEY,
            provider           TEXT,
            asn                TEXT,
            hostname           TEXT,
            organisation       TEXT,
            country            TEXT,
            city               TEXT,
            type               TEXT,
            proxy              INTEGER,
            vpn                INTEGER,
            tor                INTEGER,
            hosting            INTEGER,
            compromised        INTEGER,
            scraper            INTEGER,
            anonymous          INTEGER,
            operator_name      TEXT,
            operator_url       TEXT,
            operator_anonymity TEXT,
            totalReports       INTEGER,
            numDistinctUsers   INTEGER,
            grey_score         REAL,
            grey_sub_tier      TEXT,
            grey_signals       TEXT,
            detected_at        TEXT
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
        ip   = row.get("ipAddress")
        prov = row.get("provider")     or "unknown"
        org  = row.get("organisation") or "unknown"
        host = row.get("hostname")     or "unknown"

        proxy   = int(row.get("proxy"))   if pd.notna(row.get("proxy"))   else 0
        vpn     = int(row.get("vpn"))     if pd.notna(row.get("vpn"))     else 0
        tor     = int(row.get("tor"))     if pd.notna(row.get("tor"))     else 0
        hosting = int(row.get("hosting")) if pd.notna(row.get("hosting")) else 0

        con.execute("""
            INSERT OR REPLACE INTO ip_records (
                last_seen_db,
                ipAddress, abuseConfidenceScore, totalReports, numDistinctUsers, lastReportedAt,
                asn, hostname, provider, organisation, type,
                country, city,
                proxy, vpn, compromised, scraper, tor, hosting, anonymous,
                operator_name, operator_url, operator_anonymity, operator_popularity,
                operator_services, operator_protocols, operator_additional
            ) VALUES (
                ?,
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?,
                ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?
            )
        """, (
            now,
            ip,
            row.get("abuseConfidenceScore"),
            row.get("totalReports"),
            row.get("numDistinctUsers"),
            str(row.get("lastReportedAt", "")),
            row.get("asn"),
            host, prov, org,
            row.get("type"),
            row.get("country"),
            row.get("city"),
            proxy, vpn,
            int(row.get("compromised")) if pd.notna(row.get("compromised")) else 0,
            int(row.get("scraper"))     if pd.notna(row.get("scraper"))     else 0,
            tor, hosting,
            int(row.get("anonymous"))   if pd.notna(row.get("anonymous"))   else 0,
            row.get("operator_name"),
            row.get("operator_url"),
            row.get("operator_anonymity"),
            row.get("operator_popularity"),
            row.get("operator_services"),
            row.get("operator_protocols"),
            row.get("operator_additional"),
        ))

    con.commit()
    con.close()


def save_whitelist(df: pd.DataFrame):
    if df.empty:
        return
    init_db()
    con = sqlite3.connect(DB_PATH)
    now = datetime.now(timezone.utc).isoformat()
    for _, row in df.iterrows():
        con.execute(
            "INSERT OR REPLACE INTO whitelist_matches VALUES (?,?,?,?,?)",
            (row.get("ipAddress"), row.get("asn"), row.get("provider"), row.get("organisation"), now)
        )
    con.commit()
    con.close()


def save_wireless(df: pd.DataFrame):
    if df.empty:
        return
    init_db()
    con = sqlite3.connect(DB_PATH)
    now = datetime.now(timezone.utc).isoformat()
    for _, row in df.iterrows():
        con.execute("""
            INSERT OR REPLACE INTO wireless_ips
            (ipAddress, provider, organisation, asn, type,
             proxy, vpn, anonymous, tor, operator_name, detected_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (
            row.get("ipAddress"),
            row.get("provider"),
            row.get("organisation"),
            row.get("asn"),
            row.get("type"),
            int(row.get("proxy"))     if pd.notna(row.get("proxy"))     else 0,
            int(row.get("vpn"))       if pd.notna(row.get("vpn"))       else 0,
            int(row.get("anonymous")) if pd.notna(row.get("anonymous")) else 0,
            int(row.get("tor"))       if pd.notna(row.get("tor"))       else 0,
            row.get("operator_name"),
            now,
        ))
    con.commit()
    con.close()


def save_cloud(df: pd.DataFrame):
    if df.empty:
        return
    init_db()
    con = sqlite3.connect(DB_PATH)
    now = datetime.now(timezone.utc).isoformat()
    for _, row in df.iterrows():
        con.execute("""
            INSERT OR REPLACE INTO cloud_provider_ips
            (ipAddress, provider, asn, hostname, organisation, city, type,
             proxy, vpn, tor, hosting, compromised, scraper, anonymous,
             operator_name, operator_url, operator_anonymity, detected_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            row.get("ipAddress"),
            row.get("provider"),
            row.get("asn"),
            row.get("hostname"),
            row.get("organisation"),
            row.get("city"),
            row.get("type"),
            int(row.get("proxy"))       if pd.notna(row.get("proxy"))       else 0,
            int(row.get("vpn"))         if pd.notna(row.get("vpn"))         else 0,
            int(row.get("tor"))         if pd.notna(row.get("tor"))         else 0,
            int(row.get("hosting"))     if pd.notna(row.get("hosting"))     else 0,
            int(row.get("compromised")) if pd.notna(row.get("compromised")) else 0,
            int(row.get("scraper"))     if pd.notna(row.get("scraper"))     else 0,
            int(row.get("anonymous"))   if pd.notna(row.get("anonymous"))   else 0,
            row.get("operator_name"),
            row.get("operator_url"),
            row.get("operator_anonymity"),
            now,
        ))
    con.commit()
    con.close()


def save_cdn(df: pd.DataFrame):
    if df.empty:
        return
    init_db()
    con = sqlite3.connect(DB_PATH)
    now = datetime.now(timezone.utc).isoformat()
    for _, row in df.iterrows():
        con.execute("""
            INSERT OR REPLACE INTO cdn_edge_ips
            (ipAddress, provider, asn, hostname, organisation, city, type,
             proxy, vpn, tor, hosting, compromised, scraper, anonymous,
             operator_name, operator_url, operator_anonymity, detected_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            row.get("ipAddress"),
            row.get("provider"),
            row.get("asn"),
            row.get("hostname"),
            row.get("organisation"),
            row.get("city"),
            row.get("type"),
            int(row.get("proxy"))       if pd.notna(row.get("proxy"))       else 0,
            int(row.get("vpn"))         if pd.notna(row.get("vpn"))         else 0,
            int(row.get("tor"))         if pd.notna(row.get("tor"))         else 0,
            int(row.get("hosting"))     if pd.notna(row.get("hosting"))     else 0,
            int(row.get("compromised")) if pd.notna(row.get("compromised")) else 0,
            int(row.get("scraper"))     if pd.notna(row.get("scraper"))     else 0,
            int(row.get("anonymous"))   if pd.notna(row.get("anonymous"))   else 0,
            row.get("operator_name"),
            row.get("operator_url"),
            row.get("operator_anonymity"),
            now,
        ))
    con.commit()
    con.close()


def save_bulletproof(df: pd.DataFrame):
    if df.empty:
        return
    init_db()
    con = sqlite3.connect(DB_PATH)
    now = datetime.now(timezone.utc).isoformat()
    for _, row in df.iterrows():
        con.execute("""
            INSERT OR REPLACE INTO bulletproof_hosting
            (ipAddress, provider, asn, hostname, organisation, city, type,
             proxy, vpn, tor, operator_name, operator_url, operator_anonymity, detected_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            row.get("ipAddress"),
            row.get("provider"),
            row.get("asn"),
            row.get("hostname"),
            row.get("organisation"),
            row.get("city"),
            row.get("type"),
            int(row.get("proxy")) if pd.notna(row.get("proxy")) else 0,
            int(row.get("vpn"))   if pd.notna(row.get("vpn"))   else 0,
            int(row.get("tor"))   if pd.notna(row.get("tor"))   else 0,
            row.get("operator_name"),
            row.get("operator_url"),
            row.get("operator_anonymity"),
            now,
        ))
    con.commit()
    con.close()


def save_grey(df: pd.DataFrame):
    if df.empty:
        return
    init_db()
    con = sqlite3.connect(DB_PATH)
    now = datetime.now(timezone.utc).isoformat()
    for _, row in df.iterrows():
        con.execute("""
            INSERT OR REPLACE INTO grey_hosting
            (ipAddress, provider, asn, hostname, organisation, country, city, type,
             proxy, vpn, tor, hosting, compromised, scraper, anonymous,
             operator_name, operator_url, operator_anonymity,
             totalReports, numDistinctUsers,
             grey_score, grey_sub_tier, grey_signals,
             detected_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            row.get("ipAddress"),
            row.get("provider"),
            row.get("asn"),
            row.get("hostname"),
            row.get("organisation"),
            row.get("country"),
            row.get("city"),
            row.get("type"),
            int(row.get("proxy"))       if pd.notna(row.get("proxy"))       else 0,
            int(row.get("vpn"))         if pd.notna(row.get("vpn"))         else 0,
            int(row.get("tor"))         if pd.notna(row.get("tor"))         else 0,
            int(row.get("hosting"))     if pd.notna(row.get("hosting"))     else 0,
            int(row.get("compromised")) if pd.notna(row.get("compromised")) else 0,
            int(row.get("scraper"))     if pd.notna(row.get("scraper"))     else 0,
            int(row.get("anonymous"))   if pd.notna(row.get("anonymous"))   else 0,
            row.get("operator_name"),
            row.get("operator_url"),
            row.get("operator_anonymity"),
            int(row.get("totalReports"))     if pd.notna(row.get("totalReports"))     else 0,
            int(row.get("numDistinctUsers")) if pd.notna(row.get("numDistinctUsers")) else 0,
            float(row.get("grey_score"))     if pd.notna(row.get("grey_score"))       else None,
            row.get("grey_sub_tier"),
            row.get("grey_signals"),
            now,
        ))
    con.commit()
    con.close()


def load(days: int = 0) -> pd.DataFrame:
    try:
        con = sqlite3.connect(DB_PATH)
        if days > 0:
            cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
            df = pd.read_sql_query(
                "SELECT * FROM ip_records WHERE last_seen_db >= ? ORDER BY last_seen_db DESC",
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


def load_whitelist() -> pd.DataFrame:
    try:
        con = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query(
            "SELECT * FROM whitelist_matches ORDER BY matched_at DESC", con
        )
        con.close()
        return df
    except Exception:
        return pd.DataFrame()


def load_wireless() -> pd.DataFrame:
    try:
        con = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query(
            "SELECT * FROM wireless_ips ORDER BY detected_at DESC", con
        )
        con.close()
        return df
    except Exception:
        return pd.DataFrame()


def load_cloud() -> pd.DataFrame:
    try:
        con = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query(
            "SELECT * FROM cloud_provider_ips ORDER BY detected_at DESC", con
        )
        con.close()
        return df
    except Exception:
        return pd.DataFrame()


def load_cdn() -> pd.DataFrame:
    try:
        con = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query(
            "SELECT * FROM cdn_edge_ips ORDER BY detected_at DESC", con
        )
        con.close()
        return df
    except Exception:
        return pd.DataFrame()


def load_bulletproof() -> pd.DataFrame:
    try:
        con = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query(
            "SELECT * FROM bulletproof_hosting ORDER BY detected_at DESC", con
        )
        con.close()
        return df
    except Exception:
        return pd.DataFrame()


def load_grey(days: int = 0, sub_tier: str = None) -> pd.DataFrame:
    try:
        con = sqlite3.connect(DB_PATH)
        params, sql = [], "SELECT * FROM grey_hosting WHERE 1=1"
        if days > 0:
            cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
            sql += " AND detected_at >= ?"
            params.append(cutoff)
        if sub_tier:
            sql += " AND grey_sub_tier = ?"
            params.append(sub_tier)
        sql += " ORDER BY grey_score DESC, detected_at DESC"
        df = pd.read_sql_query(sql, con, params=params)
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