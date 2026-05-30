"""
provider_intel_db.py
--------------------
SQLite storage for provider research agent results.
Tables: provider_intel (in threat_intel.db, same DB as the rest).
Workflow: research → save (pending) → human approve/reject → production cache.
"""

import sqlite3
import json
from datetime import datetime, timezone
from typing import Optional

DB_PATH = "threat_intel.db"


def init_intel_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS provider_intel (
            asn                  INTEGER PRIMARY KEY,
            provider_name        TEXT,
            website              TEXT,
            country_code         TEXT,
            asn_age_years        REAL,
            iso_27001            INTEGER,   -- 1=yes, 0=no, NULL=unknown
            soc2                 INTEGER,
            fedramp              INTEGER,
            accepts_crypto       INTEGER,
            crypto_coins         TEXT,
            public_company       INTEGER,
            company_ticker       TEXT,
            abuse_mailbox        TEXT,
            negative_press_count INTEGER,
            negative_press_json  TEXT,
            confidence_overall   REAL,
            raw_intel_json       TEXT,
            researched_on        TEXT,
            approved             INTEGER DEFAULT 0,    -- 0=pending, 1=approved, -1=rejected
            approved_on          TEXT
        )
    """)
    con.commit()
    con.close()


def _bool_to_int(v) -> Optional[int]:
    if v is True:  return 1
    if v is False: return 0
    return None


def _parse_age_years(date_str: Optional[str]) -> Optional[float]:
    if not date_str:
        return None
    try:
        d = datetime.strptime(date_str[:10], "%Y-%m-%d")
        return round((datetime.utcnow() - d).days / 365.25, 1)
    except (ValueError, TypeError):
        return None


def save_research_result(research_dict: dict) -> int:
    """
    Save a research result (output of research_provider).
    Sets approved=0 (pending review).
    Returns the ASN that was saved.
    """
    init_intel_db()

    intel   = research_dict.get("intel", {}) or {}
    bgpview = research_dict.get("bgpview", {}) or {}
    asn     = research_dict.get("asn") or intel.get("asn")
    if asn is None:
        raise ValueError("No ASN in research result")

    iso     = (intel.get("iso_27001") or {}).get("certified") if isinstance(intel.get("iso_27001"), dict) else None
    soc     = (intel.get("soc2") or {}).get("certified")      if isinstance(intel.get("soc2"), dict)      else None
    fed     = (intel.get("fedramp") or {}).get("certified")   if isinstance(intel.get("fedramp"), dict)   else None

    crypto      = intel.get("accepts_crypto") or {}
    crypto_val  = crypto.get("value")
    crypto_list = crypto.get("coins") or []

    public_co  = intel.get("public_company") or {}

    negative   = intel.get("negative_press") or []
    abuse_list = bgpview.get("abuse_contacts") or []
    abuse_mail = abuse_list[0] if abuse_list else None

    age_years = _parse_age_years(bgpview.get("date_allocated"))

    con = sqlite3.connect(DB_PATH)
    con.execute("""
        INSERT OR REPLACE INTO provider_intel (
            asn, provider_name, website, country_code, asn_age_years,
            iso_27001, soc2, fedramp,
            accepts_crypto, crypto_coins,
            public_company, company_ticker,
            abuse_mailbox, negative_press_count, negative_press_json,
            confidence_overall, raw_intel_json,
            researched_on, approved
        ) VALUES (?,?,?,?,?, ?,?,?, ?,?, ?,?, ?,?,?, ?,?, ?,?)
    """, (
        int(asn),
        intel.get("provider_name") or bgpview.get("name"),
        intel.get("website") or bgpview.get("website"),
        intel.get("country_code") or bgpview.get("country_code"),
        age_years,
        _bool_to_int(iso), _bool_to_int(soc), _bool_to_int(fed),
        _bool_to_int(crypto_val),
        ",".join(crypto_list) if crypto_list else None,
        _bool_to_int(public_co.get("value")),
        public_co.get("ticker"),
        abuse_mail,
        len(negative),
        json.dumps(negative, ensure_ascii=False) if negative else None,
        intel.get("confidence_overall"),
        json.dumps(research_dict, ensure_ascii=False),
        research_dict.get("researched_on"),
        1,  # ★ auto-approved (trusted-source whitelist enforced upstream)
    ))
    # Set approved_on as well
    con.execute(
        "UPDATE provider_intel SET approved_on = ? WHERE asn = ? AND approved_on IS NULL",
        (research_dict.get("researched_on"), int(asn))
    )
    con.commit()
    con.close()
    return int(asn)


def is_researched(asn) -> bool:
    """Quick check: has this ASN been researched at any point?"""
    asn_num = _to_asn_int(asn)
    if asn_num is None:
        return False
    init_intel_db()
    con = sqlite3.connect(DB_PATH)
    row = con.execute(
        "SELECT 1 FROM provider_intel WHERE asn = ? LIMIT 1", (asn_num,)
    ).fetchone()
    con.close()
    return row is not None


def load_intel(asn) -> Optional[dict]:
    """Load approved intel for a specific ASN. Returns None if not found or not approved."""
    asn_num = _to_asn_int(asn)
    if asn_num is None:
        return None

    init_intel_db()
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    row = con.execute(
        "SELECT * FROM provider_intel WHERE asn = ? AND approved = 1",
        (asn_num,)
    ).fetchone()
    con.close()
    return dict(row) if row else None


def load_pending() -> list:
    """Load all pending (not yet approved/rejected) intel rows."""
    init_intel_db()
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        "SELECT * FROM provider_intel WHERE approved = 0 ORDER BY researched_on DESC"
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]


def load_all_approved() -> dict:
    """Return {asn_int: intel_row_dict} of all approved entries — for scoring lookup."""
    init_intel_db()
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        "SELECT * FROM provider_intel WHERE approved = 1"
    ).fetchall()
    con.close()
    return {r["asn"]: dict(r) for r in rows}


def load_rejected_asns() -> set:
    init_intel_db()
    con = sqlite3.connect(DB_PATH)
    rows = con.execute("SELECT asn FROM provider_intel WHERE approved = -1").fetchall()
    con.close()
    return {r[0] for r in rows}


def list_researched_asns() -> set:
    """All ASNs that have any record (pending/approved/rejected)."""
    init_intel_db()
    con = sqlite3.connect(DB_PATH)
    rows = con.execute("SELECT asn FROM provider_intel").fetchall()
    con.close()
    return {r[0] for r in rows}


def approve(asn) -> bool:
    asn_num = _to_asn_int(asn)
    if asn_num is None:
        return False
    init_intel_db()
    con = sqlite3.connect(DB_PATH)
    con.execute(
        "UPDATE provider_intel SET approved = 1, approved_on = ? WHERE asn = ?",
        (datetime.now(timezone.utc).isoformat(), asn_num)
    )
    con.commit()
    con.close()
    return True


def reject(asn) -> bool:
    asn_num = _to_asn_int(asn)
    if asn_num is None:
        return False
    init_intel_db()
    con = sqlite3.connect(DB_PATH)
    con.execute(
        "UPDATE provider_intel SET approved = -1, approved_on = ? WHERE asn = ?",
        (datetime.now(timezone.utc).isoformat(), asn_num)
    )
    con.commit()
    con.close()
    return True


def update_intel(asn, fields: dict) -> bool:
    """Update specific columns (e.g., manual correction during review)."""
    asn_num = _to_asn_int(asn)
    if asn_num is None or not fields:
        return False

    init_intel_db()
    con = sqlite3.connect(DB_PATH)
    set_clauses = []
    values = []
    for k, v in fields.items():
        set_clauses.append(f"{k} = ?")
        values.append(v)
    values.append(asn_num)
    con.execute(
        f"UPDATE provider_intel SET {', '.join(set_clauses)} WHERE asn = ?",
        values
    )
    con.commit()
    con.close()
    return True


def _to_asn_int(asn) -> Optional[int]:
    if asn is None:
        return None
    s = str(asn).upper().strip().replace("AS", "")
    try:
        return int(s)
    except (ValueError, TypeError):
        return None