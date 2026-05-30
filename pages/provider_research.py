"""
provider_research_agent.py
--------------------------
Free-stack research agent for hosting provider intel.
Sources (all free):
  - bgpview.io  → ASN metadata, allocation date, abuse contacts
  - RDAP (ARIN) → abuse mailbox
  - DuckDuckGo  → negative press search (Krebs, Correctiv, Spamhaus)
  - Gemini 2.0 Flash + google_search → structured intel extraction

Output: structured JSON per ASN (saved via provider_intel_db).
Rate-limited to fit Gemini free tier (15 RPM / 1500 RPD).
"""

import os
import json
import time
import requests
from datetime import datetime, timezone
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

GEMINI_API_KEY  = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL    = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")  # override via .env if needed
GEMINI_ENDPOINT = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"

REQUEST_TIMEOUT          = 60
GEMINI_RATE_LIMIT_SLEEP  = 4.5  # 15 RPM free tier → 4s + buffer
BGPVIEW_RATE_LIMIT_SLEEP = 1.0
DDG_MAX_RESULTS          = 5

# Grounding has a separate daily quota (500/day on gemini-2.0-flash free tier).
# Set USE_GEMINI_GROUNDING=false in .env to disable if you hit grounding quota.
USE_GEMINI_GROUNDING = os.getenv("USE_GEMINI_GROUNDING", "true").lower() != "false"


# ── Trusted source whitelist ──────────────────────────────────────────────────
# A claim is only counted as valid if its source URL contains one of these
# domains. Provider self-claims are NEVER trusted.

TRUSTED_SOURCES = {
    "iso_27001": [
        "iso.org",
        "bsigroup.com",          # BSI UK
        "tuvsud.com", "tuv.com", # TÜV SÜD, TÜV Rheinland
        "dnv.com",               # DNV
        "dekra.com",
        "sgs.com",
        "bureauveritas.com",
        "intertek.com",
        "lrqa.com",              # Lloyd's Register
        "schellman.com",
        "a-lign.com",
    ],
    "soc2": [
        "aicpa.org",
        "deloitte.com", "ey.com", "kpmg.com", "pwc.com",   # Big 4
        "bdo.com", "rsmus.com", "grantthornton.com",
        "schellman.com", "a-lign.com",                      # Niche but accredited
    ],
    "fedramp": [
        "marketplace.fedramp.gov",
        "fedramp.gov",
    ],
    "public_company": [
        "sec.gov",
        "wikipedia.org", "en.wikipedia.org",
        "nyse.com", "nasdaq.com",
        "lse.co.uk", "londonstockexchange.com",
        "investor.gov",
    ],
    "negative_press": [
        "krebsonsecurity.com",
        "correctiv.org",
        "spamhaus.org",
        "domaintools.com",
        "recordedfuture.com",
        "bleepingcomputer.com",
        "therecord.media",
        "wired.com",
        "arstechnica.com",
        "theregister.com",
        "darkreading.com",
        "ec.europa.eu",          # EU sanctions
        "treasury.gov",          # US OFAC sanctions
        "gov.uk",                # UK sanctions
    ],
}

# Flat list of all trusted domains (for prompt)
ALL_TRUSTED_DOMAINS = sorted({d for lst in TRUSTED_SOURCES.values() for d in lst})


# ── Free APIs (no key required) ───────────────────────────────────────────────

def _fetch_bgpview(asn_num: str) -> dict:
    """Try bgpview.io first."""
    r = requests.get(
        f"https://api.bgpview.io/asn/{asn_num}",
        timeout=10,
        headers={"User-Agent": "ThreatWatch/1.0"},
    )
    r.raise_for_status()
    data = r.json().get("data", {}) or {}
    return {
        "asn":             asn_num,
        "name":            data.get("name"),
        "description":     data.get("description_short"),
        "country_code":    data.get("country_code"),
        "date_allocated":  data.get("date_allocated"),
        "website":         data.get("website"),
        "email_contacts":  data.get("email_contacts", []),
        "abuse_contacts":  data.get("abuse_contacts", []),
        "rir_allocation":  (data.get("rir_allocation") or {}).get("rir_name"),
        "_source":         "bgpview.io",
    }


def _fetch_ripestat(asn_num: str) -> dict:
    """Fallback: RIPE Stat (always reachable, very reliable)."""
    # 1. AS overview
    r = requests.get(
        f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn_num}",
        timeout=10,
        headers={"User-Agent": "ThreatWatch/1.0"},
    )
    r.raise_for_status()
    data = r.json().get("data", {}) or {}

    holder = data.get("holder")     # e.g. "HETZNER-AS, DE"
    name, _, cc = (holder or "").partition(", ")

    out = {
        "asn":          asn_num,
        "name":         (name or "").strip() or None,
        "description":  holder,
        "country_code": (cc or "").strip().upper() or None,
        "_source":      "stat.ripe.net",
    }

    # 2. AS allocation date (optional)
    try:
        r2 = requests.get(
            f"https://stat.ripe.net/data/whois/data.json?resource=AS{asn_num}",
            timeout=8,
            headers={"User-Agent": "ThreatWatch/1.0"},
        )
        r2.raise_for_status()
        whois = r2.json().get("data", {}) or {}
        for rec in whois.get("records", []) or []:
            for kv in rec or []:
                if kv.get("key", "").lower() in ("created", "regdate"):
                    out["date_allocated"] = kv.get("value")
                    break
    except Exception:
        pass

    return out


def get_asn_info(asn) -> dict:
    """
    Fetch ASN metadata. Tries bgpview.io first, falls back to RIPE Stat on failure.
    """
    asn_num = str(asn).upper().replace("AS", "").strip()

    # 1. bgpview
    try:
        info = _fetch_bgpview(asn_num)
        if info.get("name"):
            return info
    except Exception as e:
        print(f"[research] bgpview error AS{asn_num}: {e} — trying RIPE Stat fallback")

    # 2. RIPE Stat fallback
    try:
        info = _fetch_ripestat(asn_num)
        if info.get("name"):
            print(f"[research] AS{asn_num} resolved via RIPE Stat: {info['name']}")
            return info
    except Exception as e:
        print(f"[research] RIPE Stat error AS{asn_num}: {e}")

    return {"asn": asn_num}


def get_rdap_abuse_contact(ip: str) -> Optional[str]:
    """Fetch abuse contact via RDAP. Free, no key."""
    try:
        r = requests.get(
            f"https://rdap.arin.net/registry/ip/{ip}",
            timeout=15,
            headers={"User-Agent": "ThreatWatch/1.0", "Accept": "application/rdap+json"},
        )
        if r.status_code != 200:
            return None
        data = r.json()
        for entity in data.get("entities", []):
            roles = entity.get("roles", []) or []
            if "abuse" in roles:
                vcard = entity.get("vcardArray", [])
                if len(vcard) > 1:
                    for item in vcard[1]:
                        if len(item) >= 4 and item[0] == "email":
                            return item[3]
        return None
    except Exception as e:
        print(f"[research] RDAP error {ip}: {e}")
        return None


def search_negative_press(provider_name: str) -> list:
    """DuckDuckGo search for negative press mentions. Free, no key."""
    if not provider_name:
        return []
    # New package name is `ddgs`. Old is `duckduckgo_search` (deprecated).
    try:
        from ddgs import DDGS
    except ImportError:
        try:
            from duckduckgo_search import DDGS
        except ImportError:
            print("[research] Neither 'ddgs' nor 'duckduckgo-search' installed; "
                  "run `pip install ddgs` to enable negative-press search")
            return []

    queries = [
        f'"{provider_name}" krebsonsecurity',
        f'"{provider_name}" bulletproof hosting',
        f'"{provider_name}" spamhaus abuse',
        f'"{provider_name}" correctiv',
    ]

    results = []
    seen_urls = set()
    try:
        with DDGS() as ddgs:
            for q in queries:
                try:
                    for hit in ddgs.text(q, max_results=DDG_MAX_RESULTS):
                        url = hit.get("href") or hit.get("url")
                        if not url or url in seen_urls:
                            continue
                        seen_urls.add(url)
                        # Filter to interesting domains only
                        if any(d in url for d in [
                            "krebsonsecurity.com", "correctiv.org",
                            "spamhaus.org", "domaintools.com",
                            "recordedfuture.com", "bleepingcomputer.com",
                            "therecord.media", "wired.com",
                        ]):
                            results.append({
                                "title": hit.get("title", ""),
                                "url":   url,
                                "snippet": (hit.get("body") or "")[:300],
                            })
                except Exception as e:
                    print(f"[research] DDG query failed '{q}': {e}")
    except Exception as e:
        print(f"[research] DDG init failed: {e}")

    return results[:8]


# ── Gemini agent ──────────────────────────────────────────────────────────────

RESEARCH_PROMPT = """\
You are a strict, evidence-based research agent. Gather public information about a hosting provider.

★ THE PROVIDER YOU MUST RESEARCH:
   ASN:           AS{asn}
   Provider name: {name_hint}
   (This name is authoritative — it comes from ProxyCheck / bgpview / RDAP enrichment.
    DO NOT search for "which company owns AS{asn}". Use the name above.
    DO NOT substitute a different company even if Google search suggests one.)

CRITICAL RULES — read carefully:
1. For EACH claim you make, set "source" to the EXACT URL where you found the evidence.
2. ONLY trust the sources listed below per field. The provider's OWN website is
   NEVER a valid source for compliance, public-company, or press claims.
3. If you cannot find evidence from a trusted source, set the value to null.
   It is BETTER to say "unknown" than to use an untrusted source.
4. NEVER fabricate URLs. If you can't find evidence, the source is null.
5. Crypto payment is the ONE exception: provider's own payment-methods page is OK.
6. If the name hint says "(unknown)", DO NOT GUESS the provider name. Set provider_name=null.

TRUSTED SOURCES PER FIELD:
- ISO 27001: must be from an accredited certification body — iso.org, bsigroup.com,
  tuvsud.com, tuv.com, dnv.com, dekra.com, sgs.com, bureauveritas.com,
  intertek.com, lrqa.com, schellman.com, a-lign.com.
- SOC 2: must be from auditor — aicpa.org, deloitte.com, ey.com, kpmg.com, pwc.com,
  bdo.com, rsmus.com, grantthornton.com, schellman.com, a-lign.com.
- FedRAMP: ONLY marketplace.fedramp.gov or fedramp.gov.
- Public company: sec.gov, en.wikipedia.org, nyse.com, nasdaq.com, lse.co.uk.
- Negative press: krebsonsecurity.com, correctiv.org, spamhaus.org, domaintools.com,
  recordedfuture.com, bleepingcomputer.com, therecord.media, wired.com,
  arstechnica.com, theregister.com, darkreading.com, ec.europa.eu, treasury.gov,
  gov.uk.
- Crypto payment: provider's own checkout/billing/payment page is acceptable.

Provider:
- ASN: AS{asn}
- Name hint: {name_hint}
- BGPView data: {bgpview_summary}
- Negative press pre-fetched hits (must verify these are real): {neg_press}

Use google_search to verify and fill the JSON below. Return STRICT JSON.
No markdown, no commentary, no code fences. JUST the JSON object:

{{
  "asn": {asn},
  "provider_name": "...",
  "website": "https://...",
  "country_code": "DE",
  "iso_27001":      {{"certified": true|false|null, "source": "URL or null", "notes": "..."}},
  "soc2":           {{"certified": true|false|null, "type": "1"|"2"|null, "source": "URL or null"}},
  "fedramp":        {{"certified": true|false|null, "level": "moderate"|"high"|null, "source": "URL or null"}},
  "accepts_crypto": {{"value": true|false|null, "coins": [], "source": "URL or null"}},
  "public_company": {{"value": true|false|null, "ticker": "..." or null, "source": "URL or null"}},
  "negative_press": [{{"source_domain": "krebsonsecurity.com", "url": "...", "summary": "..."}}],
  "confidence_overall": 0.0,
  "notes": "..."
}}

Critical: Output ONLY the JSON object. No prose before or after.
Untrusted source → value must be null.
"""


def _strip_code_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines)
    return text.strip()


def _extract_json(text: str) -> dict:
    text = _strip_code_fences(text)
    start = text.find("{")
    end   = text.rfind("}")
    if start < 0 or end < 0:
        raise ValueError(f"No JSON found in: {text[:300]}")
    return json.loads(text[start:end + 1])


def research_with_gemini(asn, name_hint: str = "",
                         bgpview_data: dict = None,
                         neg_press: list = None) -> dict:
    """Call Gemini 2.0 Flash with google_search grounding."""
    if not GEMINI_API_KEY:
        raise RuntimeError("GEMINI_API_KEY not set in .env")

    asn_str = str(asn).upper().replace("AS", "").strip()
    bgpview_summary = json.dumps(bgpview_data or {}, ensure_ascii=False)[:600]
    neg_press_summary = json.dumps(neg_press or [], ensure_ascii=False)[:800]

    prompt = RESEARCH_PROMPT.format(
        asn=asn_str,
        name_hint=name_hint or "(unknown)",
        bgpview_summary=bgpview_summary,
        neg_press=neg_press_summary,
    )

    body = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.1,
            "topP": 0.95,
            "maxOutputTokens": 4096,
        },
    }
    if USE_GEMINI_GROUNDING:
        body["tools"] = [{"google_search": {}}]

    # Up to 3 attempts with exponential backoff for rate limits
    max_attempts = 3
    backoff_seconds = [30, 60, 90]
    r = None
    last_error = None

    for attempt in range(max_attempts):
        try:
            r = requests.post(
                f"{GEMINI_ENDPOINT}?key={GEMINI_API_KEY}",
                json=body,
                timeout=REQUEST_TIMEOUT,
                headers={"Content-Type": "application/json"},
            )

            if r.status_code == 429:
                # Read error body for diagnostics
                try:
                    err_detail = r.json().get("error", {}).get("message", "")[:200]
                except Exception:
                    err_detail = ""
                wait = backoff_seconds[attempt]
                print(f"[research] Gemini 429 (attempt {attempt+1}/{max_attempts}). "
                      f"Detail: {err_detail or '(no message)'} — waiting {wait}s...")
                time.sleep(wait)
                continue

            if r.status_code == 403:
                detail = ""
                try:
                    detail = r.json().get("error", {}).get("message", "")[:300]
                except Exception:
                    pass
                raise RuntimeError(f"Gemini 403 PERMISSION_DENIED — check API key / region. {detail}")

            r.raise_for_status()
            result = r.json()
            last_error = None
            break

        except requests.exceptions.RequestException as e:
            last_error = e
            print(f"[research] Network error attempt {attempt+1}/{max_attempts}: {e}")
            time.sleep(5)

    if last_error is not None and r is None:
        raise RuntimeError(f"Gemini API error after {max_attempts} attempts: {last_error}")

    if r is not None and r.status_code == 429:
        # All retries exhausted on rate limit
        raise RuntimeError(
            "Gemini quota exhausted (429 after 3 retries). "
            "Possible causes: daily 1500 RPD limit reached, "
            "or grounded-search daily 500 limit reached. "
            "Check https://aistudio.google.com/usage"
        )

    try:
        result = r.json()
    except Exception as e:
        raise RuntimeError(f"Gemini response not JSON: {e}")

    try:
        text = result["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError, TypeError):
        raise RuntimeError(f"Unexpected Gemini response shape: {str(result)[:500]}")

    try:
        return _extract_json(text)
    except (ValueError, json.JSONDecodeError) as e:
        raise RuntimeError(f"Invalid JSON from Gemini: {e}\nText: {text[:500]}")


# ── Trusted-source post-validation ────────────────────────────────────────────

def _source_in_trusted(source_url: str, field: str) -> bool:
    """Return True if the URL contains a trusted domain for the given field."""
    if not source_url or not isinstance(source_url, str):
        return False
    url_lower = source_url.lower()
    trusted = TRUSTED_SOURCES.get(field, [])
    return any(d in url_lower for d in trusted)


def _validate_intel(intel: dict) -> dict:
    """
    Enforce trusted-source whitelist. If a positive claim lacks a trusted source,
    rewrite it to null and log the rejection in 'notes'.
    Crypto-payment is exempt (provider's own checkout page is acceptable).
    """
    if not isinstance(intel, dict):
        return intel

    rejected = []

    # iso_27001 / soc2 / fedramp — must have trusted certifier source
    for field in ("iso_27001", "soc2", "fedramp"):
        sec = intel.get(field)
        if isinstance(sec, dict):
            certified = sec.get("certified")
            src = sec.get("source")
            if certified is True and not _source_in_trusted(src, field):
                rejected.append(f"{field}: untrusted source {src!r}")
                sec["certified"] = None
                sec["source"] = None
                sec["notes"] = (sec.get("notes") or "") + " [rejected: untrusted source]"

    # public_company — trusted source required for True
    pc = intel.get("public_company")
    if isinstance(pc, dict):
        if pc.get("value") is True and not _source_in_trusted(pc.get("source"), "public_company"):
            rejected.append(f"public_company: untrusted source {pc.get('source')!r}")
            pc["value"] = None
            pc["ticker"] = None
            pc["source"] = None

    # negative_press — filter list to trusted domains only
    np_list = intel.get("negative_press") or []
    if isinstance(np_list, list):
        kept = []
        for item in np_list:
            if not isinstance(item, dict):
                continue
            url = item.get("url") or ""
            if _source_in_trusted(url, "negative_press"):
                kept.append(item)
            else:
                rejected.append(f"negative_press: untrusted {url!r}")
        intel["negative_press"] = kept

    # accepts_crypto — exempt (provider's own page acceptable)

    # Record validation summary
    if rejected:
        intel["_validation_rejected"] = rejected
        print(f"[research] Validation rejected {len(rejected)} untrusted claims")

    return intel


# ── Main entry point ──────────────────────────────────────────────────────────

def research_provider(asn, name_hint: str = "") -> dict:
    """
    Full research pipeline for one ASN.
    Returns: dict with 'bgpview', 'intel', 'researched_on' keys.
    """
    asn_str = str(asn).upper().replace("AS", "").strip()
    print(f"[research] AS{asn_str}: fetching bgpview.io...")
    bgpview = get_asn_info(asn_str)
    time.sleep(BGPVIEW_RATE_LIMIT_SLEEP)

    hint = name_hint or bgpview.get("name") or bgpview.get("description") or ""
    print(f"[research] AS{asn_str}: searching negative press (DDG) for '{hint}'...")
    neg_press = search_negative_press(hint) if hint else []

    print(f"[research] AS{asn_str}: querying Gemini...")
    try:
        intel = research_with_gemini(asn_str, hint, bgpview, neg_press)
        intel = _validate_intel(intel)   # ★ Untrusted sources rewritten to null
    except Exception as e:
        print(f"[research] AS{asn_str}: Gemini failed: {e}")
        intel = {"error": str(e), "confidence_overall": 0.0}

    return {
        "asn":            int(asn_str),
        "bgpview":        bgpview,
        "neg_press_raw":  neg_press,
        "intel":          intel,
        "researched_on":  datetime.now(timezone.utc).isoformat(),
    }


def batch_research(asns: list, name_hints: dict = None) -> list:
    """
    Research multiple ASNs with Gemini rate limiting.
    name_hints: optional {asn_int_or_str: hint_string}
    """
    name_hints = name_hints or {}
    results = []
    total = len(asns)

    for i, asn in enumerate(asns, 1):
        asn_str = str(asn).upper().replace("AS", "").strip()
        hint = (
                name_hints.get(asn) or
                name_hints.get(asn_str) or
                name_hints.get(f"AS{asn_str}") or
                name_hints.get(int(asn_str) if asn_str.isdigit() else None) or
                ""
        )
        print(f"\n[research] === {i}/{total} → AS{asn_str} ===")
        try:
            r = research_provider(asn_str, hint)
            results.append(r)
        except Exception as e:
            print(f"[research] AS{asn_str} hard failure: {e}")
            results.append({"asn": int(asn_str) if asn_str.isdigit() else None,
                            "error": str(e),
                            "researched_on": datetime.now(timezone.utc).isoformat()})

        if i < total:
            time.sleep(GEMINI_RATE_LIMIT_SLEEP)

    print(f"\n[research] Batch complete: {len(results)} results")
    return results


if __name__ == "__main__":
    # CLI smoke test — only runs when this file is executed DIRECTLY.
    # Streamlit imports the module, so this block is NOT triggered from the app.
    # To run: `python provider_research_agent.py AS24940 [AS16276 ...]`
    import sys
    if len(sys.argv) < 2:
        print("Usage: python provider_research_agent.py AS<number> [AS<number> ...]")
        sys.exit(0)
    asns = [a for a in sys.argv[1:] if a]
    out = batch_research(asns)
    print(json.dumps(out, indent=2, ensure_ascii=False))