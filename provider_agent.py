"""ASN Research Agent — LangGraph workflow.

Collects ASN/hosting-provider signals and asks Gemini for an evidence-based
risk assessment. Google Search grounding is intentionally disabled.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import time
from datetime import datetime, timedelta, timezone
from itertools import islice
from functools import lru_cache
from pathlib import Path
from typing import Any, NotRequired, Optional
from urllib.parse import urlparse

import dns.exception
import dns.resolver
import dns.reversename
import requests
from dotenv import load_dotenv
from langgraph.graph import END, START, StateGraph
from typing_extensions import TypedDict

# Load the .env beside this file, rather than depending on the current shell
# directory. Existing shell variables are left alone only if .env omits them.
ENV_FILE = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=ENV_FILE, override=True)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash").strip()
GEMINI_TIMEOUT_SECONDS = 60

print(f"[config] GEMINI_MODEL={GEMINI_MODEL}")
print(f"[config] .env found={ENV_FILE.is_file()}")

CRYPTO_KEYWORDS = (
    "bitcoin",
    "btc",
    "ethereum",
    "eth",
    "monero",
    "xmr",
    "usdt",
    "tether",
    "litecoin",
    "ltc",
    "cryptocurrency",
    "crypto payment",
    "pay with crypto",
    "digital currency",
)


class ASNState(TypedDict):
    """Compact shared state: each research node adds at most two grouped fields."""

    asn: str
    abused_ip: NotRequired[Optional[str]]

    identity: NotRequired[dict[str, Any]]
    identity_evidence: NotRequired[dict[str, Any]]

    abuse: NotRequired[dict[str, Any]]
    abuse_evidence: NotRequired[dict[str, Any]]

    network: NotRequired[dict[str, Any]]
    network_evidence: NotRequired[dict[str, Any]]

    website: NotRequired[dict[str, Any]]
    website_evidence: NotRequired[dict[str, Any]]

    verdict: NotRequired[dict[str, Any]]



def _asn_num(asn: str) -> str:
    """Normalize ``AS123``/``123`` to a numeric ASN string and validate it."""
    value = str(asn).strip().upper()
    if value.startswith("AS"):
        value = value[2:].strip()
    if not value.isdigit():
        raise ValueError(f"Invalid ASN {asn!r}; expected a number such as AS9009.")
    number = int(value)
    if not 0 <= number <= 4_294_967_295:
        raise ValueError(f"ASN out of range: {asn!r}")
    return str(number)


def _ripe(endpoint: str, **params: Any) -> dict[str, Any]:
    """Call RIPE Stat and return its data object with endpoint-specific errors."""
    url = f"https://stat.ripe.net/data/{endpoint}/data.json"
    response = requests.get(
        url,
        params=params,
        timeout=15,
        headers={"User-Agent": "ThreatWatch/2.0"},
    )
    try:
        response.raise_for_status()
    except requests.RequestException as exc:
        body = response.text[:500]
        raise RuntimeError(f"RIPE Stat {endpoint} request failed: {exc}; body={body}") from exc

    try:
        result = response.json()
    except ValueError as exc:
        raise RuntimeError(f"RIPE Stat {endpoint} returned invalid JSON.") from exc

    data = result.get("data")
    if not isinstance(data, dict):
        raise RuntimeError(f"RIPE Stat {endpoint} returned no data object.")
    return data


def _ripe_evidence(endpoint: str, **params: Any) -> dict[str, Any]:
    """Return a source-labelled, full RIPE Stat API response for LLM review."""
    url = f"https://stat.ripe.net/data/{endpoint}/data.json"
    try:
        response = requests.get(
            url,
            params=params,
            timeout=15,
            headers={"User-Agent": "ThreatWatch/2.0"},
        )
        if not response.ok:
            return {
                "status": "error",
                "source": url,
                "http_status": response.status_code,
                "error": response.text[:1200] or "empty error response",
            }
        try:
            payload = response.json()
        except ValueError:
            return {
                "status": "error",
                "source": url,
                "http_status": response.status_code,
                "error": "Response was not valid JSON",
                "body": response.text[:1200],
            }
        return {
            "status": "ok",
            "source": response.url,
            "http_status": response.status_code,
            "response": payload,  # Complete endpoint response, not just `data`.
        }
    except Exception as exc:
        return {"status": "error", "source": url, "error": str(exc)}


@lru_cache(maxsize=1)
def _rdap_asn_bootstrap() -> dict[str, Any]:
    """Load the official IANA RDAP ASN bootstrap registry once per process."""
    response = requests.get(
        "https://data.iana.org/rdap/asn.json",
        timeout=15,
        headers={"User-Agent": "ThreatWatch/2.0"},
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict) or not isinstance(payload.get("services"), list):
        raise RuntimeError("IANA RDAP ASN bootstrap response has an unexpected format")
    return payload


def _rdap_evidence(asn: str) -> dict[str, Any]:
    """Resolve the authoritative RDAP server via IANA and return the full ASN record."""
    asn_number = int(_asn_num(asn))
    try:
        bootstrap = _rdap_asn_bootstrap()
        for service in bootstrap.get("services", []):
            if not isinstance(service, list) or len(service) != 2:
                continue
            ranges, base_urls = service
            matches = False
            for asn_range in ranges:
                try:
                    if "-" in str(asn_range):
                        first, last = str(asn_range).split("-", 1)
                        matches = int(first) <= asn_number <= int(last)
                    else:
                        matches = asn_number == int(asn_range)
                except (TypeError, ValueError):
                    matches = False
                if matches:
                    break
            if not matches or not base_urls:
                continue

            url = f"{str(base_urls[0]).rstrip('/')}/autnum/{asn_number}"
            response = requests.get(
                url,
                timeout=15,
                headers={"Accept": "application/rdap+json, application/json", "User-Agent": "ThreatWatch/2.0"},
            )
            if not response.ok:
                return {
                    "status": "error",
                    "source": response.url,
                    "http_status": response.status_code,
                    "error": response.text[:1200] or "empty error response",
                }
            return {
                "status": "ok",
                "source": response.url,
                "http_status": response.status_code,
                "response": response.json(),
            }
        return {"status": "error", "source": "IANA RDAP ASN bootstrap", "error": f"No RDAP service found for AS{asn_number}"}
    except Exception as exc:
        return {"status": "error", "source": "IANA RDAP ASN bootstrap", "error": str(exc)}


def _data_from_evidence(evidence: dict[str, Any] | None) -> dict[str, Any]:
    """Get the RIPE Stat `data` object from preserved evidence safely."""
    if not evidence or evidence.get("status") != "ok":
        return {}
    response = evidence.get("response") or {}
    data = response.get("data") if isinstance(response, dict) else None
    return data if isinstance(data, dict) else {}


def _dns_record_status(domain: str, record_type: str) -> tuple[Optional[bool], str]:
    """Return (exists, status); DNS failures are not treated as missing records."""
    try:
        answer = dns.resolver.resolve(domain, record_type, lifetime=5)
        return bool(answer), "found" if answer else "no_answer"
    except dns.resolver.NXDOMAIN:
        return False, "nxdomain"
    except dns.resolver.NoAnswer:
        return False, "no_record"
    except (dns.exception.Timeout, dns.resolver.NoNameservers):
        return None, "lookup_error"
    except Exception as exc:
        print(f"[dns] {record_type} lookup for {domain} failed: {exc}")
        return None, "lookup_error"


def _domain_has_address(domain: str) -> tuple[Optional[bool], str]:
    """Check A and AAAA; distinguish a definite lack of address records from errors."""
    a_value, a_status = _dns_record_status(domain, "A")
    aaaa_value, aaaa_status = _dns_record_status(domain, "AAAA")

    if a_value is True or aaaa_value is True:
        return True, "resolved"
    if a_value is False and aaaa_value is False:
        return False, "no_a_or_aaaa_record"
    return None, "lookup_error"


def _normalize_website_url(value: Optional[str]) -> Optional[str]:
    if not value or not str(value).strip():
        return None
    url = str(value).strip()
    if not urlparse(url).scheme:
        url = f"https://{url}"
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username or parsed.password:
        return None
    return url


def _rdap_website_url(evidence: dict[str, Any]) -> Optional[str]:
    """Extract a provider homepage candidate from a successful RDAP response."""
    if not isinstance(evidence, dict) or evidence.get("status") != "ok":
        return None

    record = evidence.get("response")
    if not isinstance(record, dict):
        return None

    # Some RDAP servers expose URLs directly on the record or its entities.
    candidates: list[Any] = []
    for key in ("website", "website_url", "homepage", "homePage", "url"):
        if record.get(key):
            candidates.append(record[key])

    entities = record.get("entities", [])
    if isinstance(entities, list):
        for entity in entities:
            if not isinstance(entity, dict):
                continue
            for key in ("website", "website_url", "homepage", "homePage", "url"):
                if entity.get(key):
                    candidates.append(entity[key])

            # vCard URL fields are a standard way contact data may expose a URL.
            vcard = entity.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
                for prop in vcard[1]:
                    if (
                            isinstance(prop, list)
                            and len(prop) >= 4
                            and str(prop[0]).lower() == "url"
                    ):
                        candidates.append(prop[3])

    for candidate in candidates:
        if isinstance(candidate, str):
            normalized = _normalize_website_url(candidate)
            if normalized:
                return normalized

    return None


def setup_node(state: ASNState) -> dict[str, Any]:
    """Collect provider identity and raw registration evidence.

    Adds exactly two state fields: ``identity`` and ``identity_evidence``.
    """
    asn = _asn_num(state["asn"])
    identity: dict[str, Any] = {
        "provider_name": None,
        "country": None,
        "website_url": None,
        "website_url_source": None,
    }
    evidence: dict[str, Any] = {
        "bgpview": {"status": "not_checked"},
        "rdap": {"status": "not_checked"},
        "whois": {"status": "not_checked"},
    }

    # BGPView is an optional source for basic identity hints.
    try:
        response = requests.get(
            f"https://api.bgpview.io/asn/{asn}",
            timeout=10,
            headers={"User-Agent": "ThreatWatch/2.0"},
        )
        response.raise_for_status()
        bgp_payload = response.json()
        data = bgp_payload.get("data", {})
        identity["provider_name"] = data.get("name") or data.get("description_short")
        identity["country"] = data.get("country_code")
        identity["website_url"] = _normalize_website_url(data.get("website"))
        if identity["website_url"]:
            identity["website_url_source"] = "bgpview"
        evidence["bgpview"] = {
            "status": "ok",
            "source": response.url,
            "http_status": response.status_code,
            "fields": {
                "name": data.get("name"),
                "description_short": data.get("description_short"),
                "country_code": data.get("country_code"),
                "website": data.get("website"),
            },
        }
        print(f"[setup] BGPView AS{asn}: {identity['provider_name']} ({identity['country']})")
    except Exception as exc:
        evidence["bgpview"] = {
            "status": "error",
            "source": f"https://api.bgpview.io/asn/{asn}",
            "error": str(exc),
        }
        print(f"[setup] BGPView unavailable for AS{asn}: {exc}; continuing with registry sources")

    # Full registry responses are kept together under identity_evidence.
    evidence["whois"] = _ripe_evidence("whois", resource=f"AS{asn}")
    evidence["rdap"] = _rdap_evidence(asn)
    whois = _data_from_evidence(evidence["whois"])

    for record in whois.get("records", []):
        for item in record:
            key = str(item.get("key", "")).strip().lower()
            value = str(item.get("value", "")).strip()
            if not value:
                continue
            if key in {"org-name", "descr", "as-name", "owner", "netname"} and not identity["provider_name"]:
                identity["provider_name"] = value
            elif key == "country" and not identity["country"]:
                identity["country"] = value.upper()[:2]
            elif key in {"org-web", "website", "www", "url", "web", "homepage"} and not identity["website_url"]:
                candidate = _normalize_website_url(value)
                if candidate:
                    identity["website_url"] = candidate
                    identity["website_url_source"] = "ripe_whois"

    if not identity["website_url"]:
        rdap_url = _rdap_website_url(evidence["rdap"])
        if rdap_url:
            identity["website_url"] = rdap_url
            identity["website_url_source"] = "rdap_homepage"

    rdap_record = evidence["rdap"].get("response", {}) if evidence["rdap"].get("status") == "ok" else {}
    if not identity["provider_name"] and isinstance(rdap_record, dict):
        identity["provider_name"] = rdap_record.get("name") or rdap_record.get("handle")
    if not identity["country"] and isinstance(rdap_record, dict):
        identity["country"] = rdap_record.get("country")

    print(
        f"[setup] AS{asn}: provider={identity['provider_name']!r}, country={identity['country']!r}; "
        f"RDAP={evidence['rdap'].get('status')}, WHOIS={evidence['whois'].get('status')}"
    )
    return {"identity": identity, "identity_evidence": evidence}



def abuse_mailbox_node(state: ASNState) -> dict[str, Any]:
    """Collect abuse contact and DNS checks into two grouped state fields."""
    asn = _asn_num(state["asn"])
    abuse: dict[str, Any] = {
        "email": None,
        "contact_status": "not_checked",
        "domain_resolves": None,
        "domain_status": "not_checked",
        "mx_valid": None,
        "mx_status": "not_checked",
    }
    source_evidence = _ripe_evidence("abuse-contact-finder", resource=f"AS{asn}")
    evidence = {"ripe_abuse_contact_finder": source_evidence}

    if source_evidence.get("status") != "ok":
        abuse["contact_status"] = "lookup_error"
        print(f"[abuse] AS{asn}: source lookup failed: {source_evidence.get('error')}")
        return {"abuse": abuse, "abuse_evidence": evidence}

    contacts = _data_from_evidence(source_evidence).get("abuse_contacts", [])
    if not contacts:
        abuse["contact_status"] = "not_found"
        print(f"[abuse] AS{asn}: no abuse contact found")
        return {"abuse": abuse, "abuse_evidence": evidence}

    email = str(contacts[0]).strip()
    if "@" not in email or not email.rsplit("@", 1)[-1]:
        abuse["contact_status"] = "invalid_contact"
        print(f"[abuse] AS{asn}: invalid abuse contact format")
        return {"abuse": abuse, "abuse_evidence": evidence}

    domain = email.rsplit("@", 1)[-1].strip().rstrip(".")
    abuse["email"] = email
    abuse["contact_status"] = "found"
    abuse["domain_resolves"], abuse["domain_status"] = _domain_has_address(domain)
    abuse["mx_valid"], abuse["mx_status"] = _dns_record_status(domain, "MX")
    print(f"[abuse] AS{asn}: {email}; domain={abuse['domain_status']}, MX={abuse['mx_status']}")
    return {"abuse": abuse, "abuse_evidence": evidence}



def _parse_datetime(value: str) -> Optional[datetime]:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def asn_metadata_node(state: ASNState) -> dict[str, Any]:
    """Collect routing, target-prefix RPKI, prefix history, ASN age and PTR evidence.

    Adds exactly two state fields: ``network`` and ``network_evidence``.
    """
    asn = _asn_num(state["asn"])
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(days=30)
    identity_evidence = state.get("identity_evidence") or {}

    network: dict[str, Any] = {
        "asn_age_years": None,
        "prefix_count": None,
        "prefix_churn_score": None,
        "prefix_churn_status": "not_checked",
        "rpki_target_prefix": None,
        "sample_ptr_records": [],
    }
    evidence: dict[str, Any] = {
        "routing_status": {"status": "not_checked"},
        "announced_prefixes": {"status": "not_checked"},
        "announced_prefixes_30d": {"status": "not_checked"},
        "rpki_target_prefix": [],
    }

    routing_evidence = _ripe_evidence("routing-status", resource=f"AS{asn}")
    evidence["routing_status"] = routing_evidence

    # ASN age is derived from the WHOIS evidence collected by setup_node.
    whois_evidence = identity_evidence.get("whois") or {}
    whois = _data_from_evidence(whois_evidence)
    for record in whois.get("records", []):
        found_age = False
        for item in record:
            if str(item.get("key", "")).lower() not in {"created", "regdate"}:
                continue
            created = _parse_datetime(str(item.get("value", ""))[:25])
            if created:
                network["asn_age_years"] = round((now - created).days / 365.25, 1)
                found_age = True
                break
        if found_age:
            break

    # Fetch the current announced-prefix list to locate the abused IP's real prefix.
    current_prefix_evidence = _ripe_evidence("announced-prefixes", resource=f"AS{asn}")
    evidence["announced_prefixes"] = current_prefix_evidence
    current_prefix_data = _data_from_evidence(current_prefix_evidence)
    current_prefix_rows = current_prefix_data.get("prefixes", [])
    prefixes: list[str] = [
        str(row["prefix"])
        for row in current_prefix_rows
        if isinstance(row, dict) and row.get("prefix")
    ]
    network["prefix_count"] = len(prefixes) if current_prefix_evidence.get("status") == "ok" else None

    # Churn is computed from the existing RIPE announced-prefixes endpoint over 30 days.
    try:
        recent_evidence = _ripe_evidence(
            "announced-prefixes",
            resource=f"AS{asn}",
            starttime=int(window_start.timestamp()),
            endtime=int(now.timestamp()),
        )
        evidence["announced_prefixes_30d"] = recent_evidence
        if recent_evidence.get("status") != "ok":
            raise RuntimeError(recent_evidence.get("error", "RIPE lookup failed"))
        recent_rows = _data_from_evidence(recent_evidence).get("prefixes", [])
        recent_prefixes = []
        for row in recent_rows:
            prefix = row.get("prefix") if isinstance(row, dict) else None
            if not prefix:
                continue
            recent_prefixes.append(row)
        if network["prefix_count"]:
            recent_set = {row.get("prefix") for row in recent_prefixes}
            # A transparent activity ratio: recently observed prefixes divided by
            # the current announced set; this is an indicator, not proof of churn.
            network["prefix_churn_score"] = round(
                len(recent_set.intersection(set(prefixes))) / len(prefixes), 2
            )
            network["prefix_churn_status"] = "estimated_from_30d_observed_prefixes"
        elif not prefixes and current_prefix_evidence.get("status") == "ok":
            network["prefix_churn_score"] = 0.0
            network["prefix_churn_status"] = "no_current_prefixes"
        else:
            network["prefix_churn_status"] = "no_current_prefix_count"
    except Exception as exc:
        network["prefix_churn_status"] = "lookup_error"
        evidence["announced_prefixes_30d"].setdefault("error", str(exc))
        print(f"[metadata] AS{asn}: 30-day prefix-history lookup failed: {exc}")

    # RPKI is checked only for the prefix containing the supplied AbuseIPDB IP.
    target_ip_value = state.get("abused_ip")
    if not target_ip_value:
        evidence["rpki_target_prefix"] = [{
            "status": "not_checked",
            "reason": "No abused IP was supplied; unrelated prefixes were not checked.",
        }]
    else:
        try:
            target_ip = ipaddress.ip_address(str(target_ip_value).strip())
            matching_networks = []
            for prefix in prefixes:
                try:
                    candidate = ipaddress.ip_network(prefix, strict=False)
                    if candidate.version == target_ip.version and target_ip in candidate:
                        matching_networks.append(candidate)
                except ValueError:
                    continue

            if not matching_networks:
                evidence["rpki_target_prefix"] = [{
                    "status": "not_checked",
                    "abused_ip": str(target_ip),
                    "reason": "No current announced prefix from the existing RIPE result contains this IP.",
                }]
            else:
                target_network = max(matching_networks, key=lambda item: item.prefixlen)
                target_prefix = str(target_network)
                network["rpki_target_prefix"] = target_prefix
                rpki_result = _ripe_evidence(
                    "rpki-validation",
                    resource=f"AS{asn}",
                    prefix=target_prefix,
                )
                evidence["rpki_target_prefix"] = [{
                    "abused_ip": str(target_ip),
                    "prefix": target_prefix,
                    **rpki_result,
                }]
                print(f"[metadata] AS{asn}: RPKI target is {target_prefix} for {target_ip}; source status={rpki_result.get('status')}")
        except ValueError as exc:
            evidence["rpki_target_prefix"] = [{
                "status": "not_checked",
                "abused_ip": str(target_ip_value),
                "reason": f"Invalid abused IP address: {exc}",
            }]

    # Keep the existing PTR sample check; it is supporting context, not an RPKI substitute.
    if prefixes:
        try:
            sample_network = ipaddress.ip_network(prefixes[0], strict=False)
            sample_ips = list(islice(sample_network.hosts(), 5))
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 4
            for ip in sample_ips:
                reverse_name = dns.reversename.from_address(str(ip))
                try:
                    answer = resolver.resolve(reverse_name, "PTR")
                    network["sample_ptr_records"].append(str(answer[0]).rstrip("."))
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    network["sample_ptr_records"].append("no-ptr")
                except (dns.exception.Timeout, dns.resolver.NoNameservers):
                    network["sample_ptr_records"].append("lookup-error")
                except Exception as exc:
                    print(f"[metadata] PTR lookup for {ip} failed: {exc}")
                    network["sample_ptr_records"].append("lookup-error")
        except Exception as exc:
            print(f"[metadata] AS{asn}: PTR sampling failed: {exc}")

    print(
        f"[metadata] AS{asn}: prefixes={network['prefix_count']}, "
        f"churn={network['prefix_churn_score']}, "
        f"target_prefix={network['rpki_target_prefix']}, "
        f"PTR sample={network['sample_ptr_records']}"
    )
    return {"network": network, "network_evidence": evidence}



def crypto_check_node(state: ASNState) -> dict[str, Any]:
    """Check a known website or a clearly labelled candidate from the abuse domain."""
    identity = state.get("identity") or {}
    abuse = state.get("abuse") or {}
    url = _normalize_website_url(identity.get("website_url"))
    source = identity.get("website_url_source")

    website: dict[str, Any] = {
        "url": url,
        "url_source": source,
        "accepts_crypto": None,
        "crypto_check_status": "not_checked",
    }
    evidence: dict[str, Any] = {"status": "not_checked"}

    if not url:
        email = str(abuse.get("email") or "").strip()
        if "@" in email and abuse.get("domain_resolves") is True:
            domain = email.rsplit("@", 1)[1].strip().rstrip(".")
            if domain:
                url = f"https://{domain}"
                source = "inferred_from_abuse_email_domain"
                website["url"] = url
                website["url_source"] = source
                print(f"[crypto] trying inferred candidate {url}; not confirmed as official website")

    if not url:
        website["crypto_check_status"] = "no_website_url"
        evidence = {"status": "not_checked", "reason": "No usable provider website URL or candidate domain."}
        print("[crypto] no usable website URL available")
        return {"website": website, "website_evidence": evidence}

    try:
        response = requests.get(
            url,
            timeout=12,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; ThreatWatch/2.0)"},
        )
        response.raise_for_status()
        page_text = response.text.lower()
        hits = [keyword for keyword in CRYPTO_KEYWORDS if keyword in page_text]
        website["accepts_crypto"] = bool(hits)
        website["crypto_check_status"] = "completed"
        evidence = {
            "status": "completed",
            "requested_url": url,
            "final_url": response.url,
            "http_status": response.status_code,
            "url_source": source or "source_unspecified",
            "matched_keywords": hits,
            "note": "Keyword matches are not proof that the provider accepts cryptocurrency payments.",
        }
        print(f"[crypto] {url}: keyword_match={bool(hits)}; source={source}")
    except Exception as exc:
        website["crypto_check_status"] = "lookup_error"
        evidence = {
            "status": "error",
            "requested_url": url,
            "url_source": source or "source_unspecified",
            "error": str(exc),
        }
        print(f"[crypto] fetch error {url}: {exc}")

    return {"website": website, "website_evidence": evidence}




SYSTEM_PROMPT = """\
You are a threat-intelligence analyst assessing ASN and hosting-provider risk.

The user message contains compact grouped fields:
- `identity`: provider name, country and any website URL found.
- `source_evidence.identity`: raw/labelled BGPView, RDAP and RIPE WHOIS outputs.
- `abuse`: abuse contact and DNS/MX check outcomes.
- `source_evidence.abuse`: raw RIPE abuse-contact-finder response.
- `network`: ASN age, prefix count/churn, target prefix and PTR sample.
- `source_evidence.network`: raw RIPE routing-status, announced-prefix and target-prefix RPKI responses.
- `website`: website candidate and keyword-check outcomes.
- `source_evidence.website`: fetch status, final URL and matching keyword list.

Interpret the source responses directly. Compare provider and registered organization names, handles,
and entities across sources. Different names may reflect branding, subsidiaries, upstream providers,
resellers or stale records; do not assert legal ownership without evidence. A website URL inferred
from an abuse email domain is only a candidate, not confirmed as the official provider website.
Distinguish negative findings from missing data and technical query failures.

RPKI requirements:
- `source_evidence.network.rpki_target_prefix` contains at most one entry: the RPKI result for the prefix
  containing `abused_ip`, found locally from the existing RIPE announced-prefixes result.
- Only that abused-IP prefix is relevant. Do not invent results for unrelated prefixes.
- Assess the raw RIPE RPKI response yourself. Do not rely on a precomputed `rpki_valid` boolean.
- In `rpki_prefix_assessment`, return one object only if an actual prefix was checked; otherwise return an empty array.
- Each object must include `prefix`, `observed_status`, `assessment`, and `reason`.
- `assessment` must be `normal`, `concern`, or `unknown`. A valid status is normally normal; explicit invalid ASN/origin or invalid prefix length is a technical concern; no-ROA, unknown status, or query errors are unknown, not proof of malicious intent.
- Consider the assessment in the final score and explanation alongside all other evidence.

Do not infer malicious intent from country, ASN size, cryptocurrency keywords, or absent PTR records alone.
Treat lookup errors and missing values as unknown. A missing MX record alone does not prove an email domain
cannot receive mail. Prefix churn is an estimate and is not proof of malicious address rotation. A large
prefix count is neutral by itself. Use `bulletproof` only when evidence strongly supports abuse-friendly
infrastructure, not merely because the network provides ordinary hosting.

Give a cautious risk score from 0.0 to 10.0:
0-2 trusted; 3-4 low_risk; 5-6 medium_risk; 7-8 high_risk; 9-10 bulletproof.

Return ONLY a valid JSON object with this schema:
{
  "risk_score": 0.0,
  "verdict": "trusted|low_risk|medium_risk|high_risk|bulletproof",
  "risk_factors": ["concise evidence-based factor"],
  "positive_factors": ["concise positive factor"],
  "rpki_prefix_assessment": [
    {
      "prefix": "exact abused-IP prefix from source evidence",
      "observed_status": "exact source status, unknown, or lookup_error",
      "assessment": "normal|concern|unknown",
      "reason": "why this prefix received this assessment"
    }
  ],
  "summary": "A concise 5-7 sentence analysis."
}
"""



def _extract_json_text(response_data: dict[str, Any]) -> str:
    """Extract actual text parts from the first Gemini candidate safely."""
    candidates = response_data.get("candidates") or []
    if not candidates:
        feedback = response_data.get("promptFeedback")
        raise RuntimeError(f"Gemini returned no candidates; promptFeedback={feedback!r}")

    candidate = candidates[0]
    content = candidate.get("content") or {}
    parts = content.get("parts") or []
    text_parts = [
        part["text"]
        for part in parts
        if isinstance(part, dict)
           and isinstance(part.get("text"), str)
           and not part.get("thought", False)
    ]
    result = "\n".join(text_parts).strip()

    if not result:
        raise RuntimeError(
            "Gemini returned no final text. "
            f"finishReason={candidate.get('finishReason')!r}; "
            f"finishMessage={candidate.get('finishMessage')!r}; "
            f"promptFeedback={response_data.get('promptFeedback')!r}"
        )
    return result


def _parse_verdict(raw_text: str) -> dict[str, Any]:
    """Parse and lightly validate the JSON generated by Gemini."""
    text = raw_text.strip()
    text = re.sub(r"^\s*```(?:json)?\s*", "", text, count=1, flags=re.IGNORECASE)
    text = re.sub(r"\s*```\s*$", "", text, count=1)

    try:
        verdict = json.loads(text)
    except json.JSONDecodeError:
        from json_repair import repair_json

        repaired = repair_json(text)
        if not isinstance(repaired, str) or not repaired.strip():
            raise RuntimeError(f"Gemini response was not valid JSON: {text[:800]!r}")
        try:
            verdict = json.loads(repaired)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Could not parse Gemini JSON: {text[:800]!r}") from exc

    if not isinstance(verdict, dict):
        raise RuntimeError("Gemini JSON response must be an object.")

    try:
        score = float(verdict["risk_score"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("Gemini JSON is missing a numeric risk_score.") from exc
    if not 0.0 <= score <= 10.0:
        raise RuntimeError(f"Gemini risk_score is outside 0–10: {score}")

    allowed_verdicts = {"trusted", "low_risk", "medium_risk", "high_risk", "bulletproof"}
    label = verdict.get("verdict")
    if label not in allowed_verdicts:
        raise RuntimeError(f"Gemini returned an unsupported verdict: {label!r}")

    risk_factors = verdict.get("risk_factors", [])
    positive_factors = verdict.get("positive_factors", [])
    rpki_assessment = verdict.get("rpki_prefix_assessment", [])
    summary = verdict.get("summary", "")
    if not isinstance(risk_factors, list) or not isinstance(positive_factors, list):
        raise RuntimeError("Gemini risk_factors and positive_factors must be arrays.")
    if not isinstance(rpki_assessment, list):
        raise RuntimeError("Gemini rpki_prefix_assessment must be an array.")
    if not all(isinstance(item, dict) for item in rpki_assessment):
        raise RuntimeError("Each rpki_prefix_assessment entry must be an object.")
    if not isinstance(summary, str):
        raise RuntimeError("Gemini summary must be a string.")

    verdict["risk_score"] = score
    verdict["risk_factors"] = risk_factors
    verdict["positive_factors"] = positive_factors
    verdict["rpki_prefix_assessment"] = rpki_assessment
    verdict["summary"] = summary
    return verdict


def llm_evaluate_node(state: ASNState) -> dict[str, Any]:
    """Send the grouped evidence to Gemini and return one final verdict."""
    payload = {
        "asn": state.get("asn"),
        "abused_ip": state.get("abused_ip"),
        "identity": state.get("identity", {}),
        "abuse": state.get("abuse", {}),
        "network": state.get("network", {}),
        "website": state.get("website", {}),
        "source_evidence": {
            "identity": state.get("identity_evidence", {}),
            "abuse": state.get("abuse_evidence", {}),
            "network": state.get("network_evidence", {}),
            "website": state.get("website_evidence", {}),
        },
    }
    print(f"[llm] querying {GEMINI_MODEL} for AS{state.get('asn')}...")

    if not GEMINI_API_KEY:
        return {"verdict": {
            "error": "GEMINI_API_KEY is empty. Check the .env file beside provider_agent.py.",
            "risk_score": None,
            "verdict": "unknown",
            "risk_factors": [],
            "positive_factors": [],
            "summary": "No model evaluation was performed because the API key is missing.",
        }}

    request_body = {
        "system_instruction": {"parts": [{"text": SYSTEM_PROMPT}]},
        "contents": [{
            "role": "user",
            "parts": [{"text": "Evaluate this ASN/provider evidence:\n\n" + json.dumps(payload, indent=2, ensure_ascii=False)}],
        }],
        "generationConfig": {
            "maxOutputTokens": 4096,
            "responseMimeType": "application/json",
            "thinkingConfig": {"thinkingLevel": "low"},
        },
        # Google Search is intentionally disabled.
    }
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"

    try:
        response = requests.post(
            url,
            headers={"Content-Type": "application/json", "x-goog-api-key": GEMINI_API_KEY},
            json=request_body,
            timeout=GEMINI_TIMEOUT_SECONDS,
        )
        if not response.ok:
            try:
                error_body: Any = response.json()
            except ValueError:
                error_body = response.text[:1500] or "<empty response body>"
            raise RuntimeError(f"Gemini API HTTP {response.status_code}: {error_body}")

        try:
            response_data = response.json()
        except ValueError as exc:
            raise RuntimeError(
                "Gemini API returned an empty or invalid JSON response; "
                f"HTTP={response.status_code}, body={response.text[:1000]!r}"
            ) from exc

        raw_text = _extract_json_text(response_data)
        verdict = _parse_verdict(raw_text)
        print(
            f"[llm] AS{state.get('asn')}: score={verdict['risk_score']} "
            f"verdict={verdict['verdict']}"
        )
        return {"verdict": verdict}
    except Exception as exc:
        message = str(exc)
        print(f"[llm] error: {message}")
        return {"verdict": {
            "error": message,
            "risk_score": None,
            "verdict": "unknown",
            "risk_factors": [],
            "positive_factors": [],
            "rpki_prefix_assessment": [],
            "summary": "The model evaluation did not complete; no risk verdict was produced.",
        }}



def build_graph():
    workflow = StateGraph(ASNState)
    workflow.add_node("setup", setup_node)
    workflow.add_node("abuse_mailbox", abuse_mailbox_node)
    workflow.add_node("asn_metadata", asn_metadata_node)
    workflow.add_node("crypto_check", crypto_check_node)
    workflow.add_node("llm_evaluate", llm_evaluate_node)

    workflow.add_edge(START, "setup")

    # These research nodes are independent and can execute in parallel.
    workflow.add_edge("setup", "abuse_mailbox")
    workflow.add_edge("setup", "asn_metadata")
    workflow.add_edge(["setup", "abuse_mailbox"], "crypto_check")

    # The LLM waits until all three research nodes have completed.
    workflow.add_edge(
        ["abuse_mailbox", "asn_metadata", "crypto_check"],
        "llm_evaluate",
    )
    workflow.add_edge("llm_evaluate", END)
    return workflow.compile()


_graph = build_graph()


def research_asn(asn: str, abused_ip: Optional[str] = None) -> dict[str, Any]:
    """Run ASN/provider research, checking RPKI only for the supplied abused IP's prefix."""
    asn_clean = _asn_num(asn)
    ip_clean: Optional[str] = None
    if abused_ip is not None and str(abused_ip).strip():
        ip_clean = str(ipaddress.ip_address(str(abused_ip).strip()))

    print("\n" + "=" * 50)
    print(f"[research] Starting ASN research for AS{asn_clean}")
    if ip_clean:
        print(f"[research] Abuse IP target: {ip_clean}")
    else:
        print("[research] No abuse IP supplied; target-prefix RPKI check will be skipped")
    print("=" * 50)

    result = _graph.invoke({"asn": asn_clean, "abused_ip": ip_clean})
    verdict = result.get("verdict") or {}
    label = verdict.get("verdict", "unknown")
    score = verdict.get("risk_score", "?")
    print(f"[research] AS{asn_clean} complete → {label} (score: {score})")
    return result
