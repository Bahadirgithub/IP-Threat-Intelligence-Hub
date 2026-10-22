"""ASN/hosting-provider research workflow with focused source lookups.

The workflow retains source-backed findings and compacts repetitive registry data
when collecting it. Risk interpretation is left to the single Gemini evaluation node.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, NotRequired, Optional
from urllib.parse import urlparse

import dns.resolver
import dns.reversename
import requests
from dotenv import load_dotenv
from langgraph.graph import END, START, StateGraph
from typing_extensions import TypedDict


ENV_FILE = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=ENV_FILE, override=True)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash").strip()
HTTP_TIMEOUT = 15
GEMINI_TIMEOUT = 60
USER_AGENT = "ThreatWatch/2.0"
WHOIS_WEBSITE_KEYS = {"org-web", "website", "www", "url", "web", "homepage"}
RDAP_WEBSITE_KEYS = ("website", "website_url", "homepage", "homePage", "url")

print(f"[config] GEMINI_MODEL={GEMINI_MODEL}")
print(f"[config] .env found={ENV_FILE.is_file()}")


# Shared workflow state: inputs, raw source groups, and the final model result.
class ASNState(TypedDict):
    """Minimal state: inputs, grouped source findings, and final verdict."""

    asn: str
    abused_ip: NotRequired[Optional[str]]
    identity: NotRequired[dict[str, Any]]
    abuse: NotRequired[dict[str, Any]]
    network: NotRequired[dict[str, Any]]
    website: NotRequired[dict[str, Any]]
    verdict: NotRequired[dict[str, Any]]


# --- Shared HTTP, RIPE, and RDAP helpers -------------------------------------


def _asn_num(value: str) -> str:
    value = str(value).strip().upper()
    if value.startswith("AS"):
        value = value[2:].strip()
    if not value.isdigit():
        raise ValueError(f"Invalid ASN: {value!r}")
    number = int(value)
    if not 0 <= number <= 4_294_967_295:
        raise ValueError(f"ASN out of range: {value!r}")
    return str(number)


def _request_json(
        url: str,
        params: Optional[dict[str, Any]] = None,
        headers: Optional[dict[str, str]] = None,
) -> dict[str, Any]:
    """Keep the complete HTTP JSON response, with transport metadata/errors."""
    try:
        response = requests.get(
            url,
            params=params,
            timeout=HTTP_TIMEOUT,
            headers=headers or {"User-Agent": USER_AGENT},
        )
        try:
            body: Any = response.json()
        except ValueError:
            body = response.text
        result: dict[str, Any] = {
            "source": response.url,
            "http_status": response.status_code,
            "response": body,
        }
        if not response.ok:
            result["request_error"] = f"HTTP {response.status_code}"
        return result
    except Exception as exc:
        return {"source": url, "request_error": str(exc)}


def _ripe_raw(endpoint: str, **params: Any) -> dict[str, Any]:
    """Return the complete RIPE Stat API response, not a derived summary."""
    return _request_json(
        f"https://stat.ripe.net/data/{endpoint}/data.json",
        params=params,
        headers={"User-Agent": USER_AGENT},
    )


@lru_cache(maxsize=1)
def _iana_rdap_bootstrap() -> dict[str, Any]:
    response = requests.get(
        "https://data.iana.org/rdap/asn.json",
        timeout=HTTP_TIMEOUT,
        headers={"User-Agent": USER_AGENT},
    )
    response.raise_for_status()
    return response.json()


def _asn_range_contains(asn_number: int, value: Any) -> bool:
    """Check whether an IANA ASN range entry contains this ASN."""
    try:
        parts = str(value).split("-", 1)
        first = int(parts[0])
        last = int(parts[1]) if len(parts) == 2 else first
        return first <= asn_number <= last
    except (TypeError, ValueError):
        return False


def _rdap_raw(asn: str) -> dict[str, Any]:
    """Return the authoritative RDAP ASN record, not the large routing bootstrap."""
    number = int(_asn_num(asn))
    bootstrap_source = "https://data.iana.org/rdap/asn.json"
    try:
        for service in _as_list(_iana_rdap_bootstrap().get("services")):
            if not isinstance(service, list) or len(service) != 2:
                continue
            ranges, base_urls = service
            if not base_urls or not any(_asn_range_contains(number, item) for item in ranges):
                continue
            record_url = f"{str(base_urls[0]).rstrip('/')}/autnum/{number}"
            record = _request_json(
                record_url,
                headers={"Accept": "application/rdap+json, application/json", "User-Agent": USER_AGENT},
            )
            return {"iana_bootstrap_source": bootstrap_source, "rdap_asn_record": record}
        return {
            "iana_bootstrap_source": bootstrap_source,
            "rdap_asn_record": {"request_error": f"No RDAP service found for AS{number}"},
        }
    except Exception as exc:
        return {"iana_bootstrap_source": bootstrap_source, "request_error": str(exc)}


@lru_cache(maxsize=2)
def _iana_ip_rdap_bootstrap(version: int) -> dict[str, Any]:
    """Cache IANA's authoritative RDAP bootstrap for IPv4 or IPv6."""
    if version not in (4, 6):
        raise ValueError(f"Unsupported IP version: {version}")
    url = f"https://data.iana.org/rdap/ipv{version}.json"
    response = requests.get(
        url,
        timeout=HTTP_TIMEOUT,
        headers={"User-Agent": USER_AGENT},
    )
    response.raise_for_status()
    return response.json()


def _rdap_ip_raw(ip_value: str) -> dict[str, Any]:
    """Query the authoritative RDAP service for one IP, using IANA bootstrap."""
    try:
        address = ipaddress.ip_address(ip_value)
        bootstrap_source = f"https://data.iana.org/rdap/ipv{address.version}.json"
        bootstrap = _iana_ip_rdap_bootstrap(address.version)
        matches: list[tuple[int, str]] = []
        for service in _as_list(bootstrap.get("services")):
            if not isinstance(service, list) or len(service) != 2:
                continue
            prefixes, base_urls = service
            if not isinstance(prefixes, list) or not isinstance(base_urls, list) or not base_urls:
                continue
            for prefix in prefixes:
                try:
                    network = ipaddress.ip_network(str(prefix), strict=False)
                except ValueError:
                    continue
                if address.version == network.version and address in network:
                    matches.append((network.prefixlen, str(base_urls[0]).rstrip("/")))
        if not matches:
            return {
                "iana_bootstrap_source": bootstrap_source,
                "rdap_ip_record": {"request_error": f"No RDAP service found for {address}"},
            }
        # Prefer the most-specific matching bootstrap prefix.
        _, base_url = max(matches, key=lambda item: item[0])
        record = _request_json(
            f"{base_url}/ip/{address}",
            headers={"Accept": "application/rdap+json, application/json", "User-Agent": USER_AGENT},
        )
        return {"iana_bootstrap_source": bootstrap_source, "rdap_ip_record": record}
    except Exception as exc:
        return {
            "iana_bootstrap_source": None,
            "rdap_ip_record": {"request_error": str(exc)},
        }


def _compact_ip_rdap(wrapper: dict[str, Any]) -> dict[str, Any]:
    """Keep useful RDAP IP-registration fields, excluding bulky links and DNS delegation data."""
    wrapper = _as_dict(wrapper)
    raw = _as_dict(wrapper.get("rdap_ip_record"))
    response = _as_dict(raw.get("response"))
    result: dict[str, Any] = {}
    if wrapper.get("iana_bootstrap_source"):
        result["iana_bootstrap_source"] = wrapper["iana_bootstrap_source"]
    record_summary: dict[str, Any] = {}
    for key in ("source", "http_status", "request_error"):
        if raw.get(key) is not None:
            record_summary[key] = raw[key]

    for key in (
            "objectClassName", "handle", "name", "startAddress", "endAddress",
            "ipVersion", "type", "country", "parentHandle", "status", "cidr0_cidrs",
    ):
        if response.get(key) not in (None, [], ""):
            record_summary[key] = response[key]

    events = []
    for event in _as_list(response.get("events")):
        event = _as_dict(event)
        action = str(event.get("eventAction", "")).lower()
        if action in {"registration", "last changed", "last update of rdap database"}:
            item = {
                key: event[key]
                for key in ("eventAction", "eventDate")
                if event.get(key) is not None
            }
            if item:
                events.append(item)
    if events:
        record_summary["events"] = events

    # Extract registration organization and only relevant public abuse contacts.
    entities_out: list[dict[str, Any]] = []
    seen_entities: set[tuple[str, str, tuple[str, ...]]] = set()

    def collect_entity(entity_value: Any, depth: int = 0) -> None:
        if depth > 2:
            return
        entity = _as_dict(entity_value)
        roles = [str(role) for role in _as_list(entity.get("roles"))]
        vcard = _as_list(entity.get("vcardArray"))
        properties = _as_list(vcard[1]) if len(vcard) > 1 else []
        name: Optional[str] = None
        organization: Optional[str] = None
        abuse_emails: list[str] = []
        for prop in properties:
            if not isinstance(prop, list) or len(prop) < 4:
                continue
            prop_name = str(prop[0]).lower()
            params = _as_dict(prop[1])
            value = prop[3]
            if prop_name == "fn" and isinstance(value, str) and not name:
                name = value
            elif prop_name == "org":
                if isinstance(value, list):
                    value = " ".join(str(part) for part in value if part)
                if isinstance(value, str) and value.strip() and not organization:
                    organization = value.strip()
            elif prop_name == "email" and isinstance(value, str):
                types = params.get("type", [])
                if isinstance(types, str):
                    types = [types]
                if "abuse" in [str(item).lower() for item in types] or "abuse" in [role.lower() for role in roles]:
                    abuse_emails.append(value.strip())

        is_abuse_contact = "abuse" in [role.lower() for role in roles] or bool(abuse_emails)
        is_registration_entity = any(
            role.lower() in {"registrant", "registration", "technical", "administrative", "registrar"}
            for role in roles
        )
        out: dict[str, Any] = {}
        if roles:
            out["roles"] = roles
        if organization:
            out["organization"] = organization[:200]
        if name and (is_abuse_contact or not organization):
            out["name"] = name[:200]
        if abuse_emails:
            out["abuse_emails"] = sorted(set(email for email in abuse_emails if email))
        if out and (is_abuse_contact or is_registration_entity):
            key = (
                str(out.get("organization") or ""),
                str(out.get("name") or ""),
                tuple(out.get("roles") or []),
            )
            if key not in seen_entities:
                seen_entities.add(key)
                entities_out.append(out)
        for child in _as_list(entity.get("entities")):
            collect_entity(child, depth + 1)

    for entity in _as_list(response.get("entities")):
        collect_entity(entity)
    if entities_out:
        record_summary["entities"] = entities_out
    if response.get("errorCode") is not None:
        record_summary["source_error_code"] = response["errorCode"]
    if response.get("title"):
        record_summary["source_error_title"] = response["title"]
    if response.get("description"):
        description = response["description"]
        record_summary["source_error_description"] = str(description)[:500]

    if record_summary:
        result["rdap_ip_record"] = record_summary
    return result


def _as_dict(value: Any) -> dict[str, Any]:
    """Return a dictionary or an empty one for an unexpected API response shape."""
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    """Return a list or an empty one for an unexpected API response shape."""
    return value if isinstance(value, list) else []


def _response_data(source_result: dict[str, Any] | None) -> dict[str, Any]:
    """Extract a source's data object for lookups without altering the raw response."""
    response = _as_dict(_as_dict(source_result).get("response"))
    return _as_dict(response.get("data"))


# --- ASN identity and abuse-contact collection -------------------------------


def setup_node(state: ASNState) -> dict[str, Any]:
    """Fetch RIPE WHOIS and RDAP ASN records; avoid a duplicate BGPView lookup."""
    asn = _asn_num(state["asn"])
    identity = {
        "ripe_whois": _ripe_raw("whois", resource=f"AS{asn}"),
        "rdap": _rdap_raw(asn),
    }
    print(f"[setup] AS{asn}: collected RIPE WHOIS and RDAP ASN records")
    return {"identity": identity}


def _dns_response(query_name: str, record_type: str, timeout: int = 5) -> dict[str, Any]:
    """Return DNS answers or the resolver error without verbose wire-message text."""
    try:
        answer = dns.resolver.resolve(query_name, record_type, lifetime=timeout)
        return {"answers": [record.to_text() for record in answer]}
    except Exception as exc:
        return {"resolver_error_type": type(exc).__name__, "resolver_error": str(exc)}


def _dns_raw_lookup(name: str, record_type: str) -> dict[str, Any]:
    """Return DNS answers or the resolver error, not a risk boolean."""
    return {
        "query_name": name,
        "record_type": record_type,
        **_dns_response(name, record_type),
    }


def _extract_abuse_contacts(raw_finder: dict[str, Any]) -> list[str]:
    contacts = _as_list(_response_data(raw_finder).get("abuse_contacts"))
    return [contact.strip() for contact in contacts if isinstance(contact, str) and "@" in contact]


def abuse_mailbox_node(state: ASNState) -> dict[str, Any]:
    """Collect the full RIPE abuse-contact response and raw DNS query results."""
    asn = _asn_num(state["asn"])
    finder = _ripe_raw("abuse-contact-finder", resource=f"AS{asn}")
    dns_queries: list[dict[str, Any]] = []
    for email in _extract_abuse_contacts(finder):
        domain = email.rsplit("@", 1)[-1].strip().rstrip(".")
        if not domain:
            continue
        for record_type in ("A", "AAAA", "MX"):
            dns_queries.append(_dns_raw_lookup(domain, record_type))
    return {
        "abuse": {
            "ripe_abuse_contact_finder": finder,
            "dns_queries": dns_queries,
        }
    }


# --- Routing, target-IP DNS, RPKI, and registration data ---------------------


def _network_info_fields(raw_result: dict[str, Any]) -> tuple[Optional[str], list[dict[str, str]]]:
    """Extract the routed prefix and origin ASNs for one target IP."""
    data = _response_data(raw_result)
    prefix = data.get("prefix")
    prefix_text = str(prefix).strip() if prefix else None
    origins: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in _as_list(data.get("asns")):
        if isinstance(item, dict):
            raw_number = item.get("asn") or item.get("number") or item.get("resource")
            holder = item.get("holder") or item.get("name")
        else:
            raw_number = item
            holder = None
        text_number = str(raw_number or "").strip().upper()
        if text_number.startswith("AS"):
            text_number = text_number[2:]
        if not text_number.isdigit() or text_number in seen:
            continue
        seen.add(text_number)
        origin = {"asn": text_number}
        if holder:
            origin["holder"] = str(holder)
        origins.append(origin)
    return prefix_text, origins


def _compact_network_info(raw_result: dict[str, Any]) -> dict[str, Any]:
    """Keep only route prefix, announcing ASNs and request status."""
    response = _as_dict(_as_dict(raw_result).get("response"))
    prefix, origins = _network_info_fields(raw_result)
    data = _response_data(raw_result)
    result: dict[str, Any] = {}
    for key in ("source", "http_status", "request_error"):
        if _as_dict(raw_result).get(key) is not None:
            result[key] = _as_dict(raw_result)[key]
    if response.get("status") is not None:
        result["source_status"] = response["status"]
    if data.get("resource") is not None:
        result["resource"] = data["resource"]
    result["prefix"] = prefix
    result["origin_asns"] = origins
    if response.get("messages"):
        result["messages"] = response["messages"]
    return result


def _compact_prefix_count(raw_result: dict[str, Any]) -> dict[str, Any]:
    """Keep short IPv4/IPv6 prefix-count timelines instead of full API metadata."""
    raw_result = _as_dict(raw_result)
    response = _as_dict(raw_result.get("response"))
    data = _as_dict(response.get("data"))
    result: dict[str, Any] = {}
    for key in ("source", "http_status", "request_error"):
        if raw_result.get(key) is not None:
            result[key] = raw_result[key]
    for key in ("status", "status_code"):
        if response.get(key) is not None:
            result[f"source_{key}"] = response[key]
    for key in ("resource", "query_starttime", "query_endtime", "resolution"):
        if data.get(key) is not None:
            result[key] = data[key]
    for family in ("ipv4", "ipv6"):
        series = data.get(family)
        if isinstance(series, list):
            result[family] = [
                {
                    key: point[key]
                    for key in ("timestamp", "prefixes", "address-space", "address_space")
                    if isinstance(point, dict) and point.get(key) is not None
                }
                for point in series
                if isinstance(point, dict)
            ]
        elif isinstance(series, dict):
            # Accommodate API representations that wrap the points in a child field.
            points = series.get("values") or series.get("data") or []
            result[family] = [
                {
                    key: point[key]
                    for key in ("timestamp", "prefixes", "address-space", "address_space")
                    if isinstance(point, dict) and point.get(key) is not None
                }
                for point in points
                if isinstance(point, dict)
            ]
    if response.get("messages"):
        result["messages"] = response["messages"]
    return result


def _ptr_raw_lookup(ip_value: str) -> dict[str, Any]:
    """Query PTR for the target IP and retain the raw DNS result."""
    reverse_name = dns.reversename.from_address(ip_value).to_text()
    return {
        "ip": ip_value,
        "reverse_query": reverse_name,
        "record_type": "PTR",
        **_dns_response(reverse_name, "PTR", timeout=4),
    }


def _valid_ptr_hostname(value: str) -> Optional[str]:
    """Normalize a PTR hostname before issuing forward DNS queries."""
    hostname = str(value).strip().rstrip(".")
    if not hostname or len(hostname) > 253:
        return None
    try:
        ipaddress.ip_address(hostname)
        return None
    except ValueError:
        pass
    labels = hostname.split(".")
    if any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not re.fullmatch(r"[A-Za-z0-9-]+", label)
            for label in labels
    ):
        return None
    return hostname


def _fcrdns_forward_lookups(ptr_result: dict[str, Any]) -> list[dict[str, Any]]:
    """Collect raw A/AAAA answers for PTR hostnames so the LLM can compare them."""
    answers = ptr_result.get("answers", [])
    if not isinstance(answers, list):
        return []

    lookups: list[dict[str, Any]] = []
    seen: set[str] = set()
    for answer in answers:
        hostname = _valid_ptr_hostname(str(answer))
        if not hostname or hostname.lower() in seen:
            continue
        seen.add(hostname.lower())
        lookups.append({
            "ptr_hostname": hostname,
            "a_lookup": _dns_raw_lookup(hostname, "A"),
            "aaaa_lookup": _dns_raw_lookup(hostname, "AAAA"),
        })
        if len(lookups) == 5:
            break
    return lookups


def asn_metadata_node(state: ASNState) -> dict[str, Any]:
    """Collect routing data and lookups for the supplied target IP."""
    asn = _asn_num(state["asn"])
    now = datetime.now(timezone.utc)
    thirty_days_ago = now - timedelta(days=30)

    routing = _ripe_raw("routing-status", resource=f"AS{asn}")
    prefix_count_30d = _compact_prefix_count(_ripe_raw(
        "prefix-count",
        resource=f"AS{asn}",
        starttime=int(thirty_days_ago.timestamp()),
        endtime=int(now.timestamp()),
        resolution="2d",
    ))

    raw_target_ip = state.get("abused_ip")
    canonical_ip: Optional[str] = None
    target_ip_error: Optional[str] = None
    if raw_target_ip:
        try:
            canonical_ip = str(ipaddress.ip_address(str(raw_target_ip).strip()))
        except ValueError as exc:
            target_ip_error = str(exc)

    target_network_info_raw: dict[str, Any] = {}
    target_network_info: dict[str, Any] = {}
    target_prefix: Optional[str] = None
    origin_asns: list[dict[str, str]] = []
    if canonical_ip:
        target_network_info_raw = _ripe_raw("network-info", resource=canonical_ip)
        target_prefix, origin_asns = _network_info_fields(target_network_info_raw)
        target_network_info = _compact_network_info(target_network_info_raw)

    if not raw_target_ip:
        target_prefix_rpki = {
            "prefix_lookup": "No abused IP was supplied; no unrelated prefix was checked."
        }
    elif target_ip_error:
        target_prefix_rpki = {
            "abused_ip": str(raw_target_ip),
            "prefix_lookup_error": target_ip_error,
        }
    elif target_prefix and origin_asns:
        validations = []
        for origin in origin_asns:
            validation = _ripe_raw(
                "rpki-validation",
                resource=origin["asn"],
                prefix=target_prefix,
            )
            validation_data = _response_data(validation)
            validations.append({
                "origin_asn": origin["asn"],
                "origin_holder": origin.get("holder"),
                "response": {
                    key: validation_data[key]
                    for key in (
                        "status", "validating_roas", "invalidated_roas",
                        "resource", "prefix", "max_length", "origin",
                    )
                    if validation_data.get(key) is not None
                },
                **{
                    key: validation[key]
                    for key in ("source", "http_status", "request_error")
                    if validation.get(key) is not None
                },
            })
        target_prefix_rpki = {
            "abused_ip": canonical_ip,
            "prefix": target_prefix,
            "observed_origin_asns": origin_asns,
            "validations": validations,
        }
    else:
        target_prefix_rpki = {
            "abused_ip": canonical_ip,
            "prefix": target_prefix,
            "observed_origin_asns": origin_asns,
            "prefix_lookup": "RIPE network-info did not return both a routed prefix and origin ASN; RPKI was not queried.",
        }

    target_ip_dns: dict[str, Any] = {}
    target_ip_registration: dict[str, Any] = {}
    if canonical_ip:
        ptr_result = _ptr_raw_lookup(canonical_ip)
        target_ip_dns = {
            "target_ip": canonical_ip,
            "ptr_lookup": ptr_result,
            "fcrdns_forward_lookups": _fcrdns_forward_lookups(ptr_result),
        }
        target_ip_registration = {
            # Keep both registry perspectives, but compact the RDAP response
            # immediately so bulky links/delegation data are not stored or sent to Gemini.
            "ripe_stat_whois": _compact_target_whois(
                _ripe_raw("whois", resource=canonical_ip)
            ),
            "rdap": _compact_ip_rdap(_rdap_ip_raw(canonical_ip)),
        }
    elif raw_target_ip:
        target_ip_dns = {"target_ip": str(raw_target_ip), "lookup_error": target_ip_error}
        target_ip_registration = {
            "target_ip": str(raw_target_ip),
            "lookup_error": target_ip_error,
        }

    network_data = {
        "ripe_routing_status": routing,
        "ripe_prefix_count_last_30_days": prefix_count_30d,
        "target_ip_network_info": target_network_info,
        "abused_ip_prefix": {
            "abused_ip": canonical_ip or raw_target_ip,
            "prefix": target_prefix,
            "ripe_rpki_validation": target_prefix_rpki,
        },
        "target_ip_dns": target_ip_dns,
        "target_ip_registration": target_ip_registration,
    }
    print(
        f"[metadata] AS{asn}: collected routing summary, 30-day prefix-count trend, "
        "target route/RPKI, target-IP PTR/FCrDNS and one IP-registration lookup"
    )
    return {"network": network_data}


# --- Homepage selection for Gemini URL Context -------------------------------


def _normalize_website_url(value: Any) -> Optional[str]:
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()
    if not urlparse(value).scheme:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username or parsed.password:
        return None
    return value


def _website_candidates(identity: dict[str, Any], abuse: dict[str, Any]) -> list[dict[str, str]]:
    """Find homepage URLs from RIPE WHOIS/RDAP, using abuse domain only as fallback."""
    candidates: list[dict[str, str]] = []

    def add(value: Any, source: str) -> None:
        url = _normalize_website_url(value)
        if url and all(item["url"] != url for item in candidates):
            candidates.append({"url": url, "source": source})

    whois_data = _response_data(identity.get("ripe_whois", {}))
    for record in _as_list(whois_data.get("records")):
        for item in _as_list(record):
            item_data = _as_dict(item)
            key = str(item_data.get("key", "")).strip().lower()
            value = item_data.get("value")
            if key in WHOIS_WEBSITE_KEYS:
                add(value, f"RIPE WHOIS {key}")
            elif key == "remarks":
                remark = str(value or "")
                if "looking glass" not in remark.lower():
                    for match in re.findall(r"https?://[^\s|<>\"']+", remark, flags=re.IGNORECASE):
                        add(match.rstrip(".,;:!?)]}"), "RIPE WHOIS remarks URL")

    rdap_wrapper = _as_dict(_as_dict(identity.get("rdap")).get("rdap_asn_record"))
    rdap_record = _as_dict(rdap_wrapper.get("response"))
    for key in RDAP_WEBSITE_KEYS:
        add(rdap_record.get(key), f"RDAP {key}")

    for entity_value in _as_list(rdap_record.get("entities")):
        entity = _as_dict(entity_value)
        for key in RDAP_WEBSITE_KEYS:
            add(entity.get(key), f"RDAP entity {key}")
        vcard = _as_list(entity.get("vcardArray"))
        properties = _as_list(vcard[1]) if len(vcard) > 1 else []
        for prop in properties:
            if isinstance(prop, list) and len(prop) >= 4 and str(prop[0]).lower() == "url":
                add(prop[3], "RDAP vCard URL")

    if not candidates:
        for email in _extract_abuse_contacts(_as_dict(abuse.get("ripe_abuse_contact_finder"))):
            domain = email.rsplit("@", 1)[-1].strip().rstrip(".")
            add(domain, "candidate derived from abuse-contact email domain; not confirmed official")
    return candidates


def _is_public_web_url(url: str) -> bool:
    """Avoid fetching loopback/private/link-local addresses from source-supplied URLs."""
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return False
    try:
        literal = ipaddress.ip_address(hostname)
        return literal.is_global
    except ValueError:
        pass
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        addresses = {
            ipaddress.ip_address(info[4][0].split("%", 1)[0])
            for info in infos
        }
        return bool(addresses) and all(address.is_global for address in addresses)
    except Exception:
        return False


def crypto_check_node(state: ASNState) -> dict[str, Any]:
    """Select a public homepage URL for Gemini URL Context; do not download HTML here."""
    identity = state.get("identity") or {}
    abuse = state.get("abuse") or {}
    candidates = _website_candidates(identity, abuse)

    public_candidates: list[dict[str, str]] = []
    skipped_candidates: list[dict[str, str]] = []
    for candidate in candidates:
        if _is_public_web_url(candidate["url"]):
            public_candidates.append(candidate)
            # Only one homepage is passed to URL Context, so stop checking URLs
            # once we have the first public candidate.
            break
        else:
            skipped_candidates.append({
                **candidate,
                "reason": "URL did not resolve to a public IP address; not sent for website inspection.",
            })

    # The model inspects this exact homepage with URL Context. Python performs no
    # HTTP request to the website and does not download its HTML.
    homepage_url = public_candidates[0]["url"] if public_candidates else None
    return {
        "website": {
            "homepage_url": homepage_url,
            "url_candidates": public_candidates,
            "skipped_url_candidates": skipped_candidates,
            "website_fetch_method": "Gemini URL Context only; Python did not fetch homepage HTML.",
        }
    }


# --- Gemini evaluation and response validation --------------------------------


SYSTEM_PROMPT = """\
You are analyzing an ASN, its target IP address, and the associated hosting provider.
The input contains source data collected from RIPE Stat, RDAP, DNS, routing/RPKI
lookups, and a provider homepage URL. IP registration and prefix-count history are
compact summaries that preserve relevant fields and time windows.

Review all supplied data groups and source responses before producing the assessment.
Provide an overall assessment, negative/risk factors, positive factors, the target-prefix
RPKI assessment when data is available, and a separate assessment of whether the provider
accepts cryptocurrency payments based on the supplied homepage. For the cryptocurrency-
payment assessment, use English- or German-language evidence from the homepage.

Return ONLY one valid JSON object with this schema:
{
  "risk_score": 0.0,
  "verdict": "trusted|low_risk|medium_risk|high_risk|bulletproof",
  "risk_factors": ["negative factor supported by the supplied data"],
  "positive_factors": ["positive factor supported by the supplied data"],
  "crypto_payment_assessment": {
    "status": "yes|no|unclear",
    "payment_methods": ["payment method"],
    "evidence": ["supporting homepage evidence in English or German"],
    "checked_url": "homepage URL"
  },
  "rpki_prefix_assessment": [
    {
      "prefix": "prefix from source data",
      "observed_status": "status from source data",
      "assessment": "normal|concern|unknown",
      "reason": "assessment based on the source data"
    }
  ],
  "summary": "overall analysis"
}
"""


def _extract_json_text(response_data: dict[str, Any]) -> str:
    candidates = response_data.get("candidates") or []
    if not candidates:
        raise RuntimeError(f"Gemini returned no candidates: {response_data.get('promptFeedback')!r}")
    candidate = candidates[0]
    parts = (candidate.get("content") or {}).get("parts") or []
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
            f"finishMessage={candidate.get('finishMessage')!r}"
        )
    return result


def _parse_verdict(raw_text: str) -> dict[str, Any]:
    text = re.sub(
        r"^\s*```(?:json)?\s*",
        "",
        raw_text.strip(),
        count=1,
        flags=re.IGNORECASE,
    )
    text = re.sub(r"\s*```\s*$", "", text, count=1).strip()
    try:
        result = json.loads(text)
    except json.JSONDecodeError:
        from json_repair import repair_json

        repaired = repair_json(text)
        if not isinstance(repaired, str) or not repaired.strip():
            raise RuntimeError(f"Gemini response was not valid JSON: {text[:800]!r}")
        result = json.loads(repaired)
    if not isinstance(result, dict):
        raise RuntimeError("Gemini response must be a JSON object.")
    try:
        score = float(result["risk_score"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("Gemini JSON is missing a numeric risk_score.") from exc
    if not 0.0 <= score <= 10.0:
        raise RuntimeError(f"Gemini risk_score is outside 0–10: {score}")
    allowed = {"trusted", "low_risk", "medium_risk", "high_risk", "bulletproof"}
    if result.get("verdict") not in allowed:
        raise RuntimeError(f"Gemini returned unsupported verdict: {result.get('verdict')!r}")
    for field in ("risk_factors", "positive_factors", "rpki_prefix_assessment"):
        if not isinstance(result.get(field, []), list):
            raise RuntimeError(f"{field} must be a JSON array")
    if not isinstance(result.get("summary", ""), str):
        raise RuntimeError("summary must be a string")
    result["risk_score"] = score
    result.setdefault("risk_factors", [])
    result.setdefault("positive_factors", [])
    result.setdefault("rpki_prefix_assessment", [])
    result.setdefault("summary", "")
    crypto_assessment = result.get("crypto_payment_assessment")
    if not isinstance(crypto_assessment, dict):
        crypto_assessment = {}
    crypto_status = crypto_assessment.get("status")
    if crypto_status not in {"yes", "no", "unclear"}:
        crypto_status = "unclear"
    payment_methods = crypto_assessment.get("payment_methods", [])
    evidence = crypto_assessment.get("evidence", [])
    result["crypto_payment_assessment"] = {
        "status": crypto_status,
        "payment_methods": payment_methods if isinstance(payment_methods, list) else [],
        "evidence": evidence if isinstance(evidence, list) else [],
        "checked_url": crypto_assessment.get("checked_url", "")
        if isinstance(crypto_assessment.get("checked_url", ""), str) else "",
    }
    return result


def _failed_verdict(error: str, summary: str) -> dict[str, Any]:
    """Return a consistent result when the Gemini assessment cannot complete."""
    return {
        "error": error,
        "risk_score": None,
        "verdict": "unknown",
        "risk_factors": [],
        "positive_factors": [],
        "rpki_prefix_assessment": [],
        "crypto_payment_assessment": {
            "status": "unclear",
            "payment_methods": [],
            "evidence": [],
            "checked_url": "",
        },
        "summary": summary,
    }


def _compact_source_metadata(source_result: dict[str, Any]) -> dict[str, Any]:
    """Keep source URL and transport/API errors while dropping verbose API metadata."""
    source_result = _as_dict(source_result)
    result: dict[str, Any] = {}
    for key in ("source", "http_status", "request_error"):
        if source_result.get(key) is not None:
            result[key] = source_result[key]
    response = _as_dict(source_result.get("response"))
    if response.get("status") is not None:
        result["source_status"] = response["status"]
    if response.get("status_code") is not None:
        result["source_status_code"] = response["status_code"]
    return result


def _compact_target_whois(source_result: dict[str, Any]) -> dict[str, Any]:
    """Keep useful IP registration fields and drop repetitive reverse-DNS records."""
    result = _compact_source_metadata(source_result)
    response = _as_dict(_as_dict(source_result).get("response"))
    data = _as_dict(response.get("data"))
    wanted_keys = {
        "inetnum", "inet6num", "netrange", "netname", "route", "route6",
        "origin", "aut-num", "as-name", "org", "org-name", "org-type",
        "organisation", "descr", "owner", "ownerid", "responsible", "country",
        "address", "status", "created", "last-modified", "abuse-c",
        "abuse-mailbox", "abuse-contact", "e-mail", "email", "nic-hdl",
        "person", "role", "source", "remarks", "mnt-by",
    }
    fields: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for record in _as_list(data.get("records")):
        for item in _as_list(record):
            item = _as_dict(item)
            key = str(item.get("key", "")).strip().lower()
            value = item.get("value")
            if key not in wanted_keys or value is None:
                continue
            value_text = str(value).strip()
            if not value_text:
                continue
            if len(value_text) > 400:
                value_text = value_text[:397] + "..."
            pair = (key, value_text)
            if pair in seen:
                continue
            seen.add(pair)
            fields.append({"key": key, "value": value_text})
    result["resource"] = data.get("resource")
    result["query_time"] = data.get("query_time")
    result["registration_fields"] = fields
    return result


def llm_evaluate_node(state: ASNState) -> dict[str, Any]:
    """Send grouped source findings to Gemini after collection-time compaction."""
    if not GEMINI_API_KEY:
        return {
            "verdict": _failed_verdict(
                "GEMINI_API_KEY is empty. Check the .env file beside provider_agent.py.",
                "No model evaluation was performed because the API key is missing.",
            )
        }

    payload = {
        "asn": state.get("asn"),
        "abused_ip": state.get("abused_ip"),
        "identity": state.get("identity", {}),
        "abuse": state.get("abuse", {}),
        "network": state.get("network", {}),
        "website": state.get("website", {}),
    }
    compact_payload_json = json.dumps(payload, indent=2, ensure_ascii=False)
    print(f"[llm] source payload prepared at collection time: {len(compact_payload_json):,} characters")
    website_data = payload.get("website", {})
    homepage_url = website_data.get("homepage_url") if isinstance(website_data, dict) else None
    homepage_instruction = (
        f"Homepage URL for cryptocurrency-payment assessment: {homepage_url}\n"
        "Use URL Context to inspect this homepage.\n\n"
        if isinstance(homepage_url, str) and homepage_url.strip()
        else "Homepage URL for cryptocurrency-payment assessment: not found.\n\n"
    )
    user_message = (
            homepage_instruction
            + "Analyze these ASN/provider source responses and compacted registration/prefix summaries:\n\n"
            + compact_payload_json
    )
    request_body = {
        "system_instruction": {"parts": [{"text": SYSTEM_PROMPT}]},
        "contents": [{"role": "user", "parts": [{"text": user_message}]}],
        "tools": [{"url_context": {}}, {"google_search": {}}],
        "generationConfig": {
            "maxOutputTokens": 4096,
            "responseMimeType": "application/json",
            "thinkingConfig": {"thinkingLevel": "low"},
        },
    }
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"
    print(f"[llm] querying {GEMINI_MODEL} for AS{state.get('asn')}...")
    try:
        response = requests.post(
            url,
            headers={
                "Content-Type": "application/json",
                "x-goog-api-key": GEMINI_API_KEY,
            },
            json=request_body,
            timeout=GEMINI_TIMEOUT,
        )
        if not response.ok:
            try:
                detail: Any = response.json()
            except ValueError:
                detail = response.text[:1500] or "<empty response body>"
            raise RuntimeError(f"Gemini API HTTP {response.status_code}: {detail}")
        try:
            response_data = response.json()
        except ValueError as exc:
            raise RuntimeError(
                f"Gemini API returned invalid JSON: {response.text[:1000]!r}"
            ) from exc
        verdict = _parse_verdict(_extract_json_text(response_data))
        print(
            f"[llm] AS{state.get('asn')}: score={verdict['risk_score']} "
            f"verdict={verdict['verdict']}"
        )
        return {"verdict": verdict}
    except Exception as exc:
        message = str(exc)
        print(f"[llm] error: {message}")
        return {
            "verdict": _failed_verdict(
                message,
                "The model evaluation did not complete; no risk verdict was produced.",
            )
        }


# --- LangGraph assembly and public entry point --------------------------------


def build_graph():
    """Build the existing collection branches and the final Gemini assessment."""
    graph = StateGraph(ASNState)
    graph.add_node("setup", setup_node)
    graph.add_node("abuse_mailbox", abuse_mailbox_node)
    graph.add_node("asn_metadata", asn_metadata_node)
    graph.add_node("crypto_check", crypto_check_node)
    graph.add_node("llm_evaluate", llm_evaluate_node)

    # Resolve the ASN identity first.
    graph.add_edge(START, "setup")

    # Collect abuse-contact/DNS data and routing/IP metadata in parallel.
    graph.add_edge("setup", "abuse_mailbox")
    graph.add_edge("setup", "asn_metadata")

    # Website selection may need the abuse contact as a fallback.
    graph.add_edge(["setup", "abuse_mailbox"], "crypto_check")

    # Run one model assessment after all source-data branches finish.
    graph.add_edge(
        ["abuse_mailbox", "asn_metadata", "crypto_check"],
        "llm_evaluate",
    )
    graph.add_edge("llm_evaluate", END)
    return graph.compile()


_graph = build_graph()


def research_asn(asn: str, abused_ip: Optional[str] = None) -> dict[str, Any]:
    """Run ASN/provider research; RPKI is queried only for the abused IP's prefix."""
    clean_asn = _asn_num(asn)
    clean_ip: Optional[str] = None
    if abused_ip is not None and str(abused_ip).strip():
        clean_ip = str(ipaddress.ip_address(str(abused_ip).strip()))

    print("\n" + "=" * 50)
    print(f"[research] Starting ASN research for AS{clean_asn}")
    if clean_ip:
        print(f"[research] Abuse IP target: {clean_ip}")
    else:
        print("[research] No abuse IP supplied; target-prefix RPKI check will be skipped")
    print("=" * 50)
    result = _graph.invoke({"asn": clean_asn, "abused_ip": clean_ip})
    verdict = result.get("verdict") or {}
    print(
        f"[research] AS{clean_asn} complete → {verdict.get('verdict', 'unknown')} "
        f"(score: {verdict.get('risk_score', '?')})"
    )
    return result





