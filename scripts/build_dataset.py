#!/usr/bin/env python3
"""Build a privacy-minimized, lossless normalized RDAP/WHOIS release.

The builder accepts any number of directories for each protocol. It deliberately
does not record input paths, file names, collection times, response headers, or
server URLs. Only whitelisted domain-level technical facts are exported.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import re
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "1.1.0"
DOMAIN_RE = re.compile(
    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+ye",
    re.IGNORECASE,
)
TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/+ -]{0,255}")
SAFE_HANDLE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
URL_RE = re.compile(r"https?://", re.I)
PHONE_RE = re.compile(r"(?:^|\s)\+?\d[\d .()/-]{7,}\d(?:$|\s)")

WHOIS_FIELDS = {
    "domain name",
    "registry domain id",
    "updated date",
    "creation date",
    "registry expiry date",
    "registrar",
    "registrar iana id",
    "domain status",
    "name server",
    "dnssec",
}

NO_RECORD_RE = re.compile(r"no match|not found|no data|no entries|not registered|available|no object", re.I)
QUERY_ERROR_RE = re.compile(r"socket|timeout|timed out|connection|refused|temporar|unavailable|unsupported|error", re.I)
PUBLIC_SUFFIXES = ("com.ye", "edu.ye", "gov.ye", "mil.ye", "net.ye", "org.ye", "ye")

STATUS_EQUIVALENTS = {
    "ok": "active",
    "active": "active",
    "clienthold": "client_hold",
    "client hold": "client_hold",
    "pendingdelete": "pending_delete",
    "pending delete": "pending_delete",
    "addperiod": "add_period",
    "add period": "add_period",
}


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def pretty_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def normalized_domain(value: Any) -> str:
    text = str(value or "").strip().lower().rstrip(".")
    return text if DOMAIN_RE.fullmatch(text) else ""


def registrable_domain(value: Any) -> str:
    name = normalized_domain(value)
    if not name:
        return ""
    labels = name.split(".")
    for suffix in PUBLIC_SUFFIXES:
        suffix_labels = suffix.split(".")
        if name == suffix:
            return ""
        if name.endswith("." + suffix) and len(labels) > len(suffix_labels):
            return ".".join(labels[-len(suffix_labels) - 1:])
    return ""


def standard_model_match(value: Any) -> bool:
    name = normalized_domain(value)
    return bool(name) and (name in PUBLIC_SUFFIXES or registrable_domain(name) == name)


def normalized_handle(value: Any) -> str | None:
    text = str(value or "").strip()
    return text if SAFE_HANDLE_RE.fullmatch(text) else None


def normalized_text(value: Any, limit: int = 256) -> str | None:
    text = re.sub(r"\s+", " ", str(value or "").strip())
    if not text or len(text) > limit:
        return None
    if EMAIL_RE.search(text) or URL_RE.search(text) or PHONE_RE.search(text):
        return None
    return text if TOKEN_RE.fullmatch(text) else None


def normalized_timestamp(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    parsed = parsed.astimezone(dt.timezone.utc)
    timespec = "milliseconds" if parsed.microsecond % 1000 == 0 else "microseconds"
    return parsed.isoformat(timespec=timespec).replace("+00:00", "Z")


def status_item(value: Any) -> dict[str, str] | None:
    source_value = re.sub(r"\s+", " ", str(value or "").strip())
    if not source_value or len(source_value) > 80 or URL_RE.search(source_value):
        return None
    compact = re.sub(r"[^a-z0-9]+", " ", source_value.lower()).strip()
    camel_compact = re.sub(r"[^a-z0-9]+", "", source_value.lower())
    normalized = STATUS_EQUIVALENTS.get(source_value.lower())
    if normalized is None:
        normalized = STATUS_EQUIVALENTS.get(compact)
    if normalized is None:
        normalized = STATUS_EQUIVALENTS.get(camel_compact)
    if normalized is None:
        normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", source_value)
        normalized = re.sub(r"[^A-Za-z0-9]+", "_", normalized).strip("_").lower()
    if not normalized:
        return None
    return {"source_value": source_value, "normalized": normalized}


def sort_unique(values: Iterable[Any]) -> list[Any]:
    keyed: dict[str, Any] = {}
    for value in values:
        keyed[canonical_json(value)] = value
    return [keyed[key] for key in sorted(keyed)]


def safe_public_id(value: Any) -> dict[str, str | None] | None:
    if not isinstance(value, dict):
        return None
    id_type = normalized_text(value.get("type"), 128)
    identifier = normalized_handle(value.get("identifier"))
    if not id_type or not identifier:
        return None
    return {"type": id_type, "identifier": identifier}


def registrar_from_rdap(entities: Any) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    stack = list(entities) if isinstance(entities, list) else []
    while stack:
        entity = stack.pop()
        if not isinstance(entity, dict):
            continue
        roles = [str(role).strip().lower() for role in entity.get("roles") or []]
        if "registrar" in roles:
            name = None
            version = None
            card = entity.get("vcardArray")
            if isinstance(card, list) and len(card) > 1 and isinstance(card[1], list):
                for prop in card[1]:
                    if not isinstance(prop, list) or len(prop) < 4:
                        continue
                    if str(prop[0]).lower() == "fn":
                        name = normalized_text(prop[3], 256)
                    elif str(prop[0]).lower() == "version":
                        version = normalized_text(prop[3], 32)
            public_ids = []
            for item in entity.get("publicIds") or []:
                parsed = safe_public_id(item)
                if parsed:
                    public_ids.append(parsed)
            output.append(
                {
                    "registry_handle": normalized_handle(entity.get("handle")),
                    "name": name,
                    "public_ids": sort_unique(public_ids),
                    "vcard_version": version,
                }
            )
        nested = entity.get("entities")
        if isinstance(nested, list):
            stack.extend(nested)
    return sort_unique(output)


def nameservers_from_rdap(value: Any) -> list[dict[str, str | None]]:
    output = []
    for item in value if isinstance(value, list) else []:
        if not isinstance(item, dict):
            continue
        name = normalized_domain(item.get("ldhName"))
        if name:
            output.append(
                {
                    "ldh_name": name,
                    "registry_handle": normalized_handle(item.get("handle")),
                }
            )
    return sort_unique(output)


def dnssec_from_rdap(value: Any) -> dict[str, Any]:
    value = value if isinstance(value, dict) else {}
    delegation = value.get("delegationSigned")
    zone = value.get("zoneSigned")
    max_life = value.get("maxSigLife")
    ds_records = []
    for item in value.get("dsData") or []:
        if not isinstance(item, dict):
            continue
        row = {
            "key_tag": item.get("keyTag") if isinstance(item.get("keyTag"), int) else None,
            "algorithm": item.get("algorithm") if isinstance(item.get("algorithm"), int) else None,
            "digest_type": item.get("digestType") if isinstance(item.get("digestType"), int) else None,
            "digest": normalized_handle(item.get("digest")),
        }
        if any(v is not None for v in row.values()):
            ds_records.append(row)
    key_records = []
    for item in value.get("keyData") or []:
        if not isinstance(item, dict):
            continue
        public_key = str(item.get("publicKey") or "").strip() or None
        if public_key and (len(public_key) > 8192 or not re.fullmatch(r"[A-Za-z0-9+/=]+", public_key)):
            public_key = None
        row = {
            "flags": item.get("flags") if isinstance(item.get("flags"), int) else None,
            "protocol": item.get("protocol") if isinstance(item.get("protocol"), int) else None,
            "algorithm": item.get("algorithm") if isinstance(item.get("algorithm"), int) else None,
            "public_key": public_key,
        }
        if any(v is not None for v in row.values()):
            key_records.append(row)
    semantic = None
    if delegation is True:
        semantic = "signed"
    elif delegation is False:
        semantic = "unsigned"
    return {
        "status": semantic,
        "delegation_signed": delegation if isinstance(delegation, bool) else None,
        "zone_signed": zone if isinstance(zone, bool) else None,
        "max_signature_life": max_life if isinstance(max_life, int) and max_life >= 0 else None,
        "ds_records": sort_unique(ds_records),
        "key_records": sort_unique(key_records),
    }


def lifecycle_from_rdap(value: Any) -> dict[str, list[str]]:
    mapping = {
        "registration": "registration",
        "expiration": "expiration",
        "last changed": "last_changed",
    }
    output: dict[str, list[str]] = {key: [] for key in mapping.values()}
    for event in value if isinstance(value, list) else []:
        if not isinstance(event, dict):
            continue
        key = mapping.get(str(event.get("eventAction") or "").strip().lower())
        timestamp = normalized_timestamp(event.get("eventDate"))
        if key and timestamp:
            output[key].append(timestamp)
    return {key: sorted(set(values)) for key, values in output.items()}


def make_record(source_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    name = payload["domain"]
    standard = registrable_domain(name)
    payload = {
        **payload,
        "registration_object_basis": "authoritative_record",
        "standard_registrable_domain": standard,
        "standard_public_suffix_model_match": standard_model_match(name),
    }
    body = {"schema_version": SCHEMA_VERSION, "source_type": source_type, **payload}
    digest = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
    return {**body, "record_id": f"sha256:{digest}"}


def make_outcome(
    query_name: str,
    outcome: str,
    returned_domains: Iterable[str] = (),
) -> dict[str, Any]:
    returned = sorted(
        {
            domain
            for value in returned_domains
            if (domain := normalized_domain(value))
        }
    )
    if outcome == "different_domain_returned":
        if not returned or all(domain == query_name for domain in returned):
            raise ValueError("different-domain outcome requires a different returned domain")
    elif returned:
        raise ValueError("returned domains are valid only for different-domain outcomes")
    body = {
        "schema_version": SCHEMA_VERSION,
        "source_type": "whois",
        "query_name": query_name,
        "registrable_domain": registrable_domain(query_name),
        "outcome": outcome,
        "returned_domains": returned,
    }
    digest = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
    return {**body, "outcome_id": f"sha256:{digest}"}


def classify_whois_outcome(text: str) -> str:
    if NO_RECORD_RE.search(text):
        return "no_record"
    if QUERY_ERROR_RE.search(text):
        return "query_error"
    return "unparseable"


def parse_rdap(path: Path, diagnostics: Counter[str]) -> list[dict[str, Any]]:
    diagnostics["rdap_artifacts_read"] += 1
    try:
        value = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        diagnostics["rdap_unreadable_or_invalid"] += 1
        return []
    if not isinstance(value, dict):
        diagnostics["rdap_invalid_shape"] += 1
        return []
    domain = normalized_domain(value.get("ldhName"))
    if not domain:
        diagnostics["rdap_missing_or_invalid_domain"] += 1
        return []
    statuses = []
    for item in value.get("status") or []:
        parsed = status_item(item)
        if parsed:
            statuses.append(parsed)
    conformance = []
    for item in value.get("rdapConformance") or []:
        parsed = normalized_handle(item)
        if parsed:
            conformance.append(parsed)
    registry_id = normalized_handle(value.get("handle"))
    record = make_record(
        "rdap",
        {
            "domain": domain,
            "object_class": normalized_text(value.get("objectClassName"), 64),
            "registry_ids": [registry_id] if registry_id else [],
            "statuses": sort_unique(statuses),
            "nameservers": nameservers_from_rdap(value.get("nameservers")),
            "registrars": registrar_from_rdap(value.get("entities")),
            "lifecycle": lifecycle_from_rdap(value.get("events")),
            "dnssec": dnssec_from_rdap(value.get("secureDNS")),
            "protocol_conformance": sorted(set(conformance)),
        },
    )
    diagnostics["rdap_record_blocks_parsed"] += 1
    return [record]


def whois_blocks(text: str) -> list[dict[str, list[str]]]:
    blocks = []
    current: dict[str, list[str]] | None = None
    for line in text.splitlines():
        match = re.match(r"^\s*([A-Za-z][A-Za-z0-9 _./()-]{0,80})\s*:\s*(.*?)\s*$", line)
        if not match:
            continue
        label = re.sub(r"\s+", " ", match.group(1).strip()).lower()
        value = match.group(2).strip()
        if label == "domain name":
            if current is not None:
                blocks.append(current)
            current = defaultdict(list)
        if current is not None and label in WHOIS_FIELDS:
            current[label].append(value)
    if current is not None:
        blocks.append(current)
    return blocks


def parse_whois_block(fields: dict[str, list[str]]) -> dict[str, Any] | None:
    domains = sorted({normalized_domain(v) for v in fields.get("domain name", []) if normalized_domain(v)})
    if len(domains) != 1:
        return None
    domain = domains[0]
    ids = sorted({x for v in fields.get("registry domain id", []) if (x := normalized_handle(v))})
    statuses = []
    for value in fields.get("domain status", []):
        parsed = status_item(value.split()[0] if value else "")
        if parsed:
            statuses.append(parsed)
    nameservers = []
    for value in fields.get("name server", []):
        name = normalized_domain(value.split()[0] if value else "")
        if name:
            nameservers.append({"ldh_name": name, "registry_handle": None})
    registrar_names = sorted(
        {x for v in fields.get("registrar", []) if (x := normalized_text(v, 256))}
    )
    iana_ids = sorted(
        {x for v in fields.get("registrar iana id", []) if (x := normalized_handle(v))}
    )
    registrars = []
    for name in registrar_names if registrar_names else ([None] if iana_ids else []):
        registrars.append(
            {
                "registry_handle": None,
                "name": name,
                "public_ids": [
                    {"type": "IANA Registrar ID", "identifier": identifier}
                    for identifier in iana_ids
                ],
                "vcard_version": None,
            }
        )
    lifecycle = {"registration": [], "expiration": [], "last_changed": []}
    mapping = {
        "creation date": "registration",
        "registry expiry date": "expiration",
        "updated date": "last_changed",
    }
    for label, output in mapping.items():
        lifecycle[output] = sorted(
            {x for v in fields.get(label, []) if (x := normalized_timestamp(v))}
        )
    dnssec_values = []
    for value in fields.get("dnssec", []):
        item = re.sub(r"[^a-z0-9]+", "_", value.split()[0].lower()).strip("_") if value else ""
        if item:
            dnssec_values.append(item)
    dnssec_values = sorted(set(dnssec_values))
    semantic = dnssec_values[0] if len(dnssec_values) == 1 else None
    delegation = True if semantic in {"signed", "signed_delegation"} else False if semantic == "unsigned" else None
    return make_record(
        "whois",
        {
            "domain": domain,
            "object_class": "domain",
            "registry_ids": ids,
            "statuses": sort_unique(statuses),
            "nameservers": sort_unique(nameservers),
            "registrars": sort_unique(registrars),
            "lifecycle": lifecycle,
            "dnssec": {
                "status": semantic,
                "delegation_signed": delegation,
                "zone_signed": None,
                "max_signature_life": None,
                "ds_records": [],
                "key_records": [],
            },
            "protocol_conformance": [],
        },
    )


def parse_whois(
    path: Path,
    diagnostics: Counter[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    diagnostics["whois_artifacts_read"] += 1
    domain = normalized_domain(path.stem)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        diagnostics["whois_unreadable"] += 1
        outcomes = [make_outcome(domain, "unparseable")] if domain else []
        return [], outcomes
    blocks = whois_blocks(text)
    if not blocks:
        diagnostics["whois_artifacts_without_record"] += 1
        outcome = classify_whois_outcome(text)
        diagnostics[f"whois_outcome_{outcome}"] += 1
        outcomes = [make_outcome(domain, outcome)] if domain else []
        if not domain:
            diagnostics["whois_outcome_missing_domain"] += 1
        return [], outcomes
    output = []
    for block in blocks:
        diagnostics["whois_record_blocks_seen"] += 1
        record = parse_whois_block(block)
        if record:
            output.append(record)
            diagnostics["whois_record_blocks_parsed"] += 1
        else:
            diagnostics["whois_invalid_record_blocks"] += 1
    if not output:
        diagnostics["whois_outcome_unparseable"] += 1
        outcomes = [make_outcome(domain, "unparseable")] if domain else []
        return [], outcomes
    returned_domains = sorted({record["domain"] for record in output})
    mismatched = [
        returned for returned in returned_domains
        if returned != domain
    ]
    if domain and mismatched:
        diagnostics["whois_outcome_different_domain_returned"] += 1
        return output, [
            make_outcome(domain, "different_domain_returned", returned_domains)
        ]
    return output, []


def deduplicate(
    records: Iterable[dict[str, Any]],
    id_field: str = "record_id",
) -> tuple[list[dict[str, Any]], int]:
    unique: dict[str, dict[str, Any]] = {}
    seen = 0
    for record in records:
        seen += 1
        unique[record[id_field]] = record
    rows = sorted(unique.values(), key=lambda r: (r.get("domain", r.get("query_name", "")), r[id_field]))
    return rows, seen - len(unique)


def read_domain_universe(path: Path | None) -> set[str]:
    if path is None:
        return set()
    with path.open(encoding="utf-8", newline="") as handle:
        rows = csv.DictReader(handle)
        if "domain" not in (rows.fieldnames or []):
            raise ValueError("domain-universe CSV must contain a domain column")
        domains = {normalized_domain(row.get("domain")) for row in rows}
    domains.discard("")
    return domains


def record_values(record: dict[str, Any]) -> dict[str, set[str]]:
    registrar_names = {
        str(item["name"])
        for item in record["registrars"]
        if item.get("name") is not None
    }
    return {
        "registry_ids": set(record["registry_ids"]),
        "status_codes": {item["normalized"] for item in record["statuses"]},
        "nameservers": {item["ldh_name"] for item in record["nameservers"]},
        "registrar_names": registrar_names,
        "registration_dates": set(record["lifecycle"]["registration"]),
        "expiration_dates": set(record["lifecycle"]["expiration"]),
        "last_changed_dates": set(record["lifecycle"]["last_changed"]),
        "dnssec_status": {record["dnssec"]["status"]} if record["dnssec"]["status"] else set(),
    }


def merge_registrars(entries: list[tuple[str, dict[str, Any]]]) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, set[Any]]] = {}
    for source_type, item in entries:
        name = item.get("name")
        handle = item.get("registry_handle")
        public_ids = item.get("public_ids") or []
        identity = (
            f"name:{str(name).casefold()}" if name
            else f"handle:{handle}" if handle
            else "ids:" + canonical_json(public_ids) if public_ids
            else ""
        )
        if not identity:
            continue
        group = groups.setdefault(
            identity,
            {
                "names": set(), "handles": set(), "public_ids": set(),
                "versions": set(), "sources": set(),
            },
        )
        if name:
            group["names"].add(name)
        if handle:
            group["handles"].add(handle)
        for public_id in public_ids:
            group["public_ids"].add(canonical_json(public_id))
        if item.get("vcard_version"):
            group["versions"].add(item["vcard_version"])
        group["sources"].add(source_type)
    output = []
    for _, group in sorted(groups.items()):
        output.append(
            {
                "names_observed": sorted(group["names"]),
                "registry_handles_observed": sorted(group["handles"]),
                "public_ids_observed": [json.loads(value) for value in sorted(group["public_ids"])],
                "vcard_versions_observed": sorted(group["versions"]),
                "source_types": sorted(group["sources"]),
            }
        )
    return sort_unique(output)


def merge_domains(
    records: list[dict[str, Any]], reference: set[str],
    outcomes: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    by_domain: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        by_domain[record["domain"]].append(record)
    outcomes_by_domain: dict[str, list[dict[str, Any]]] = defaultdict(list)
    existing_domains = reference | set(by_domain)
    for outcome in outcomes or []:
        target = ""
        if outcome["outcome"] == "different_domain_returned":
            if outcome["query_name"] in existing_domains:
                target = outcome["query_name"]
        elif outcome["query_name"] == outcome["registrable_domain"]:
            target = outcome["registrable_domain"]
        if target:
            outcomes_by_domain[target].append(outcome)
    output = []
    for domain in sorted(reference | set(by_domain) | set(outcomes_by_domain)):
        rows = by_domain.get(domain, [])
        by_source = {
            source: [row for row in rows if row["source_type"] == source]
            for source in ("rdap", "whois")
        }
        source_values: dict[str, dict[str, set[str]]] = {}
        for source, source_rows in by_source.items():
            values: dict[str, set[str]] = defaultdict(set)
            for row in source_rows:
                for key, items in record_values(row).items():
                    values[key].update(items)
            source_values[source] = values
        conflict_fields = []
        for field in (
            "registry_ids",
            "status_codes",
            "nameservers",
            "registrar_names",
            "registration_dates",
            "expiration_dates",
            "last_changed_dates",
            "dnssec_status",
        ):
            left = source_values["rdap"].get(field, set())
            right = source_values["whois"].get(field, set())
            if left and right and left != right:
                conflict_fields.append(field)
        nameserver_map: dict[str, dict[str, set[str]]] = defaultdict(lambda: {"handles": set(), "sources": set()})
        registrar_entries: list[tuple[str, dict[str, Any]]] = []
        ds_records = []
        key_records = []
        conformance = set()
        registry_ids = set()
        lifecycle = {"registration": set(), "expiration": set(), "last_changed": set()}
        delegation = set()
        zone = set()
        dnssec_status = set()
        max_life = set()
        status_values_by_source = {"rdap": set(), "whois": set()}
        status_codes = set()
        for row in rows:
            registry_ids.update(row["registry_ids"])
            conformance.update(row["protocol_conformance"])
            registrar_entries.extend((row["source_type"], item) for item in row["registrars"])
            for item in row["statuses"]:
                status_values_by_source[row["source_type"]].add(item["source_value"])
                status_codes.add(item["normalized"])
            for item in row["nameservers"]:
                entry = nameserver_map[item["ldh_name"]]
                entry["sources"].add(row["source_type"])
                if item["registry_handle"]:
                    entry["handles"].add(item["registry_handle"])
            for key in lifecycle:
                lifecycle[key].update(row["lifecycle"][key])
            dnssec = row["dnssec"]
            if dnssec["delegation_signed"] is not None:
                delegation.add(dnssec["delegation_signed"])
            if dnssec["zone_signed"] is not None:
                zone.add(dnssec["zone_signed"])
            if dnssec["status"]:
                dnssec_status.add(dnssec["status"])
            if dnssec["max_signature_life"] is not None:
                max_life.add(dnssec["max_signature_life"])
            ds_records.extend(dnssec["ds_records"])
            key_records.extend(dnssec["key_records"])
        nameservers = [
            {
                "ldh_name": name,
                "registry_handles_observed": sorted(value["handles"]),
                "source_types": sorted(value["sources"]),
            }
            for name, value in sorted(nameserver_map.items())
        ]
        source_ids = {
            source: sorted(row["record_id"] for row in by_source[source])
            for source in ("rdap", "whois")
        }
        output.append(
            {
                "schema_version": SCHEMA_VERSION,
                "source_type": "merged",
                "domain": domain,
                "domain_in_reference_corpus": domain in reference,
                "standard_registrable_domain": registrable_domain(domain),
                "standard_public_suffix_model_match": standard_model_match(domain),
                "registration_object_basis": (
                    "authoritative_record" if rows
                    else "reference_corpus" if domain in reference
                    else "registrable_outcome"
                ),
                "sources_observed": [source for source in ("rdap", "whois") if by_source[source]],
                "source_outcomes": {
                    "rdap": [],
                    "whois": sorted({item["outcome"] for item in outcomes_by_domain.get(domain, [])}),
                },
                "source_outcome_ids": {
                    "rdap": [],
                    "whois": sorted(item["outcome_id"] for item in outcomes_by_domain.get(domain, [])),
                },
                "source_record_ids": source_ids,
                "source_record_variant_counts": {source: len(source_ids[source]) for source in source_ids},
                "registry_ids_observed": sorted(registry_ids),
                "status_codes_observed": sorted(status_codes),
                "status_values_by_source": {key: sorted(value) for key, value in status_values_by_source.items()},
                "nameservers_observed": nameservers,
                "registrars_observed": merge_registrars(registrar_entries),
                "lifecycle": {key: sorted(value) for key, value in lifecycle.items()},
                "dnssec": {
                    "statuses_observed": sorted(dnssec_status),
                    "delegation_signed_observed": sorted(delegation),
                    "zone_signed_observed": sorted(zone),
                    "max_signature_life_observed": sorted(max_life),
                    "ds_records_observed": sort_unique(ds_records),
                    "key_records_observed": sort_unique(key_records),
                },
                "protocol_conformance_observed": sorted(conformance),
                "cross_source_conflict_fields": sorted(conflict_fields),
                "has_cross_source_conflict": bool(conflict_fields),
            }
        )
    return output


def completeness(records: list[dict[str, Any]]) -> dict[str, dict[str, float | int]]:
    fields = {
        "registry_ids": lambda r: bool(r["registry_ids"]),
        "statuses": lambda r: bool(r["statuses"]),
        "nameservers": lambda r: bool(r["nameservers"]),
        "registrars": lambda r: bool(r["registrars"] and any(x.get("name") for x in r["registrars"])),
        "registration_date": lambda r: bool(r["lifecycle"]["registration"]),
        "expiration_date": lambda r: bool(r["lifecycle"]["expiration"]),
        "last_changed_date": lambda r: bool(r["lifecycle"]["last_changed"]),
        "dnssec_status": lambda r: bool(r["dnssec"]["status"]),
    }
    total = len(records)
    return {
        key: {
            "populated_records": sum(1 for record in records if test(record)),
            "total_records": total,
            "rate": round(sum(1 for record in records if test(record)) / total, 6) if total else 0.0,
        }
        for key, test in fields.items()
    }


def quality_summary(
    rdap: list[dict[str, Any]],
    whois: list[dict[str, Any]],
    whois_outcomes: list[dict[str, Any]],
    merged: list[dict[str, Any]],
    reference: set[str],
    diagnostics: Counter[str],
    duplicates: dict[str, int],
) -> dict[str, Any]:
    registered = [row for row in merged if row["sources_observed"]]
    conflicts = Counter(
        field for row in merged for field in row["cross_source_conflict_fields"]
    )
    rdap_domains = {row["domain"] for row in rdap}
    whois_domains = {row["domain"] for row in whois}
    outcome_counts = Counter(row["outcome"] for row in whois_outcomes)
    mismatch_outcomes = [
        row for row in whois_outcomes
        if row["outcome"] == "different_domain_returned"
    ]
    attached_outcome_ids = {
        outcome_id
        for row in merged
        for outcome_id in row["source_outcome_ids"]["whois"]
    }
    existing_domains = reference | rdap_domains | whois_domains
    expected_attached_outcome_ids = {
        row["outcome_id"]
        for row in whois_outcomes
        if (
            row["outcome"] == "different_domain_returned"
            and row["query_name"] in existing_domains
        ) or (
            row["outcome"] != "different_domain_returned"
            and row["query_name"] == row["registrable_domain"]
        )
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "grain": {
            "rdap": "one row per distinct privacy-safe RDAP record variant",
            "whois": "one row per distinct privacy-safe WHOIS record variant",
            "whois_outcomes": "one undated row per distinct query, normalized outcome, and returned-domain set",
            "merged": "one row per domain in the union of the reference corpus, registration records, and source outcomes",
        },
        "counts": {
            "reference_corpus_domains": len(reference),
            "rdap_domains": len(rdap_domains),
            "whois_domains": len(whois_domains),
            "domains_in_both_protocols": len(rdap_domains & whois_domains),
            "registration_domains_union": len(rdap_domains | whois_domains),
            "merged_domains": len(merged),
            "merged_domains_without_registration_record": len(merged) - len(registered),
            "rdap_record_variants": len(rdap),
            "whois_record_variants": len(whois),
            "rdap_duplicates_collapsed": duplicates["rdap"],
            "whois_duplicates_collapsed": duplicates["whois"],
            "whois_outcome_rows": len(whois_outcomes),
            "whois_outcome_query_names": len({row["query_name"] for row in whois_outcomes}),
            "whois_outcome_nonregistrable_query_names": sum(row["query_name"] != row["registrable_domain"] for row in whois_outcomes),
            "whois_different_domain_returned_rows": len(mismatch_outcomes),
            "whois_different_domain_returned_query_names": len({row["query_name"] for row in mismatch_outcomes}),
            "whois_different_domains_observed": len({domain for row in mismatch_outcomes for domain in row["returned_domains"]}),
            "whois_different_domain_returned_attached_rows": sum(row["outcome_id"] in attached_outcome_ids for row in mismatch_outcomes),
            "whois_different_domain_returned_unattached_rows": sum(row["outcome_id"] not in attached_outcome_ids for row in mismatch_outcomes),
            "authoritative_registration_objects_outside_standard_suffix_model": sum(row["registration_object_basis"] == "authoritative_record" and not row["standard_public_suffix_model_match"] for row in merged),
            "whois_outcome_duplicates_collapsed": duplicates["whois_outcomes"],
            "domains_with_cross_source_conflict": sum(row["has_cross_source_conflict"] for row in merged),
        },
        "whois_outcomes_by_type": dict(sorted(outcome_counts.items())),
        "diagnostics": dict(sorted(diagnostics.items())),
        "completeness": {
            "rdap_record_variants": completeness(rdap),
            "whois_record_variants": completeness(whois),
        },
        "cross_source_conflicts_by_field": dict(sorted(conflicts.items())),
        "checks": {
            "record_ids_unique": len({r["record_id"] for r in rdap + whois}) == len(rdap) + len(whois),
            "outcome_ids_unique": len({r["outcome_id"] for r in whois_outcomes}) == len(whois_outcomes),
            "outcome_returned_domains_valid": all(
                bool(row["returned_domains"]) and any(domain != row["query_name"] for domain in row["returned_domains"])
                if row["outcome"] == "different_domain_returned"
                else not row["returned_domains"]
                for row in whois_outcomes
            ),
            "outcome_attachments_exact": attached_outcome_ids == expected_attached_outcome_ids,
            "merged_domains_unique": len({r["domain"] for r in merged}) == len(merged),
            "all_domains_valid": all(normalized_domain(r["domain"]) == r["domain"] for r in rdap + whois + merged) and all(normalized_domain(r["query_name"]) == r["query_name"] for r in whois_outcomes),
            "outcome_registrable_derivation_valid": all(registrable_domain(r["query_name"]) == r["registrable_domain"] for r in whois_outcomes),
            "reference_corpus_fully_covered": reference <= {r["domain"] for r in merged},
        },
    }


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text("".join(canonical_json(row) + "\n" for row in rows), encoding="utf-8")


def write_outcomes_csv(path: Path, outcomes: list[dict[str, Any]]) -> None:
    fields = [
        "source_type", "query_name", "registrable_domain", "outcome",
        "returned_domains_json", "outcome_id",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for row in outcomes:
            writer.writerow(
                {
                    **{field: row[field] for field in fields if field != "returned_domains_json"},
                    "returned_domains_json": canonical_json(row["returned_domains"]),
                }
            )


def write_records_csv(path: Path, records: list[dict[str, Any]]) -> None:
    fields = [
        "source_type", "domain", "record_id", "object_class", "registration_object_basis",
        "standard_registrable_domain", "standard_public_suffix_model_match", "registry_ids_json",
        "statuses_json", "nameservers_json", "registrars_json", "registration_dates_json",
        "expiration_dates_json", "last_changed_dates_json", "dnssec_json", "protocol_conformance_json",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for row in records:
            writer.writerow(
                {
                    "source_type": row["source_type"],
                    "domain": row["domain"],
                    "record_id": row["record_id"],
                    "object_class": row["object_class"] or "",
                    "registration_object_basis": row["registration_object_basis"],
                    "standard_registrable_domain": row["standard_registrable_domain"],
                    "standard_public_suffix_model_match": str(row["standard_public_suffix_model_match"]).lower(),
                    "registry_ids_json": canonical_json(row["registry_ids"]),
                    "statuses_json": canonical_json(row["statuses"]),
                    "nameservers_json": canonical_json(row["nameservers"]),
                    "registrars_json": canonical_json(row["registrars"]),
                    "registration_dates_json": canonical_json(row["lifecycle"]["registration"]),
                    "expiration_dates_json": canonical_json(row["lifecycle"]["expiration"]),
                    "last_changed_dates_json": canonical_json(row["lifecycle"]["last_changed"]),
                    "dnssec_json": canonical_json(row["dnssec"]),
                    "protocol_conformance_json": canonical_json(row["protocol_conformance"]),
                }
            )


def write_merged_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fields = [
        "domain", "domain_in_reference_corpus", "registration_object_basis", "standard_registrable_domain",
        "standard_public_suffix_model_match", "sources_observed_json", "source_outcomes_json", "source_outcome_ids_json",
        "rdap_record_variant_count", "whois_record_variant_count", "registry_ids_observed_json", "status_codes_observed_json",
        "status_values_by_source_json", "nameservers_observed_json", "registrars_observed_json",
        "registration_dates_json", "expiration_dates_json", "last_changed_dates_json", "dnssec_json",
        "protocol_conformance_observed_json", "has_cross_source_conflict", "cross_source_conflict_fields_json",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "domain": row["domain"],
                    "domain_in_reference_corpus": str(row["domain_in_reference_corpus"]).lower(),
                    "registration_object_basis": row["registration_object_basis"],
                    "standard_registrable_domain": row["standard_registrable_domain"],
                    "standard_public_suffix_model_match": str(row["standard_public_suffix_model_match"]).lower(),
                    "sources_observed_json": canonical_json(row["sources_observed"]),
                    "source_outcomes_json": canonical_json(row["source_outcomes"]),
                    "source_outcome_ids_json": canonical_json(row["source_outcome_ids"]),
                    "rdap_record_variant_count": row["source_record_variant_counts"]["rdap"],
                    "whois_record_variant_count": row["source_record_variant_counts"]["whois"],
                    "registry_ids_observed_json": canonical_json(row["registry_ids_observed"]),
                    "status_codes_observed_json": canonical_json(row["status_codes_observed"]),
                    "status_values_by_source_json": canonical_json(row["status_values_by_source"]),
                    "nameservers_observed_json": canonical_json(row["nameservers_observed"]),
                    "registrars_observed_json": canonical_json(row["registrars_observed"]),
                    "registration_dates_json": canonical_json(row["lifecycle"]["registration"]),
                    "expiration_dates_json": canonical_json(row["lifecycle"]["expiration"]),
                    "last_changed_dates_json": canonical_json(row["lifecycle"]["last_changed"]),
                    "dnssec_json": canonical_json(row["dnssec"]),
                    "protocol_conformance_observed_json": canonical_json(row["protocol_conformance_observed"]),
                    "has_cross_source_conflict": str(row["has_cross_source_conflict"]).lower(),
                    "cross_source_conflict_fields_json": canonical_json(row["cross_source_conflict_fields"]),
                }
            )


def write_sqlite(
    path: Path, records: list[dict[str, Any]],
    outcomes: list[dict[str, Any]], merged: list[dict[str, Any]],
) -> None:
    if path.exists():
        path.unlink()
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        PRAGMA page_size=4096;
        PRAGMA journal_mode=DELETE;
        PRAGMA foreign_keys=ON;
        CREATE TABLE records (
          record_id TEXT PRIMARY KEY, source_type TEXT NOT NULL, domain TEXT NOT NULL,
          object_class TEXT, registration_object_basis TEXT NOT NULL, standard_registrable_domain TEXT NOT NULL,
          standard_public_suffix_model_match INTEGER NOT NULL, registry_ids_json TEXT NOT NULL, registrars_json TEXT NOT NULL,
          dnssec_json TEXT NOT NULL
        );
        CREATE TABLE record_statuses (
          record_id TEXT NOT NULL REFERENCES records(record_id), source_value TEXT NOT NULL,
          normalized TEXT NOT NULL, PRIMARY KEY(record_id, source_value, normalized)
        ) WITHOUT ROWID;
        CREATE TABLE record_nameservers (
          record_id TEXT NOT NULL REFERENCES records(record_id), ldh_name TEXT NOT NULL,
          registry_handle TEXT, PRIMARY KEY(record_id, ldh_name, registry_handle)
        );
        CREATE TABLE lifecycle_events (
          record_id TEXT NOT NULL REFERENCES records(record_id), action TEXT NOT NULL,
          event_date TEXT NOT NULL, PRIMARY KEY(record_id, action, event_date)
        ) WITHOUT ROWID;
        CREATE TABLE protocol_conformance (
          record_id TEXT NOT NULL REFERENCES records(record_id), value TEXT NOT NULL,
          PRIMARY KEY(record_id, value)
        ) WITHOUT ROWID;
        CREATE TABLE source_outcomes (
          outcome_id TEXT PRIMARY KEY, source_type TEXT NOT NULL, query_name TEXT NOT NULL, registrable_domain TEXT NOT NULL,
          outcome TEXT NOT NULL CHECK(outcome IN ('no_record','query_error','unparseable','different_domain_returned')),
          returned_domains_json TEXT NOT NULL
        );
        CREATE TABLE merged_domains (
          domain TEXT PRIMARY KEY, domain_in_reference_corpus INTEGER NOT NULL,
          registration_object_basis TEXT NOT NULL, standard_registrable_domain TEXT NOT NULL, standard_public_suffix_model_match INTEGER NOT NULL,
          sources_observed_json TEXT NOT NULL, source_outcomes_json TEXT NOT NULL, source_outcome_ids_json TEXT NOT NULL,
          source_record_ids_json TEXT NOT NULL,
          registry_ids_observed_json TEXT NOT NULL, status_codes_observed_json TEXT NOT NULL,
          status_values_by_source_json TEXT NOT NULL, nameservers_observed_json TEXT NOT NULL,
          registrars_observed_json TEXT NOT NULL, lifecycle_json TEXT NOT NULL,
          dnssec_json TEXT NOT NULL, protocol_conformance_observed_json TEXT NOT NULL,
          cross_source_conflict_fields_json TEXT NOT NULL, has_cross_source_conflict INTEGER NOT NULL
        );
        CREATE INDEX records_domain_idx ON records(domain, source_type);
        CREATE INDEX nameserver_idx ON record_nameservers(ldh_name);
        CREATE INDEX lifecycle_date_idx ON lifecycle_events(event_date, action);
        CREATE INDEX source_outcomes_domain_idx ON source_outcomes(registrable_domain, query_name, outcome);
        """
    )
    for row in records:
        connection.execute(
            "INSERT INTO records VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                row["record_id"], row["source_type"], row["domain"], row["object_class"],
                row["registration_object_basis"], row["standard_registrable_domain"],
                int(row["standard_public_suffix_model_match"]),
                canonical_json(row["registry_ids"]), canonical_json(row["registrars"]), canonical_json(row["dnssec"]),
            ),
        )
        for status in row["statuses"]:
            connection.execute("INSERT INTO record_statuses VALUES (?,?,?)", (row["record_id"], status["source_value"], status["normalized"]))
        for nameserver in row["nameservers"]:
            connection.execute("INSERT INTO record_nameservers VALUES (?,?,?)", (row["record_id"], nameserver["ldh_name"], nameserver["registry_handle"]))
        for action, dates in row["lifecycle"].items():
            for date in dates:
                connection.execute("INSERT INTO lifecycle_events VALUES (?,?,?)", (row["record_id"], action, date))
        for value in row["protocol_conformance"]:
            connection.execute("INSERT INTO protocol_conformance VALUES (?,?)", (row["record_id"], value))
    for row in outcomes:
        connection.execute(
            "INSERT INTO source_outcomes VALUES (?,?,?,?,?,?)",
            (
                row["outcome_id"], row["source_type"], row["query_name"],
                row["registrable_domain"], row["outcome"],
                canonical_json(row["returned_domains"]),
            ),
        )
    for row in merged:
        connection.execute(
            "INSERT INTO merged_domains VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                row["domain"], int(row["domain_in_reference_corpus"]),
                row["registration_object_basis"], row["standard_registrable_domain"],
                int(row["standard_public_suffix_model_match"]),
                canonical_json(row["sources_observed"]),
                canonical_json(row["source_outcomes"]),
                canonical_json(row["source_outcome_ids"]), canonical_json(row["source_record_ids"]),
                canonical_json(row["registry_ids_observed"]),
                canonical_json(row["status_codes_observed"]), canonical_json(row["status_values_by_source"]),
                canonical_json(row["nameservers_observed"]), canonical_json(row["registrars_observed"]),
                canonical_json(row["lifecycle"]), canonical_json(row["dnssec"]),
                canonical_json(row["protocol_conformance_observed"]), canonical_json(row["cross_source_conflict_fields"]),
                int(row["has_cross_source_conflict"]),
            ),
        )
    connection.commit()
    connection.execute("VACUUM")
    connection.close()


def checksum_outputs(root: Path) -> None:
    paths = sorted(
        path for path in (root / "data").iterdir()
        if path.is_file() and path.name != "CHECKSUMS.sha256"
    )
    lines = []
    for path in paths:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.name}\n")
    (root / "data" / "CHECKSUMS.sha256").write_text("".join(lines), encoding="ascii")


def build(args: argparse.Namespace) -> None:
    diagnostics: Counter[str] = Counter()
    rdap_seen = []
    whois_seen = []
    whois_outcomes_seen = []
    for directory in args.rdap_input:
        for path in sorted(directory.glob("*.json")):
            rdap_seen.extend(parse_rdap(path, diagnostics))
    for directory in args.whois_input:
        for path in sorted(directory.glob("*.txt")):
            records, outcomes = parse_whois(path, diagnostics)
            whois_seen.extend(records)
            whois_outcomes_seen.extend(outcomes)
    rdap, rdap_duplicates = deduplicate(rdap_seen)
    whois, whois_duplicates = deduplicate(whois_seen)
    whois_outcomes, outcome_duplicates = deduplicate(whois_outcomes_seen, "outcome_id")
    reference = read_domain_universe(args.domain_universe)
    merged = merge_domains(rdap + whois, reference, whois_outcomes)
    quality = quality_summary(
        rdap, whois, whois_outcomes, merged, reference, diagnostics,
        {"rdap": rdap_duplicates, "whois": whois_duplicates, "whois_outcomes": outcome_duplicates},
    )
    if not all(quality["checks"].values()):
        raise RuntimeError("quality invariants failed")
    output = args.output.resolve()
    data = output / "data"
    data.mkdir(parents=True, exist_ok=True)
    write_jsonl(data / "rdap.jsonl", rdap)
    write_jsonl(data / "whois.jsonl", whois)
    write_jsonl(data / "whois-outcomes.jsonl", whois_outcomes)
    write_jsonl(data / "merged.jsonl", merged)
    write_records_csv(data / "records.csv", rdap + whois)
    write_outcomes_csv(data / "whois-outcomes.csv", whois_outcomes)
    write_merged_csv(data / "merged.csv", merged)
    write_sqlite(data / "registration.sqlite", rdap + whois, whois_outcomes, merged)
    (data / "quality-metrics.json").write_text(pretty_json(quality), encoding="utf-8")
    checksum_outputs(output)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--rdap-input", action="append", type=Path, default=[], help="directory of RDAP JSON records; repeatable")
    value.add_argument("--whois-input", action="append", type=Path, default=[], help="directory of WHOIS text records; repeatable")
    value.add_argument("--domain-universe", type=Path, help="optional CSV with a domain column")
    value.add_argument("--output", type=Path, default=Path.cwd(), help="repository/output root")
    return value


if __name__ == "__main__":
    build(parser().parse_args())
