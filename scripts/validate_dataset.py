#!/usr/bin/env python3
"""Validate release integrity, privacy, determinism, and reconciliation."""

from __future__ import annotations

import csv
import hashlib
import json
import re
import sqlite3
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_dataset import (  # noqa: E402
    SCHEMA_VERSION,
    canonical_json,
    merge_domains,
    normalized_domain,
    registrable_domain,
    standard_model_match,
    normalized_timestamp,
    write_merged_csv,
    write_outcomes_csv,
    write_records_csv,
    write_sqlite,
)

DATA = ROOT / "data"
REQUIRED = {
    "rdap.jsonl",
    "whois.jsonl",
    "whois-outcomes.jsonl",
    "whois-outcomes.csv",
    "merged.jsonl",
    "records.csv",
    "merged.csv",
    "registration.sqlite",
    "quality-metrics.json",
    "CHECKSUMS.sha256",
}
SOURCE_KEYS = {
    "schema_version", "source_type", "domain", "object_class", "registry_ids",
    "statuses", "nameservers", "registrars", "lifecycle", "dnssec",
    "protocol_conformance", "record_id", "registration_object_basis",
    "standard_registrable_domain", "standard_public_suffix_model_match",
}
MERGED_KEYS = {
    "schema_version", "source_type", "domain", "domain_in_reference_corpus",
    "sources_observed", "source_outcomes", "source_outcome_ids", "source_record_ids", "source_record_variant_counts",
    "registration_object_basis", "standard_registrable_domain", "standard_public_suffix_model_match",
    "registry_ids_observed", "status_codes_observed", "status_values_by_source",
    "nameservers_observed", "registrars_observed", "lifecycle", "dnssec",
    "protocol_conformance_observed", "cross_source_conflict_fields",
    "has_cross_source_conflict",
}
BLOCKED_KEY_PARTS = {
    "email", "phone", "telephone", "fax", "address", "street", "postal",
    "locality", "country", "entity", "entities", "vcardarray", "link", "notice",
    "remark", "url", "response_header", "collected_at", "fetched_at",
    "generated_at", "queried_at", "query_time", "source_path", "file_path",
}
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
URL_RE = re.compile(r"https?://", re.I)
LOCAL_PATH_RE = re.compile(r"(?:^|[\s\"'])(?:/home/|/Users/|[A-Za-z]:[\\/])")


def fail(message: str) -> None:
    raise AssertionError(message)


def sorted_unique(values: list[Any]) -> bool:
    keys = [canonical_json(value) for value in values]
    return keys == sorted(set(keys))


def load_jsonl(name: str) -> list[dict[str, Any]]:
    rows = []
    previous = None
    for number, line in enumerate((DATA / name).read_text(encoding="utf-8").splitlines(), 1):
        if not line:
            fail(f"{name}:{number}: blank line")
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            fail(f"{name}:{number}: invalid JSON: {exc}")
        if line != canonical_json(row):
            fail(f"{name}:{number}: not canonical JSON")
        key = (row.get("domain", row.get("query_name", "")), row.get("record_id", row.get("outcome_id", "")))
        if previous is not None and key < previous:
            fail(f"{name}:{number}: rows are not sorted")
        previous = key
        rows.append(row)
    return rows


def privacy_walk(value: Any, location: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            folded = key.casefold()
            if any(part == folded or part in folded for part in BLOCKED_KEY_PARTS):
                fail(f"{location}: blocked personal/provenance key {key!r}")
            privacy_walk(child, f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            privacy_walk(child, f"{location}[{index}]")
    elif isinstance(value, str):
        if EMAIL_RE.search(value):
            fail(f"{location}: email-like value")
        if URL_RE.search(value):
            fail(f"{location}: URL value")
        if LOCAL_PATH_RE.search(value):
            fail(f"{location}: local path value")


def validate_timestamp(value: str, location: str) -> None:
    if normalized_timestamp(value) != value:
        fail(f"{location}: invalid or non-canonical timestamp")


def validate_registrars(registrars: list[dict[str, Any]], location: str) -> None:
    for index, registrar in enumerate(registrars):
        here = f"{location}[{index}]"
        if set(registrar) != {"registry_handle", "name", "public_ids", "vcard_version"}:
            fail(f"{here}: unexpected keys")
        if not any((registrar["registry_handle"], registrar["name"], registrar["public_ids"], registrar["vcard_version"])):
            fail(f"{here}: all-null registrar object")
        if not sorted_unique(registrar["public_ids"]):
            fail(f"{here}: public IDs not sorted/unique")
        for public_id in registrar["public_ids"]:
            if set(public_id) != {"type", "identifier"}:
                fail(f"{here}: malformed public ID")
            if not public_id["type"] or not public_id["identifier"]:
                fail(f"{here}: null/empty public ID")


def validate_source_record(row: dict[str, Any], source: str, location: str) -> None:
    if set(row) != SOURCE_KEYS:
        fail(f"{location}: unexpected top-level keys")
    if row["schema_version"] != SCHEMA_VERSION or row["source_type"] != source:
        fail(f"{location}: schema/source mismatch")
    if normalized_domain(row["domain"]) != row["domain"]:
        fail(f"{location}: invalid domain")
    if row["registration_object_basis"] != "authoritative_record":
        fail(f"{location}: source record must be authoritative")
    if row["standard_registrable_domain"] != registrable_domain(row["domain"]):
        fail(f"{location}: incorrect standard registrable domain")
    if row["standard_public_suffix_model_match"] != standard_model_match(row["domain"]):
        fail(f"{location}: incorrect standard suffix model flag")
    body = {key: value for key, value in row.items() if key != "record_id"}
    expected = "sha256:" + hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
    if row["record_id"] != expected:
        fail(f"{location}: record hash mismatch")
    for field in ("registry_ids", "statuses", "nameservers", "registrars", "protocol_conformance"):
        if not isinstance(row[field], list) or not sorted_unique(row[field]):
            fail(f"{location}: {field} must be sorted and unique")
    for status in row["statuses"]:
        if set(status) != {"source_value", "normalized"} or not all(status.values()):
            fail(f"{location}: malformed status")
    for nameserver in row["nameservers"]:
        if set(nameserver) != {"ldh_name", "registry_handle"}:
            fail(f"{location}: malformed nameserver")
        if normalized_domain(nameserver["ldh_name"]) != nameserver["ldh_name"]:
            fail(f"{location}: invalid nameserver")
    validate_registrars(row["registrars"], f"{location}.registrars")
    if set(row["lifecycle"]) != {"registration", "expiration", "last_changed"}:
        fail(f"{location}: malformed lifecycle")
    for action, values in row["lifecycle"].items():
        if not sorted_unique(values):
            fail(f"{location}: lifecycle {action} is not sorted/unique")
        for value in values:
            validate_timestamp(value, f"{location}.lifecycle.{action}")
    dnssec = row["dnssec"]
    if set(dnssec) != {
        "status", "delegation_signed", "zone_signed", "max_signature_life",
        "ds_records", "key_records",
    }:
        fail(f"{location}: malformed DNSSEC object")
    for field in ("delegation_signed", "zone_signed"):
        if dnssec[field] is not None and not isinstance(dnssec[field], bool):
            fail(f"{location}: DNSSEC boolean type")
    for field in ("ds_records", "key_records"):
        if not isinstance(dnssec[field], list) or not sorted_unique(dnssec[field]):
            fail(f"{location}: DNSSEC {field} not sorted/unique")
    privacy_walk(row, location)


def validate_outcome(row: dict[str, Any], location: str) -> None:
    if set(row) != {
        "schema_version", "source_type", "query_name", "registrable_domain",
        "outcome", "returned_domains", "outcome_id",
    }:
        fail(f"{location}: unexpected outcome keys")
    if row["schema_version"] != SCHEMA_VERSION or row["source_type"] != "whois":
        fail(f"{location}: outcome schema/source mismatch")
    if normalized_domain(row["query_name"]) != row["query_name"]:
        fail(f"{location}: invalid outcome query name")
    if registrable_domain(row["query_name"]) != row["registrable_domain"]:
        fail(f"{location}: incorrect outcome registrable domain")
    if row["outcome"] not in {
        "no_record", "query_error", "unparseable", "different_domain_returned",
    }:
        fail(f"{location}: invalid normalized outcome")
    returned = row["returned_domains"]
    if not isinstance(returned, list) or not sorted_unique(returned):
        fail(f"{location}: returned domains must be sorted and unique")
    if any(normalized_domain(domain) != domain for domain in returned):
        fail(f"{location}: invalid returned domain")
    if row["outcome"] == "different_domain_returned":
        if not returned or not any(domain != row["query_name"] for domain in returned):
            fail(f"{location}: mismatch outcome lacks a different returned domain")
    elif returned:
        fail(f"{location}: non-mismatch outcome contains returned domains")
    body = {key: value for key, value in row.items() if key != "outcome_id"}
    expected = "sha256:" + hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
    if row["outcome_id"] != expected:
        fail(f"{location}: outcome hash mismatch")
    privacy_walk(row, location)


def validate_merged_registrars(rows: list[dict[str, Any]], location: str) -> None:
    identities = set()
    for index, registrar in enumerate(rows):
        here = f"{location}[{index}]"
        if set(registrar) != {
            "names_observed", "registry_handles_observed", "public_ids_observed",
            "vcard_versions_observed", "source_types",
        }:
            fail(f"{here}: malformed merged registrar")
        for field in registrar:
            if not isinstance(registrar[field], list) or not sorted_unique(registrar[field]):
                fail(f"{here}: {field} not sorted/unique")
        if not any(registrar[field] for field in registrar if field != "source_types"):
            fail(f"{here}: all-null merged registrar")
        for public_id in registrar["public_ids_observed"]:
            if not public_id.get("type") or not public_id.get("identifier"):
                fail(f"{here}: null/empty merged public ID")
        if registrar["names_observed"]:
            identity = ("name", tuple(name.casefold() for name in registrar["names_observed"]))
        elif registrar["registry_handles_observed"]:
            identity = ("handle", tuple(registrar["registry_handles_observed"]))
        else:
            identity = ("ids", canonical_json(registrar["public_ids_observed"]))
        if identity in identities:
            fail(f"{here}: semantic registrar duplicate")
        identities.add(identity)


def validate_checksums() -> None:
    entries = {}
    for line in (DATA / "CHECKSUMS.sha256").read_text(encoding="ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
        if not match:
            fail("malformed checksum line")
        digest, name = match.groups()
        if name in entries:
            fail("duplicate checksum entry")
        entries[name] = digest
    expected_names = REQUIRED - {"CHECKSUMS.sha256"}
    if set(entries) != expected_names:
        fail("checksum file set mismatch")
    for name, expected in entries.items():
        actual = hashlib.sha256((DATA / name).read_bytes()).hexdigest()
        if actual != expected:
            fail(f"checksum mismatch: {name}")


def validate_csv(records: list[dict[str, Any]], outcomes: list[dict[str, Any]], merged: list[dict[str, Any]]) -> None:
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        write_records_csv(directory / "records.csv", records)
        write_outcomes_csv(directory / "whois-outcomes.csv", outcomes)
        write_merged_csv(directory / "merged.csv", merged)
        for name in ("records.csv", "whois-outcomes.csv", "merged.csv"):
            if (directory / name).read_bytes() != (DATA / name).read_bytes():
                fail(f"{name}: not the deterministic projection")
    with (DATA / "records.csv").open(encoding="utf-8", newline="") as handle:
        if sum(1 for _ in csv.DictReader(handle)) != len(records):
            fail("records.csv row count mismatch")
    with (DATA / "whois-outcomes.csv").open(encoding="utf-8", newline="") as handle:
        if sum(1 for _ in csv.DictReader(handle)) != len(outcomes):
            fail("whois-outcomes.csv row count mismatch")
    with (DATA / "merged.csv").open(encoding="utf-8", newline="") as handle:
        if sum(1 for _ in csv.DictReader(handle)) != len(merged):
            fail("merged.csv row count mismatch")


def validate_sqlite(records: list[dict[str, Any]], outcomes: list[dict[str, Any]], merged: list[dict[str, Any]]) -> None:
    def canonical_dump(path: Path) -> tuple[str, ...]:
        database = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            return tuple(database.iterdump())
        finally:
            database.close()

    with tempfile.TemporaryDirectory() as directory:
        expected_path = Path(directory) / "registration.sqlite"
        write_sqlite(expected_path, records, outcomes, merged)
        if canonical_dump(expected_path) != canonical_dump(DATA / "registration.sqlite"):
            fail("SQLite is not the exact deterministic projection")

    connection = sqlite3.connect(f"file:{DATA / 'registration.sqlite'}?mode=ro", uri=True)
    try:
        if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            fail("SQLite integrity check failed")
        if connection.execute("PRAGMA foreign_key_check").fetchall():
            fail("SQLite foreign-key check failed")
    finally:
        connection.close()
    connection = sqlite3.connect(f"file:{DATA / 'registration.sqlite'}?mode=ro", uri=True)
    if connection.execute("SELECT count(*) FROM records").fetchone()[0] != len(records):
        fail("SQLite source record count mismatch")
    if connection.execute("SELECT count(*) FROM merged_domains").fetchone()[0] != len(merged):
        fail("SQLite merged count mismatch")
    if connection.execute("SELECT count(*) FROM source_outcomes").fetchone()[0] != len(outcomes):
        fail("SQLite source outcome count mismatch")
    source_counts = dict(connection.execute("SELECT source_type, count(*) FROM records GROUP BY source_type"))
    expected = {
        "rdap": sum(row["source_type"] == "rdap" for row in records),
        "whois": sum(row["source_type"] == "whois" for row in records),
    }
    if source_counts != expected:
        fail("SQLite protocol counts mismatch")
    connection.close()


def validate_metrics(
    metrics: dict[str, Any],
    rdap: list[dict[str, Any]],
    whois: list[dict[str, Any]],
    outcomes: list[dict[str, Any]],
    merged: list[dict[str, Any]],
) -> None:
    counts = metrics["counts"]
    mismatch = [
        row for row in outcomes
        if row["outcome"] == "different_domain_returned"
    ]
    attached = {
        outcome_id
        for row in merged
        for outcome_id in row["source_outcome_ids"]["whois"]
    }
    expected = {
        "rdap_record_variants": len(rdap),
        "whois_record_variants": len(whois),
        "whois_outcome_rows": len(outcomes),
        "whois_outcome_query_names": len({row["query_name"] for row in outcomes}),
        "whois_outcome_nonregistrable_query_names": sum(row["query_name"] != row["registrable_domain"] for row in outcomes),
        "whois_different_domain_returned_rows": len(mismatch),
        "whois_different_domain_returned_query_names": len({row["query_name"] for row in mismatch}),
        "whois_different_domains_observed": len({domain for row in mismatch for domain in row["returned_domains"]}),
        "whois_different_domain_returned_attached_rows": sum(row["outcome_id"] in attached for row in mismatch),
        "whois_different_domain_returned_unattached_rows": sum(row["outcome_id"] not in attached for row in mismatch),
        "authoritative_registration_objects_outside_standard_suffix_model": sum(row["registration_object_basis"] == "authoritative_record" and not row["standard_public_suffix_model_match"] for row in merged),
        "rdap_domains": len({row["domain"] for row in rdap}),
        "whois_domains": len({row["domain"] for row in whois}),
        "merged_domains": len(merged),
        "merged_domains_without_registration_record": sum(not row["sources_observed"] for row in merged),
        "domains_with_cross_source_conflict": sum(row["has_cross_source_conflict"] for row in merged),
    }
    for key, value in expected.items():
        if counts.get(key) != value:
            fail(f"quality metric mismatch: {key}")
    expected_outcome_types = dict(sorted(Counter(row["outcome"] for row in outcomes).items()))
    if metrics["whois_outcomes_by_type"] != expected_outcome_types:
        fail("quality metric mismatch: whois_outcomes_by_type")
    if metrics["diagnostics"].get("whois_outcome_different_domain_returned", 0) < len(mismatch):
        fail("mismatch artifact diagnostics cannot be below unique mismatch outcomes")
    if not all(metrics["checks"].values()):
        fail("quality invariant marked false")
    privacy_walk(metrics, "quality-metrics.json")


def main() -> None:
    if {path.name for path in DATA.iterdir() if path.is_file()} != REQUIRED:
        fail("unexpected or missing data files")
    rdap = load_jsonl("rdap.jsonl")
    whois = load_jsonl("whois.jsonl")
    outcomes = load_jsonl("whois-outcomes.jsonl")
    merged = load_jsonl("merged.jsonl")
    all_records = rdap + whois
    identifiers = set()
    for source, rows in (("rdap", rdap), ("whois", whois)):
        for index, row in enumerate(rows, 1):
            validate_source_record(row, source, f"{source}.jsonl:{index}")
            if row["record_id"] in identifiers:
                fail("duplicate record ID across protocols")
            identifiers.add(row["record_id"])
    outcome_ids = set()
    for index, row in enumerate(outcomes, 1):
        validate_outcome(row, f"whois-outcomes.jsonl:{index}")
        if row["outcome_id"] in outcome_ids:
            fail("duplicate outcome ID")
        outcome_ids.add(row["outcome_id"])
    reference = {row["domain"] for row in merged if row["domain_in_reference_corpus"]}
    expected_merged = merge_domains(all_records, reference, outcomes)
    if merged != expected_merged:
        fail("merged.jsonl is not the exact canonical merge")
    previous = None
    for index, row in enumerate(merged, 1):
        location = f"merged.jsonl:{index}"
        if set(row) != MERGED_KEYS:
            fail(f"{location}: unexpected keys")
        if row["schema_version"] != SCHEMA_VERSION or row["source_type"] != "merged":
            fail(f"{location}: schema/source mismatch")
        if previous is not None and row["domain"] <= previous:
            fail(f"{location}: domain order/uniqueness failure")
        previous = row["domain"]
        if row["standard_registrable_domain"] != registrable_domain(row["domain"]):
            fail(f"{location}: bad standard registrable domain")
        if row["standard_public_suffix_model_match"] != standard_model_match(row["domain"]):
            fail(f"{location}: bad standard suffix model flag")
        if row["registration_object_basis"] not in {"authoritative_record", "reference_corpus", "registrable_outcome"}:
            fail(f"{location}: invalid registration object basis")
        if not row["standard_public_suffix_model_match"] and row["registration_object_basis"] != "authoritative_record":
            fail(f"{location}: nonstandard merged object lacks authoritative evidence")
        if not isinstance(row["sources_observed"], list) or not sorted_unique(row["sources_observed"]):
            fail(f"{location}: sources_observed must be sorted and unique")
        if any(source not in {"rdap", "whois"} for source in row["sources_observed"]):
            fail(f"{location}: invalid observed source")
        for field in ("source_outcomes", "source_outcome_ids", "source_record_ids", "source_record_variant_counts"):
            if set(row[field]) != {"rdap", "whois"}:
                fail(f"{location}: {field} must contain both protocols")
        for field in ("source_outcomes", "source_outcome_ids", "source_record_ids"):
            for source, values in row[field].items():
                if not isinstance(values, list) or not sorted_unique(values):
                    fail(f"{location}: {field}.{source} must be sorted and unique")
        if row["source_outcomes"]["rdap"] or row["source_outcome_ids"]["rdap"]:
            fail(f"{location}: RDAP outcomes are not part of this release")
        if not set(row["source_outcome_ids"]["whois"]) <= outcome_ids:
            fail(f"{location}: unknown WHOIS outcome ID")
        observed_record_ids = {
            record_id
            for values in row["source_record_ids"].values()
            for record_id in values
        }
        if not observed_record_ids <= identifiers:
            fail(f"{location}: unknown source record ID")
        for source in ("rdap", "whois"):
            if row["source_record_variant_counts"][source] != len(row["source_record_ids"][source]):
                fail(f"{location}: source record variant count mismatch")
        validate_merged_registrars(row["registrars_observed"], f"{location}.registrars_observed")
        privacy_walk(row, location)
    validate_csv(all_records, outcomes, merged)
    validate_sqlite(all_records, outcomes, merged)
    metrics = json.loads((DATA / "quality-metrics.json").read_text(encoding="utf-8"))
    validate_metrics(metrics, rdap, whois, outcomes, merged)
    validate_checksums()
    print(
        "validated:",
        f"{len(rdap)} RDAP variants,",
        f"{len(whois)} WHOIS variants,",
        f"{len(merged)} merged domains,",
        f"{sum(not row['sources_observed'] for row in merged)} without registration records",
    )


if __name__ == "__main__":
    main()
