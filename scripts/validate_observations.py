#!/usr/bin/env python3
"""Validate the complete public CT and RDAP observation archive."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
OBSERVATIONS = ROOT / "observations"
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+ye$"
)
PUBLIC_SUFFIXES = (
    "biz.ye", "com.ye", "edu.ye", "gov.ye", "hospital.ye", "law.ye",
    "me.ye", "mil.ye", "net.ye", "org.ye", "pro.ye", "school.ye",
    "tv.ye", "uni.ye", "ye",
)
RDAP_STATUSES = {
    "unqueried", "registered", "not_found", "temporary_error",
    "invalid_response", "transport_error",
}
RDAP_CLASSIFICATIONS = {
    "registered", "not_found", "temporary_error", "invalid_response",
}


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fail(message: str) -> None:
    raise AssertionError(message)


def normalized_domain(value: object) -> str:
    text = str(value or "").strip().lower().rstrip(".")
    if not DOMAIN_RE.fullmatch(text):
        return ""
    return text


def registrable_domain(value: object) -> str:
    name = normalized_domain(value)
    if not name or name in PUBLIC_SUFFIXES:
        return ""
    matches = [
        suffix for suffix in PUBLIC_SUFFIXES
        if name != suffix and name.endswith(f".{suffix}")
    ]
    if not matches:
        return ""
    suffix = max(matches, key=lambda item: item.count("."))
    labels = name.split(".")
    suffix_labels = suffix.split(".")
    return ".".join(labels[-len(suffix_labels) - 1:])


def canonical_time(value: object) -> str:
    if not isinstance(value, str):
        fail("timestamp must be a string")
    parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        fail(f"non-canonical timestamp: {value}")
    return value


def canonical_date(value: object) -> str:
    if not isinstance(value, str):
        fail("date must be a string")
    parsed = datetime.strptime(value, "%Y-%m-%d")
    if parsed.strftime("%Y-%m-%d") != value:
        fail(f"non-canonical date: {value}")
    return value


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        fail(f"missing {path.relative_to(ROOT)}")
    rows = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line:
            fail(f"{path}:{number}: blank line")
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            fail(f"{path}:{number}: invalid JSON: {exc}")
        if not isinstance(value, dict) or canonical_json(value) != line:
            fail(f"{path}:{number}: non-canonical object")
        rows.append(value)
    return rows


def hash_path(family: str, value: str, suffix: str) -> Path:
    if not HEX_64.fullmatch(value):
        fail(f"invalid SHA-256 value: {value}")
    return OBSERVATIONS / family / "sha256" / value[:2] / f"{value}{suffix}"


def validate_header_pairs(value: object, label: str) -> None:
    if not isinstance(value, list):
        fail(f"{label}: headers must be an array")
    for pair in value:
        if (
            not isinstance(pair, list)
            or len(pair) != 2
            or not all(isinstance(item, str) for item in pair)
            or pair[0] != pair[0].lower()
        ):
            fail(f"{label}: invalid header pair")


def validate_rdap() -> tuple[dict[str, dict], set[Path]]:
    rows = load_jsonl(OBSERVATIONS / "rdap/index.jsonl")
    keys = {
        "schema_version", "observed_at", "domain", "http_status", "media_type",
        "body_sha256", "exchange_sha256", "classification",
        "registration_events", "observation_id",
    }
    observations = {}
    referenced = set()
    ordering = []
    for number, row in enumerate(rows, 1):
        label = f"rdap index line {number}"
        if set(row) != keys or row["schema_version"] != 1:
            fail(f"{label}: unexpected schema")
        domain = row["domain"]
        if registrable_domain(domain) != domain:
            fail(f"{label}: invalid registrable domain")
        canonical_time(row["observed_at"])
        if type(row["http_status"]) is not int or not 100 <= row["http_status"] <= 599:
            fail(f"{label}: invalid HTTP status")
        if row["classification"] not in RDAP_CLASSIFICATIONS:
            fail(f"{label}: invalid classification")
        if not isinstance(row["registration_events"], list):
            fail(f"{label}: registration events must be an array")
        if row["registration_events"] != sorted(set(row["registration_events"])):
            fail(f"{label}: registration events are not sorted and unique")
        body = {key: value for key, value in row.items() if key != "observation_id"}
        expected_id = digest(canonical_json(body).encode())
        if row["observation_id"] != expected_id or expected_id in observations:
            fail(f"{label}: observation ID mismatch or duplicate")
        observations[expected_id] = row

        suffix = (
            ".json"
            if row["media_type"] in {"application/json", "application/rdap+json"}
            else ".bin"
        )
        body_path = hash_path("rdap/bodies", row["body_sha256"], suffix)
        exchange_path = hash_path("rdap/exchanges", row["exchange_sha256"], ".json")
        for path, expected in (
            (body_path, row["body_sha256"]),
            (exchange_path, row["exchange_sha256"]),
        ):
            if not path.is_file() or digest(path.read_bytes()) != expected:
                fail(f"{label}: missing or corrupt {path.relative_to(ROOT)}")
            referenced.add(path)

        exchange_text = exchange_path.read_text(encoding="utf-8")
        if not exchange_text.endswith("\n") or exchange_text.count("\n") != 1:
            fail(f"{label}: exchange is not one canonical JSON line")
        exchange = json.loads(exchange_text)
        if canonical_json(exchange) + "\n" != exchange_text:
            fail(f"{label}: exchange is not canonical")
        if (
            exchange.get("domain") != domain
            or exchange.get("observed_at") != row["observed_at"]
            or exchange.get("classification") != row["classification"]
            or exchange.get("registration_events") != row["registration_events"]
        ):
            fail(f"{label}: exchange/index mismatch")
        request = exchange.get("request")
        response = exchange.get("response")
        if not isinstance(request, dict) or not isinstance(response, dict):
            fail(f"{label}: request or response is not an object")
        if set(request) != {"method", "url", "headers"} or request["method"] != "GET":
            fail(f"{label}: invalid request metadata")
        parsed_url = urlparse(request["url"])
        if parsed_url.scheme != "https" or not parsed_url.hostname:
            fail(f"{label}: request URL is not HTTPS")
        validate_header_pairs(request["headers"], f"{label}.request")
        if set(response) != {
            "http_version", "status_code", "headers", "body_sha256",
            "body_encoding", "media_type",
        }:
            fail(f"{label}: invalid response metadata")
        validate_header_pairs(response["headers"], f"{label}.response")
        if (
            response["status_code"] != row["http_status"]
            or response["body_sha256"] != row["body_sha256"]
            or response["media_type"] != row["media_type"]
            or response["body_encoding"] != "identity"
        ):
            fail(f"{label}: response/index mismatch")

        if row["classification"] == "registered":
            try:
                rdap_object = json.loads(body_path.read_bytes())
            except (UnicodeDecodeError, json.JSONDecodeError):
                fail(f"{label}: registered response is not JSON")
            if (
                not isinstance(rdap_object, dict)
                or rdap_object.get("objectClassName") != "domain"
                or normalized_domain(rdap_object.get("ldhName")) != domain
            ):
                fail(f"{label}: registered response identity mismatch")
        ordering.append((row["observed_at"], domain, row["observation_id"]))
    if ordering != sorted(ordering):
        fail("RDAP observations are not sorted")
    return observations, referenced


def validate_ct() -> tuple[dict[str, dict], set[Path]]:
    rows = load_jsonl(OBSERVATIONS / "ct/events.jsonl")
    keys = {
        "schema_version", "observed_at", "log_uri", "entry_index", "watch_item",
        "tbs_sha256", "cert_sha256", "pubkey_sha256", "not_before", "not_after",
        "dns_names", "matched_ye_names", "registrable_domains",
        "certificate_chain_sha256", "certspotter_json_sha256", "event_id",
    }
    events = {}
    referenced = set()
    ordering = []
    for number, row in enumerate(rows, 1):
        label = f"CT event line {number}"
        if set(row) != keys or row["schema_version"] != 1:
            fail(f"{label}: unexpected schema")
        canonical_time(row["observed_at"])
        body = {key: value for key, value in row.items() if key != "event_id"}
        event_id = digest(canonical_json(body).encode())
        if row["event_id"] != event_id or event_id in events:
            fail(f"{label}: event ID mismatch or duplicate")
        events[event_id] = row
        for field in ("dns_names", "matched_ye_names", "registrable_domains"):
            if not isinstance(row[field], list) or row[field] != sorted(set(row[field])):
                fail(f"{label}: {field} is not sorted and unique")
        if any(normalized_domain(name) != name for name in row["matched_ye_names"]):
            fail(f"{label}: invalid matched .ye name")
        expected_domains = sorted({
            registrable_domain(name)
            for name in row["matched_ye_names"]
            if registrable_domain(name)
        })
        if row["registrable_domains"] != expected_domains:
            fail(f"{label}: registrable domain derivation mismatch")

        cert_path = hash_path(
            "ct/certificates", row["certificate_chain_sha256"], ".pem"
        )
        json_path = hash_path(
            "ct/certspotter-json", row["certspotter_json_sha256"], ".json"
        )
        for path, expected in (
            (cert_path, row["certificate_chain_sha256"]),
            (json_path, row["certspotter_json_sha256"]),
        ):
            if not path.is_file() or digest(path.read_bytes()) != expected:
                fail(f"{label}: missing or corrupt {path.relative_to(ROOT)}")
            referenced.add(path)
        ordering.append((row["observed_at"], event_id))
    if ordering != sorted(ordering):
        fail("CT events are not sorted")
    return events, referenced


def validate_domains(
    rdap: dict[str, dict],
    ct: dict[str, dict],
) -> None:
    rows = load_jsonl(OBSERVATIONS / "newly-observed-domains.jsonl")
    keys = {
        "schema_version", "domain", "first_observed_date", "last_observed_date",
        "known_in_corpus_at_first_observation", "signals", "rdap_status",
        "rdap_last_observed_at", "rdap_latest_observation_id",
        "registration_events",
    }
    names = []
    for number, row in enumerate(rows, 1):
        label = f"new domain line {number}"
        if set(row) != keys or row["schema_version"] != 1:
            fail(f"{label}: unexpected schema")
        domain = row["domain"]
        if registrable_domain(domain) != domain:
            fail(f"{label}: invalid domain")
        if domain in names:
            fail(f"{label}: duplicate domain")
        names.append(domain)
        first = canonical_date(row["first_observed_date"])
        last = canonical_date(row["last_observed_date"])
        if first > last or type(row["known_in_corpus_at_first_observation"]) is not bool:
            fail(f"{label}: invalid observation bounds")
        if row["rdap_status"] not in RDAP_STATUSES:
            fail(f"{label}: invalid RDAP status")
        if row["rdap_last_observed_at"] is not None:
            canonical_time(row["rdap_last_observed_at"])
        observation_id = row["rdap_latest_observation_id"]
        if observation_id is not None:
            if observation_id not in rdap or rdap[observation_id]["domain"] != domain:
                fail(f"{label}: broken RDAP observation reference")
        if row["registration_events"] != sorted(set(row["registration_events"])):
            fail(f"{label}: registration events are not sorted and unique")
        signal_ids = []
        for signal in row["signals"]:
            if set(signal) != {
                "signal_type", "observed_date", "evidence_id", "signal_id"
            }:
                fail(f"{label}: invalid signal schema")
            canonical_date(signal["observed_date"])
            body = {
                key: value for key, value in signal.items() if key != "signal_id"
            }
            if signal["signal_id"] != digest(canonical_json(body).encode()):
                fail(f"{label}: signal ID mismatch")
            if signal["signal_type"] == "certificate_transparency":
                if signal["evidence_id"] not in ct:
                    fail(f"{label}: broken CT reference")
            elif signal["signal_type"] in {
                "dns_reference",
                "common_crawl",
            }:
                if not HEX_64.fullmatch(signal["evidence_id"]):
                    fail(f"{label}: invalid technical evidence reference")
            else:
                fail(f"{label}: invalid signal type")
            signal_ids.append(signal["signal_id"])
        if signal_ids != sorted(set(signal_ids)) or not signal_ids:
            fail(f"{label}: signals are not sorted, unique, and non-empty")
    if names != sorted(names):
        fail("newly observed domains are not sorted")


def validate_manifest(referenced: set[Path]) -> None:
    manifest_path = OBSERVATIONS / "MANIFEST.sha256"
    entries = {}
    for line in manifest_path.read_text(encoding="ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_./-]+)", line)
        if not match or match.group(2) in entries:
            fail("invalid manifest line")
        entries[match.group(2)] = match.group(1)
    actual = {
        path.relative_to(OBSERVATIONS).as_posix(): digest(path.read_bytes())
        for path in OBSERVATIONS.rglob("*")
        if path.is_file() and path != manifest_path
    }
    if entries != actual:
        fail("manifest does not exactly cover the archive")
    indexed_families = {
        path
        for family in (
            "rdap/bodies/sha256", "rdap/exchanges/sha256",
            "ct/certificates/sha256", "ct/certspotter-json/sha256",
        )
        for path in (OBSERVATIONS / family).rglob("*")
        if path.is_file()
    }
    if indexed_families != referenced:
        fail("raw artifact exists without an index reference")


def validate(root: Path = ROOT) -> dict:
    global ROOT, OBSERVATIONS
    original_root, original_observations = ROOT, OBSERVATIONS
    ROOT = root.resolve()
    OBSERVATIONS = ROOT / "observations"
    try:
        rdap, rdap_files = validate_rdap()
        ct, ct_files = validate_ct()
        validate_domains(rdap, ct)
        validate_manifest(rdap_files | ct_files)
        result = {
            "ok": True,
            "rdap_observations": len(rdap),
            "ct_events": len(ct),
            "newly_observed_domains": len(
                load_jsonl(OBSERVATIONS / "newly-observed-domains.jsonl")
            ),
        }
    finally:
        ROOT, OBSERVATIONS = original_root, original_observations
    return result


def main() -> int:
    print(canonical_json(validate()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
