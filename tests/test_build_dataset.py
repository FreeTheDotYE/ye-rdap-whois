#!/usr/bin/env python3

import json
import sqlite3
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_dataset import (
    classify_whois_outcome,
    make_outcome,
    make_record,
    merge_domains,
    merge_registrars,
    parse_whois,
    registrable_domain,
    safe_public_id,
    standard_model_match,
    status_item,
    write_sqlite,
)


def payload(domain, source_status, nameservers=None, registrar_name="Example Registrar"):
    return {
        "domain": domain,
        "object_class": "domain",
        "registry_ids": ["D1-YE"],
        "statuses": [status_item(source_status)],
        "nameservers": nameservers or [],
        "registrars": [
            {
                "registry_handle": "R1-YE",
                "name": registrar_name,
                "public_ids": [],
                "vcard_version": "4.0",
            }
        ],
        "lifecycle": {
            "registration": ["2000-01-01T00:00:00.000Z"],
            "expiration": ["2040-12-31T23:59:59.999Z"],
            "last_changed": [],
        },
        "dnssec": {
            "status": "unsigned",
            "delegation_signed": False,
            "zone_signed": False,
            "max_signature_life": None,
            "ds_records": [],
            "key_records": [],
        },
        "protocol_conformance": [],
    }


class BuildDatasetTests(unittest.TestCase):
    def test_registrar_merge_resolves_sparse_and_enriched_variants(self):
        entries = [
            (
                "whois",
                {
                    "registry_handle": None,
                    "name": "Example Registrar",
                    "public_ids": [],
                    "vcard_version": None,
                },
            ),
            (
                "rdap",
                {
                    "registry_handle": "R1-YE",
                    "name": "Example Registrar",
                    "public_ids": [{"type": "IANA Registrar ID", "identifier": "999"}],
                    "vcard_version": "4.0",
                },
            ),
        ]
        merged = merge_registrars(entries)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["source_types"], ["rdap", "whois"])
        self.assertEqual(merged[0]["registry_handles_observed"], ["R1-YE"])
        self.assertEqual(
            merged[0]["public_ids_observed"],
            [{"identifier": "999", "type": "IANA Registrar ID"}],
        )

    def test_empty_public_identifier_is_not_exported(self):
        self.assertIsNone(
            safe_public_id({"type": "IANA Registrar ID", "identifier": ""})
        )

    def test_active_and_ok_are_reconciled_without_conflict(self):
        rdap = make_record("rdap", payload("example.ye", "active"))
        whois_payload = payload("example.ye", "ok")
        whois_payload["registrars"][0]["registry_handle"] = None
        whois_payload["registrars"][0]["vcard_version"] = None
        whois_payload["dnssec"]["zone_signed"] = None
        whois = make_record("whois", whois_payload)
        merged = merge_domains([rdap, whois], {"example.ye"})
        self.assertEqual(merged[0]["status_codes_observed"], ["active"])
        self.assertNotIn("status_codes", merged[0]["cross_source_conflict_fields"])

    def test_hostname_outcome_does_not_create_merged_domain(self):
        outcome = make_outcome("host.example.net.ye", "unparseable")
        rows = merge_domains([], {"example.net.ye"}, [outcome])
        self.assertEqual([row["domain"] for row in rows], ["example.net.ye"])
        self.assertEqual(rows[0]["source_outcomes"]["whois"], [])

    def test_registrable_outcome_can_attach_to_same_domain(self):
        outcome = make_outcome("example.net.ye", "no_record")
        rows = merge_domains([], {"example.net.ye"}, [outcome])
        self.assertEqual(rows[0]["source_outcomes"]["whois"], ["no_record"])
        self.assertEqual(rows[0]["source_outcome_ids"]["whois"], [outcome["outcome_id"]])

    def test_mismatch_outcome_is_sorted_semantic_and_strict(self):
        first = make_outcome(
            "host.example.ye",
            "different_domain_returned",
            ["zeta.ye", "alpha.ye", "zeta.ye"],
        )
        second = make_outcome(
            "host.example.ye",
            "different_domain_returned",
            ["alpha.ye", "zeta.ye"],
        )
        self.assertEqual(first["returned_domains"], ["alpha.ye", "zeta.ye"])
        self.assertEqual(first["outcome_id"], second["outcome_id"])
        with self.assertRaises(ValueError):
            make_outcome(
                "host.example.ye",
                "different_domain_returned",
                ["host.example.ye"],
            )
        with self.assertRaises(ValueError):
            make_outcome("host.example.ye", "no_record", ["other.ye"])

    def test_mismatch_parse_retains_records_and_emits_outcome(self):
        diagnostics = Counter()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "query.ye.txt"
            path.write_text(
                "\n".join(
                    [
                        "Domain Name: returned.ye",
                        "Domain Status: active",
                        "Domain Name: returned.ye",
                        "Domain Status: ok",
                    ]
                ),
                encoding="utf-8",
            )
            records, outcomes = parse_whois(path, diagnostics)
        self.assertEqual(len(records), 2)
        self.assertEqual({row["domain"] for row in records}, {"returned.ye"})
        self.assertEqual(len(outcomes), 1)
        self.assertEqual(outcomes[0]["outcome"], "different_domain_returned")
        self.assertEqual(outcomes[0]["returned_domains"], ["returned.ye"])
        self.assertEqual(diagnostics["whois_outcome_different_domain_returned"], 1)

    def test_mismatch_attachment_requires_exact_existing_query(self):
        outcome = make_outcome(
            "host.example.net.ye",
            "different_domain_returned",
            ["example.net.ye"],
        )
        rows = merge_domains([], {"example.net.ye"}, [outcome])
        self.assertEqual([row["domain"] for row in rows], ["example.net.ye"])
        self.assertEqual(rows[0]["source_outcomes"]["whois"], [])

        record = make_record("rdap", payload("host.example.net.ye", "active"))
        rows = merge_domains([record], {"example.net.ye"}, [outcome])
        query_row = next(row for row in rows if row["domain"] == "host.example.net.ye")
        self.assertEqual(
            query_row["source_outcomes"]["whois"],
            ["different_domain_returned"],
        )
        self.assertEqual(
            query_row["source_outcome_ids"]["whois"],
            [outcome["outcome_id"]],
        )

        reference_outcome = make_outcome(
            "example.ye",
            "different_domain_returned",
            ["other.ye"],
        )
        rows = merge_domains([], {"example.ye"}, [reference_outcome])
        self.assertEqual(
            rows[0]["source_outcomes"]["whois"],
            ["different_domain_returned"],
        )

    def test_sqlite_projection_is_deterministic_and_lossless(self):
        outcome = make_outcome(
            "example.ye",
            "different_domain_returned",
            ["other.ye"],
        )
        merged = merge_domains([], {"example.ye"}, [outcome])
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.sqlite"
            second = Path(directory) / "second.sqlite"
            write_sqlite(first, [], [outcome], merged)
            write_sqlite(second, [], [outcome], merged)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            connection = sqlite3.connect(first)
            stored = connection.execute(
                "SELECT returned_domains_json FROM source_outcomes"
            ).fetchone()[0]
            connection.close()
        self.assertEqual(stored, '["other.ye"]')

    def test_authoritative_nonstandard_object_is_retained_and_marked(self):
        record = make_record("rdap", payload("clinic.hospital.ye", "active"))
        rows = merge_domains([record], set())
        self.assertEqual(rows[0]["domain"], "clinic.hospital.ye")
        self.assertEqual(rows[0]["standard_registrable_domain"], "hospital.ye")
        self.assertFalse(rows[0]["standard_public_suffix_model_match"])
        self.assertEqual(rows[0]["registration_object_basis"], "authoritative_record")

    def test_standard_suffix_model(self):
        self.assertEqual(registrable_domain("host.example.net.ye"), "example.net.ye")
        self.assertEqual(registrable_domain("example.net.ye"), "example.net.ye")
        self.assertTrue(standard_model_match("net.ye"))
        self.assertFalse(standard_model_match("clinic.hospital.ye"))

    def test_no_record_artifact_is_preserved_without_raw_diagnostic(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "example.ye.txt"
            path.write_text("No match", encoding="utf-8")
            records, outcomes = parse_whois(path, Counter())
        self.assertEqual(records, [])
        self.assertEqual(len(outcomes), 1)
        self.assertEqual(outcomes[0]["outcome"], "no_record")
        self.assertEqual(outcomes[0]["query_name"], "example.ye")
        self.assertNotIn("raw", json.dumps(outcomes[0]).lower())

    def test_outcome_classifier_distinguishes_failure_shapes(self):
        self.assertEqual(classify_whois_outcome("No match"), "no_record")
        self.assertEqual(classify_whois_outcome("Socket not responding"), "query_error")
        self.assertEqual(classify_whois_outcome("opaque response"), "unparseable")


if __name__ == "__main__":
    unittest.main()
