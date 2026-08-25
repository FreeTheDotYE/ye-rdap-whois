#!/usr/bin/env python3

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
SCHEMAS = ROOT / "schemas"


def load_jsonl(name):
    return [
        json.loads(line)
        for line in (DATA / name).read_text(encoding="utf-8").splitlines()
    ]


class ReleaseInvariantTests(unittest.TestCase):
    def test_machine_readable_schemas_are_valid_json(self):
        expected = {
            "merged-domain.schema.json",
            "quality-metrics.schema.json",
            "source-record.schema.json",
            "whois-outcome.schema.json",
        }
        self.assertEqual({path.name for path in SCHEMAS.glob("*.json")}, expected)
        for path in sorted(SCHEMAS.glob("*.json")):
            with self.subTest(schema=path.name):
                schema = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
                self.assertEqual(schema["type"], "object")

    def test_mismatch_snapshot_is_lossless_and_safely_attached(self):
        outcomes = load_jsonl("whois-outcomes.jsonl")
        merged = load_jsonl("merged.jsonl")
        metrics = json.loads(
            (DATA / "quality-metrics.json").read_text(encoding="utf-8")
        )
        mismatch = [
            row
            for row in outcomes
            if row["outcome"] == "different_domain_returned"
        ]

        self.assertEqual(len(mismatch), 11)
        self.assertEqual(
            metrics["diagnostics"]["whois_outcome_different_domain_returned"],
            15,
        )
        self.assertEqual(
            len(
                {
                    (row["query_name"], tuple(row["returned_domains"]))
                    for row in mismatch
                }
            ),
            11,
        )
        self.assertTrue(
            all(
                row["returned_domains"] == sorted(set(row["returned_domains"]))
                and any(
                    domain != row["query_name"]
                    for domain in row["returned_domains"]
                )
                and "observation_count" not in row
                for row in mismatch
            )
        )

        merged_names = {row["domain"] for row in merged}
        holders = {
            outcome_id: row
            for row in merged
            for outcome_id in row["source_outcome_ids"]["whois"]
        }
        for outcome in mismatch:
            holder = holders.get(outcome["outcome_id"])
            if holder is None:
                self.assertNotIn(outcome["query_name"], merged_names)
            else:
                self.assertEqual(holder["domain"], outcome["query_name"])
                self.assertTrue(
                    holder["domain_in_reference_corpus"]
                    or holder["sources_observed"]
                )

        self.assertEqual(
            metrics["counts"]["whois_different_domain_returned_rows"],
            len(mismatch),
        )
        self.assertEqual(
            metrics["counts"]["whois_different_domain_returned_attached_rows"],
            sum(row["outcome_id"] in holders for row in mismatch),
        )
        self.assertEqual(
            metrics["counts"]["whois_different_domain_returned_unattached_rows"],
            sum(row["outcome_id"] not in holders for row in mismatch),
        )


if __name__ == "__main__":
    unittest.main()
