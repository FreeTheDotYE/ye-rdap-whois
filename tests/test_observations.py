from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.validate_observations import (
    canonical_json,
    registrable_domain,
    validate,
)


class ObservationValidatorTests(unittest.TestCase):
    def empty_archive(self, root: Path) -> Path:
        observations = root / "observations"
        (observations / "rdap").mkdir(parents=True)
        (observations / "ct").mkdir(parents=True)
        (observations / "rdap/index.jsonl").write_text("", encoding="utf-8")
        (observations / "ct/events.jsonl").write_text("", encoding="utf-8")
        (observations / "newly-observed-domains.jsonl").write_text(
            "",
            encoding="utf-8",
        )
        files = {
            path.relative_to(observations).as_posix(): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in observations.rglob("*")
            if path.is_file()
        }
        (observations / "MANIFEST.sha256").write_text(
            "".join(f"{digest}  {name}\n" for name, digest in sorted(files.items())),
            encoding="ascii",
        )
        return observations

    def rewrite_manifest(self, observations: Path) -> None:
        manifest = observations / "MANIFEST.sha256"
        files = {
            path.relative_to(observations).as_posix(): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in observations.rglob("*")
            if path.is_file() and path != manifest
        }
        manifest.write_text(
            "".join(f"{digest}  {name}\n" for name, digest in sorted(files.items())),
            encoding="ascii",
        )

    def test_empty_archive_is_valid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.empty_archive(root)
            self.assertEqual(
                validate(root),
                {
                    "ok": True,
                    "rdap_observations": 0,
                    "ct_events": 0,
                    "newly_observed_domains": 0,
                },
            )

    def test_manifest_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            observations = self.empty_archive(root)
            (observations / "extra.txt").write_text("tampered", encoding="utf-8")
            with self.assertRaisesRegex(AssertionError, "manifest"):
                validate(root)

    def test_unindexed_raw_artifact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            observations = self.empty_archive(root)
            body = b"unindexed"
            value = hashlib.sha256(body).hexdigest()
            path = (
                observations
                / "rdap/bodies/sha256"
                / value[:2]
                / f"{value}.bin"
            )
            path.parent.mkdir(parents=True)
            path.write_bytes(body)
            self.rewrite_manifest(observations)
            with self.assertRaisesRegex(AssertionError, "without an index"):
                validate(root)

    def test_domain_index_requires_signal_and_valid_domain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            observations = self.empty_archive(root)
            row = {
                "schema_version": 1,
                "domain": "com.ye",
                "first_observed_date": "2026-08-26",
                "last_observed_date": "2026-08-26",
                "known_in_corpus_at_first_observation": False,
                "signals": [],
                "rdap_status": "unqueried",
                "rdap_last_observed_at": None,
                "rdap_latest_observation_id": None,
                "registration_events": [],
            }
            (observations / "newly-observed-domains.jsonl").write_text(
                canonical_json(row) + "\n",
                encoding="utf-8",
            )
            self.rewrite_manifest(observations)
            with self.assertRaisesRegex(AssertionError, "invalid domain"):
                validate(root)

    def test_common_crawl_signal_is_content_addressed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            observations = self.empty_archive(root)
            body = {
                "signal_type": "common_crawl",
                "observed_date": "2026-08-26",
                "evidence_id": "a" * 64,
            }
            signal = {
                **body,
                "signal_id": hashlib.sha256(
                    canonical_json(body).encode("utf-8")
                ).hexdigest(),
            }
            row = {
                "schema_version": 1,
                "domain": "example.com.ye",
                "first_observed_date": "2026-08-26",
                "last_observed_date": "2026-08-26",
                "known_in_corpus_at_first_observation": False,
                "signals": [signal],
                "rdap_status": "unqueried",
                "rdap_last_observed_at": None,
                "rdap_latest_observation_id": None,
                "registration_events": [],
            }
            index = (
                observations
                / "newly-observed-domains.jsonl"
            )
            index.write_text(
                canonical_json(row) + "\n",
                encoding="utf-8",
            )
            self.rewrite_manifest(observations)
            self.assertEqual(
                validate(root)["newly_observed_domains"],
                1,
            )

            row["signals"][0]["evidence_id"] = "not-a-digest"
            changed_body = {
                key: value
                for key, value in row["signals"][0].items()
                if key != "signal_id"
            }
            row["signals"][0]["signal_id"] = hashlib.sha256(
                canonical_json(changed_body).encode("utf-8")
            ).hexdigest()
            index.write_text(
                canonical_json(row) + "\n",
                encoding="utf-8",
            )
            self.rewrite_manifest(observations)
            with self.assertRaisesRegex(
                AssertionError,
                "technical evidence reference",
            ):
                validate(root)

    def test_registrable_model_handles_structured_suffixes(self) -> None:
        self.assertEqual(
            registrable_domain("www.example.com.ye"),
            "example.com.ye",
        )
        self.assertEqual(registrable_domain("com.ye"), "")


if __name__ == "__main__":
    unittest.main()
