# .ye Registration Data

A privacy-minimized, deterministic release of normalized public technical facts about `.ye` registration objects.

Multiple public datasets and protocol records were normalized into a common model. The release deliberately omits input-provider identities, collection endpoints, acquisition chronology, source locations, source filenames, raw responses, and bulk personal-contact fields.

## What this repository contains

- Distinct privacy-safe RDAP and WHOIS record variants.
- Exact normalized domain lifecycle timestamps.
- Registry identifiers, statuses, nameservers, registrar-level technical identifiers, DNSSEC facts, and protocol conformance values.
- Explicit normalized WHOIS failure outcomes.
- Explicit `different_domain_returned` outcomes when a public query returned a different public domain, including the sorted returned-domain set.
- A deterministic merged domain view, CSV projections, quality metrics, checksums, and an equivalent SQLite projection.

The release preserves conflicting or distinct technical variants instead of selecting an unsupported “winner.” A returned-domain mismatch is linked to a merged row only when its exact query name already exists in the reference or authoritative-record domain universe. An outcome alone never creates a hostname-level merged domain.

## Release files

| File | Purpose |
|---|---|
| `data/rdap.jsonl` | Distinct normalized RDAP variants |
| `data/whois.jsonl` | Distinct normalized WHOIS variants |
| `data/whois-outcomes.jsonl` | Distinct normalized WHOIS non-record and mismatch outcomes |
| `data/merged.jsonl` | Canonical per-domain reconciliation |
| `data/records.csv` | Flat record-variant projection with canonical JSON cells |
| `data/whois-outcomes.csv` | Flat outcome projection |
| `data/merged.csv` | Flat merged projection |
| `data/registration.sqlite` | Deterministic relational projection |
| `data/quality-metrics.json` | Coverage, diagnostics, conflicts, and invariant results |
| `data/CHECKSUMS.sha256` | SHA-256 checksums for every other release file |

See `docs/data-dictionary.md`, `docs/schema.md`, `docs/privacy.md`, and `docs/quality.md` before analysis.

## Validate locally

Python 3.12 or newer is sufficient; the validation path uses only the standard library.

```sh
env PYTHONDONTWRITEBYTECODE=1 python3.12 -m unittest discover -s tests -p 'test_*.py' -v
env PYTHONDONTWRITEBYTECODE=1 python3.12 scripts/validate_dataset.py
```

Validation checks canonical JSON, schemas, hashes, timestamps, sorting, privacy rules, the exact canonical merge, byte-exact CSV projections, a full logical SQLite projection, integrity, foreign keys, metrics, and checksums.

## Interpretation limits

This is historical technical evidence, not a live registry, ownership determination, affiliation finding, legal conclusion, or allegation of intent. Absence is not proof that a domain never existed. Conflicts can reflect protocol semantics, update timing, incomplete fields, or differing public records.

## Licensing and data rights

The MIT license in `LICENSE` applies to repository code only. Data and factual records are covered by the cautious notice in `DATA-RIGHTS.md`; no exclusive rights in underlying public facts are claimed.

## Citation and contributions

Citation metadata is in `CITATION.cff`. Contributions must follow `CONTRIBUTING.md`, including the prohibition on submitting raw bulk responses or personal-contact fields. Security-sensitive reports follow `SECURITY.md`.
