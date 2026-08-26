# .ye Registration and Observation Data

This repository contains two complementary evidence layers:

1. `data/` is the deterministic normalized research dataset. It retains
   technical registration facts while omitting bulk contact cards.
2. `observations/` is a complete, content-addressed archive of automated
   public RDAP responses and Certificate Transparency evidence for newly
   observed `.ye` candidates. RDAP bodies, response headers, request metadata,
   precise observation times, certificate chains, and Cert Spotter JSON are
   retained without field masking.

Normalization is additive and never replaces the complete raw evidence.

## What this repository contains

- Distinct privacy-safe RDAP and WHOIS record variants.
- Exact normalized domain lifecycle timestamps.
- Registry identifiers, statuses, nameservers, registrar-level technical identifiers, DNSSEC facts, and protocol conformance values.
- Explicit normalized WHOIS failure outcomes.
- Complete immutable RDAP response bodies and HTTP exchange metadata.
- Complete matching CT certificate chains and Cert Spotter JSON.
- A newly observed domain index that distinguishes discovery signals from
  RDAP-confirmed objects and registry-supplied registration dates.
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
| `observations/newly-observed-domains.jsonl` | Candidate ledger with discovery and RDAP status |
| `observations/rdap/` | Complete RDAP bodies, exchange envelopes, and index |
| `observations/ct/` | Matching CT certificate chains, parser JSON, and event index |
| `observations/MANIFEST.sha256` | SHA-256 coverage for every observation artifact |

See `docs/data-dictionary.md`, `docs/schema.md`, `docs/privacy.md`, and `docs/quality.md` before analysis.

## Validate locally

Python 3.12 or newer is sufficient; the validation path uses only the standard library.

```sh
env PYTHONDONTWRITEBYTECODE=1 python3.12 -m unittest discover -s tests -p 'test_*.py' -v
env PYTHONDONTWRITEBYTECODE=1 python3.12 scripts/validate_dataset.py
env PYTHONDONTWRITEBYTECODE=1 python3.12 scripts/validate_observations.py
```

Validation checks canonical JSON, schemas, hashes, timestamps, sorting, privacy rules, the exact canonical merge, byte-exact CSV projections, a full logical SQLite projection, integrity, foreign keys, metrics, and checksums.

## Interpretation limits

RDAP validates a known candidate; it does not enumerate unknown registrations.
CT shows certificate issuance, not registration or abusive conduct. A first-seen
date is never converted into a registration date. Absence is not proof that a
domain never existed.

## Licensing and data rights

The MIT license in `LICENSE` applies to repository code only. Data and factual records are covered by the cautious notice in `DATA-RIGHTS.md`; no exclusive rights in underlying public facts are claimed.

## Citation and contributions

Citation metadata is in `CITATION.cff`. Contributions must follow `CONTRIBUTING.md`. Security-sensitive reports follow `SECURITY.md`.
