# Data quality and limitations

## Current mismatch reconciliation

The release normalizes 15 public WHOIS artifacts with query/returned-domain mismatches into 11 unique semantic `different_domain_returned` outcomes. Duplicate artifacts are collapsed without publishing per-outcome multiplicity. Each outcome retains its sorted returned-domain set, and the aggregate artifact and duplicate counts remain in `quality-metrics.json`.

Current domain and variant totals must be read from `quality-metrics.json`; they are intentionally not duplicated in documentation.

## Automated checks

- Canonical JSON and stable ordering.
- Unique content-derived record and outcome IDs.
- Exact normalized timestamps.
- Fixed allowlisted schemas and privacy scanning.
- Complete reference-corpus coverage.
- Exact canonical merge recomputation.
- Exact CSV projections.
- Complete logical SQLite projection, schema, integrity, and foreign keys.
- Metrics recomputation and checksum coverage.
- Focused outcome attachment tests preventing hostname-level row creation.

## Conflict handling

A cross-source conflict is reported only when both protocol families provide non-empty value sets and those normalized sets differ. The release retains both sets. No protocol is treated as universally authoritative for reconciliation.

Equivalent status spellings can normalize to the same comparison code while preserving their safe source values.

## Known limitations

- This is a bounded historical normalization, not a live registry.
- Public records can be incomplete, stale, inconsistent, or shaped by protocol behavior.
- Absence from the release is not evidence of nonexistence.
- A query mismatch can reflect service behavior and is not evidence of ownership or affiliation.
- The modeled suffix list is explicit and conservative; authoritative objects outside it are retained and marked.
- Aggregate diagnostics describe processing outcomes but intentionally omit source-level acquisition fingerprints.

Analyses should cite the release version, disclose these limitations, and avoid causal or legal conclusions from technical correlation alone.
