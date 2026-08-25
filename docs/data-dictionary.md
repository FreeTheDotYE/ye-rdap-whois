# Data dictionary

All JSONL rows use schema version `1.1.0`, canonical JSON, normalized lowercase domain names, sorted unique arrays, and deterministic content identifiers.

## Source record variants

`rdap.jsonl` and `whois.jsonl` contain one row per distinct privacy-safe technical record variant.

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | string | Release schema version |
| `source_type` | `rdap` or `whois` | Public protocol family |
| `domain` | string | Domain named by the authoritative record block |
| `object_class` | string or null | Normalized protocol object class |
| `registration_object_basis` | `authoritative_record` | Evidence basis |
| `standard_registrable_domain` | string | Result of the release suffix model; may be empty for a suffix-level object |
| `standard_public_suffix_model_match` | boolean | Whether `domain` is a suffix level or exactly one label below a modeled suffix |
| `registry_ids` | array of strings | Public registry handles |
| `statuses` | array of objects | Original safe status value and normalized status code |
| `nameservers` | array of objects | LDH name and optional public registry handle |
| `registrars` | array of objects | Registrar-level public technical identifiers; no contact cards |
| `lifecycle` | object | Sorted exact UTC registration, expiration, and last-changed timestamps |
| `dnssec` | object | Status, signed flags, signature life, and public DS/key facts |
| `protocol_conformance` | array of strings | Public protocol conformance identifiers |
| `record_id` | string | SHA-256 identifier of the complete canonical row body |

Distinct rows for the same domain are deliberate record variants.

## WHOIS outcomes

`whois-outcomes.jsonl` contains one undated row per distinct semantic query outcome.

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | string | Release schema version |
| `source_type` | `whois` | Protocol family |
| `query_name` | string | Normalized public query name |
| `registrable_domain` | string | Standard modeled registrable domain derived from the query |
| `outcome` | enum | `no_record`, `query_error`, `unparseable`, or `different_domain_returned` |
| `returned_domains` | array of strings | Sorted unique public returned domains; non-empty only for `different_domain_returned` |
| `outcome_id` | string | SHA-256 identifier of the complete canonical outcome body |

A mismatch row requires at least one returned domain different from `query_name`. Artifact multiplicity remains aggregate-only in quality diagnostics; individual outcome rows are semantic and undated.

## Merged domains

`merged.jsonl` contains one row per accepted domain in the canonical union.

| Field | Meaning |
|---|---|
| `domain` | Merge key |
| `domain_in_reference_corpus` | Whether the exact key is in the reference corpus |
| `registration_object_basis` | `authoritative_record`, `reference_corpus`, or `registrable_outcome` |
| `sources_observed` | Protocols with authoritative record variants |
| `source_outcomes` | Outcome types attached to the exact domain |
| `source_outcome_ids` | Deterministic links to attached outcome rows |
| `source_record_ids` | Deterministic links to source variants |
| `source_record_variant_counts` | Variant counts by protocol |
| `registry_ids_observed` | Union of registry handles |
| `status_codes_observed` | Union of normalized status codes |
| `status_values_by_source` | Safe source values retained by protocol |
| `nameservers_observed` | Nameservers with observed handles and protocol provenance |
| `registrars_observed` | Reconciled registrar-level technical identifiers |
| `lifecycle` | Union of exact timestamps by lifecycle action |
| `dnssec` | Union of safe DNSSEC facts |
| `protocol_conformance_observed` | Union of conformance identifiers |
| `cross_source_conflict_fields` | Fields whose non-empty protocol value sets differ |
| `has_cross_source_conflict` | Convenience boolean |

A `different_domain_returned` outcome attaches only if its exact `query_name` already exists in the reference or authoritative-record universe. It cannot create a hostname-level row.

## CSV

Columns ending in `_json` contain canonical JSON, not delimiter-joined values. Boolean cells are lowercase `true` or `false`. CSV rows are deterministic projections of the JSONL rows.

## SQLite

| Table | Grain |
|---|---|
| `records` | One source record variant |
| `record_statuses` | One status per record variant |
| `record_nameservers` | One nameserver per record variant |
| `lifecycle_events` | One exact timestamp and action per record variant |
| `protocol_conformance` | One conformance value per record variant |
| `source_outcomes` | One semantic WHOIS outcome |
| `merged_domains` | One canonical merged domain |

JSON columns in SQLite use the same canonical serialization as JSONL and CSV.
