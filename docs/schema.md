# Schema and reconciliation

## Version

Schema `1.1.0` adds lossless semantic returned-domain mismatch outcomes and deterministic merged-row outcome links. The shape and content hashes of affected rows change with the schema version.

## Normalization

- Domain names are lowercase LDH names without a trailing dot.
- Arrays representing sets are sorted and unique.
- JSON uses sorted keys, UTF-8, and compact separators.
- Lifecycle timestamps retain exact normalized UTC precision; they are not reduced to dates.
- Safe protocol status values are retained beside normalized comparison codes.
- Empty or invalid optional values are omitted through nulls or empty arrays according to the documented fixed shape.

## Content identifiers

`record_id` is `sha256:` plus the hexadecimal SHA-256 digest of the canonical source-record body excluding `record_id`.

`outcome_id` uses the same rule over the canonical outcome body excluding `outcome_id`. The returned-domain set is therefore part of mismatch identity. Artifact multiplicity is not part of semantic identity.

## Variant preservation

Rows are deduplicated only when their complete privacy-safe canonical bodies are identical. Different technical values, exact timestamps, DNSSEC facts, or protocol variants remain separate. The merged row stores every source record ID and variant count.

## Outcome semantics

- `no_record`: a normalized public no-record response shape.
- `query_error`: a normalized transport or service error shape.
- `unparseable`: no safe authoritative record could be parsed and no narrower outcome applied.
- `different_domain_returned`: at least one authoritative public record was retained, but its returned domain set differs from the public query name.

For a mismatch, `returned_domains` is non-empty, sorted, unique, and contains at least one value different from the query. Other outcome types require an empty returned-domain array.

## Merge rules

The merge universe is the union of the reference corpus, authoritative source-record domains, and eligible registrable outcomes.

A mismatch outcome is eligible for attachment only when its exact query name already belongs to the reference or authoritative source-record universe. This prevents a hostname query from becoming a merged registration object merely because it returned a different domain.

Non-mismatch outcomes may form a merged row only when the query is itself the modeled registrable domain. Authoritative nonstandard objects are retained and explicitly marked rather than discarded or silently reinterpreted.

## Projections

JSONL is canonical. CSV is regenerated and compared byte-for-byte. SQLite is regenerated in a temporary database and compared through a complete deterministic logical dump, including schema, indexes, and every row in every table. Integrity and foreign-key checks run separately.
