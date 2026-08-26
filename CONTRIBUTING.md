# Contributing

Contributions that improve correctness, validation, documentation, or privacy are welcome.

## Before proposing a change

1. Read the privacy and schema documentation.
2. Keep claims limited to supported public technical facts.
3. Normalized data changes follow the strict allowlist. Complete raw responses belong only in the content-addressed observations archive.
4. Preserve exact lifecycle timestamps and distinct technical record variants.
5. Do not collapse a conflict by choosing one source value without a documented deterministic rule.

## Data corrections

Describe the affected public domain and the normalized field or outcome. Provide only the minimum non-personal public evidence needed for review. Do not paste raw bulk records or contact details.

A query-mismatch outcome may attach only to an already-existing exact query-name row. It must never create a hostname-level merged domain.

## Code changes

Run:

```sh
env PYTHONDONTWRITEBYTECODE=1 python3.12 -m unittest discover -s tests -p 'test_*.py' -v
env PYTHONDONTWRITEBYTECODE=1 python3.12 scripts/validate_dataset.py
env PYTHONDONTWRITEBYTECODE=1 python3.12 scripts/validate_observations.py
```

Changes to canonical JSON fields, identifiers, CSV columns, SQLite tables, or semantics require a schema-version review and matching updates to tests, validators, machine-readable schemas, and documentation.
