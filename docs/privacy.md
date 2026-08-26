# Privacy model

The repository has two intentionally different layers.

The normalized `data/` release applies a strict allowlist. It is designed for
domain-level technical research, not contact discovery.

The `observations/` archive preserves complete public RDAP responses and CT
artifacts. It does not remove returned fields, remarks, notices, links, contact
cards, response headers, or precise HTTP dates.

## Retained

- Public domain names and registry handles.
- Public status values and normalized status codes.
- Public nameserver names and technical handles.
- Registrar-level public organization names and public identifiers.
- Exact public lifecycle timestamps.
- Public DNSSEC and protocol-conformance facts.
- Normalized public query outcomes and returned-domain mismatches.
- Aggregate diagnostics and data-quality counts.

## Excluded

- Registrant, administrative, technical, and abuse contact cards.
- Email addresses, telephone numbers, fax numbers, street addresses, postal data, locality, and country contact fields.
- Raw response bodies and free-text remarks.
- Response headers, request logs, collection endpoints, acquisition chronology, source locations, and source filenames.
- Input-provider identities and per-outcome source-set multiplicity.

These exclusions apply only to normalized `data/` projections.

## Enforcement

The builder emits only fixed allowlisted structures. The validator rejects unexpected keys, contact-like keys, email-like strings, endpoint-like values, local-location strings, noncanonical rows, and outcome fields outside their fixed shape. Checksums cover every release artifact.

Privacy minimization reduces risk but does not make technical data harmless. Domain names can still be sensitive in context. Do not infer a person, affiliation, ownership, intent, or wrongdoing from a technical record, absence, mismatch, or infrastructure overlap.
