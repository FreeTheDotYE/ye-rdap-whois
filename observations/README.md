# Complete .ye observations

This directory is the append-only evidence layer for newly observed `.ye`
activity. It is separate from the normalized datasets under `data/`.

## Completeness

For each successful or error RDAP HTTP response, the archive retains:

- the exact response body bytes requested with identity transfer encoding;
- every returned response header, including repeated headers;
- the HTTP status and protocol version;
- the complete request URL and request headers;
- the precise UTC observation time;
- SHA-256 identifiers for the body and exchange envelope; and
- the mechanical response classification and any returned registration events.

No returned RDAP object fields are removed or masked in this layer. The
normalized `data/` projections remain available for easier analysis.

For each matching Certificate Transparency event, the archive retains the
certificate chain, Cert Spotter JSON, CT log URI and entry index, certificate
hashes, validity fields, every certificate DNS name, the matched `.ye` names,
and derived registrable domains.

## Layout

- `newly-observed-domains.jsonl` is the candidate ledger.
- `rdap/index.jsonl` indexes all archived RDAP observations.
- `rdap/bodies/sha256/` contains complete response bodies.
- `rdap/exchanges/sha256/` contains complete HTTP exchange envelopes.
- `ct/events.jsonl` indexes matching CT observations.
- `ct/certificates/sha256/` contains certificate chains.
- `ct/certspotter-json/sha256/` contains the exact parser JSON.
- `MANIFEST.sha256` covers every other file in this directory.

All content-addressed filenames are the lowercase SHA-256 digest of the exact
stored bytes.

## Evidence semantics

`first_observed_date` means the monitor first received a listed discovery
signal. It is not a registration date.

`rdap_status: registered` requires an HTTP 200 RDAP domain object whose
`ldhName` exactly matches the queried registrable `.ye` domain. Only
registry-returned registration events appear in `registration_events`.

Certificate Transparency proves that a certificate containing a DNS name was
submitted to a monitored CT log. It does not by itself prove registration,
current website use, ownership, affiliation, or abusive conduct.

A domain can be registered without appearing here because RDAP requires a known
query name and the discovery inputs do not enumerate the complete registry.
Absence is not evidence that a domain never existed.

## Validation

Run:

```sh
python3.12 scripts/validate_observations.py
```

The validator checks canonical indexes, identifier recomputation, raw byte
hashes, complete manifest coverage, domain and response identity, cross-file
references, ordering, and that no raw artifact exists without an index record.
