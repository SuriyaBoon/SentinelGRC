# Historical Azure staging evidence

This package is a sanitized index of selected SentinelGRC staging exercises performed on 2026-08-04 and 2026-08-05.

It records control outcomes, source-file hashes, the tested source commit, and immutable container image digests. Raw Azure exports remain in a private local evidence directory and are intentionally not committed.

## Claim boundary

- The evidence belongs to source commit `09e7f50c3c737c42d9b2c6f597cc8cb1faa70e37`, not current `main`.
- The tests used synthetic staging data inside a private Azure environment.
- The archive does not prove production readiness, certification, current deployment health, or completion of current live-validation gates.
- Failed, partial, and untested observations are retained rather than rewritten as passes.
- Resource IDs, subscription and tenant identifiers, endpoints, credentials, tokens, personal identifiers, and raw logs are excluded.

## Files

- `manifest.json` is the strict machine-readable sanitized evidence index.
- `SHA256SUMS.txt` contains the SHA-256 of the canonical validated manifest.
- `README.md` defines the human-readable scope and limitations.

## Verification

Use `historical_evidence_archive.verify_archive()` to validate the package structure, schema, claim boundary, sanitization rules, and canonical manifest checksum.

An authorized reviewer who holds the private originals can additionally call `verify_private_sources()` to compare every raw source file with the hashes recorded in the sanitized manifest. This second operation reads private evidence but does not copy it into the repository.
