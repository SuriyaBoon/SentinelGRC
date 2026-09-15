# Repository organization — 2026-09-15

Base: main `3bdfc881d0f0e8d4a2c22f827816bb328fe69514`.
Changes are prepared on a review branch, not applied directly to remote main.

## Grouped and cleaned

- Move every root test suite into `tests/`, retaining coverage and optional-integration boundaries.
- Update test module paths, repository-root resolution, CI partitioning, Sonar inputs and security-suite presence checks together.
- Replace the oversized README with a short entry page and explicit dated status.
- Group architecture, integration, operations, Azure, security and historical planning documents.
- Extract the duplicated Mini-SOAR appendix from the landing page into portfolio reference.
- Retain evidence folders and checksum manifests at their original paths.
- Preserve detailed command, architecture, safety and integration content in focused guides.

## Deliberately retained

Root Python modules are existing runtime imports and Docker positive-manifest inputs; relocating them is a separate packaging migration.
Root JSON examples are used by CLI defaults and tests.
SQL migrations, security checks, image definitions, hash-locked dependencies and evidence are operational inputs, not clutter.
Adjacent Mini-SOAR documents describe a supported bridge boundary, so they are labeled reference rather than deleted as unrelated.

No source module or historical evidence is deleted. No cache, generated database, key, private support log, worker packet or unrelated Second-Brain repository is imported.
The existing user's dirty checkout is not modified.

## Validation and publication

Run the complete suite from the repository root, validate documentation links and verify that CI's explicit image-qualification partitions cover all test modules exactly once.
The reorganization must not weaken security checks, widen production image contents or grant current live-gate credit.
Local success does not replace new remote CI or authorize push/merge.

## Local verification of this reorganization

- All 59 baseline test modules were retained; an AST comparison found no removed baseline test methods.
- Added one layout-regression module with three tests (60 modules total).
- Full suite: 579 tests, OK, 21 skipped, 78.353 seconds on 2026-09-15 (558 non-skipped tests).
- Documentation navigation, CI qualification partition coverage and image import-closure checks passed locally.
- Offline staging demonstration passed all seven offline gates; no Azure mutation and no live-gate credit.
- The first full run found two stale Sonar evidence paths; the registry paths were corrected and the complete suite rerun. Review ownership, rationale and expiry were not changed.
- Existing evidence payloads/checksum manifests, SQL migrations and Docker image manifests remain unchanged.
- Fresh remote CI/Sonar and container execution are not claimed for this branch until publication and verification.
