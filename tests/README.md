# Tests

Run from the repository root with Python 3.12 and the reviewed hash-locked dependencies:

```powershell
python -m unittest discover -v
python -m unittest tests.test_repository_layout -v
python -m unittest tests.test_production_image_closure -v
```

All suites live here as importable `tests.test_*` modules. Do not run from inside this folder: runtime modules and fixture paths are rooted at the repository.

The main CI job excludes the `test_postgres*` modules and the separate container job runs them against an ephemeral PostgreSQL service. Image qualification explicitly partitions all modules between the runtime and assessment-dependency images; its regression test rejects omissions or duplicates.

Local environment-dependent skips are not integration passes. A local suite does not grant Azure live-gate credit. Do not set a production database URL to satisfy optional test prerequisites.
