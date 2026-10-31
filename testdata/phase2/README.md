# Phase 2 Python-source fixtures

`legacy_contract.json` is re-derived offline from the immutable Windows development Python source identified in its `source.provenance` map. Where the accepted Linux files are byte-identical, their SHA-256 and identity are recorded for comparison; Windows remains the primary behavior source for this migration.

`synthetic_legacy_run.sql` is a generated, deterministic **synthetic SQLite database dump**, not a historical run database. It is emitted by applying the source DDL and source ingest functions to fixed test events. No genuine historical SQLite run is present in the workspace. The fixture exercises schema shape, duplicate first-writer behavior, object and relation merging, screenshot identity, specialized rows, rollback, malformed/dry-run JSONL ingest, and provider/completeness cases. Wall-clock ingest duration is intentionally omitted.

The developer generator loads behavior-bearing legacy modules from `reference/windows-0.11.3-development`. Only unavailable import infrastructure is stubbed: JSON Schema validation uses the checked-in event schema with Python `jsonschema`, JSON serialization selects the legacy stdlib backend, and the JSONL read barrier is a no-op because generation has no background writer. No network calls or package installation occur. All temporary databases and scratch data are placed in `tmp/phase2-fixtures`.

From workspace root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/build_phase2_fixture.py --check
```

The `--check` mode re-derives expected bytes in scratch space and compares them without writing the fixture files. To regenerate the fixture files after an approved baseline change, omit `--check`. Python and `jsonschema` are developer-only tools; they are not Go runtime dependencies.
