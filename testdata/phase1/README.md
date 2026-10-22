# Phase 1 offline evidence

`source_defaults.json`, `source_ai_presets.json`, `source_suffix_fallback.json`
and `catalog_{en,ru}.json` are literal data extracted by
`scripts/extract_phase1_fixtures.py` through `ast.parse` / `ast.literal_eval`.
The application is not imported. `provenance.json` pins source file hashes and
Windows development commit `3007642c302c7d1f61daa8f45ee5e33c2557aa02`.
Go tests check these hashes and compare every retained default and catalog text.
All source catalog entries are preserved as inert text, including unused
academic labels; no academic report implementation is present.

`normalization.json` is independently written from source behavior. The developer
check `scripts/check_phase1_source.py` compares its valid cases against the pure
stdlib-only normalization module from both immutable reference snapshots, with
an AST guard on imports and statements. It does not invoke the application,
network, legacy test suite, or release harness. Go tests independently consume
these cases and additionally test rejected inputs and scope/authorization.

`config_operational.yml` exercises Unicode paths, separate authorization,
standard/deep collection, rate limits, scope, modules, reporting and optional AI.
Inert `research_*` configuration fields from legacy standard configurations are
ignored; selecting research, dnsx or Katana and enabling resource telemetry is
rejected. Copied historic assets remain immutable evidence of the prior format.

## Deliberate differences and limits

- Configuration/settings are UTF-8 and capped at 1 MiB. Duplicate keys, aliases,
  merge keys, custom tags, multiple YAML documents, nonmapping sections, explicit
  null required scalars, fractional/nonfinite/out-of-range integer budgets and
  quoted/nonboolean security switches fail closed.
  Plain YAML 1.1 `yes`/`no`/`on`/`off` and YAML 1.2 `true`/`false` switches
  retain PyYAML boolean semantics (source case variants supported). Unknown ordinary fields and
  inert academic fields remain ignored for legacy compatibility.
- Active config requires `verify`/`full` and explicit authorization. Every future
  active consumer must call the unified scope gate. IP scope always requires its
  own CIDR allowance; domain authorization does not implicitly authorize its DNS IP.
- Host syntax requires valid ASCII DNS labels after IDNA mapping, Bidi validation
  and DNS length bounds. Scope retains the source rejection of leading/trailing
  ASCII dots and repeated dots. Invalid labels (underscores, slashes, controls,
  leading/trailing hyphens), scoped IPv6 zones and non-HTTP(S)/hostless URLs are
  rejected. URL ports must be 1–65535; malformed percent query escapes fail closed.
  Raw Unicode/space paths, percent-escaped paths, query pair sorting, fragment
  removal, userinfo removal and IPv6 default-port representation retain source
  behavior for valid fixtures.
- IPv4-mapped IPv6 wire text matches the current Python 3.14 user runtime
  (`::ffff:192.0.2.1`); older Python versions may use hexadecimal suffixes.
  Scope membership retains the IPv6 family without unmapping. Future readers
  should interpret historic IP values semantically without rewriting original data.
- IDNA is pinned x/net UTS46 transitional mapping, not Python's older IDNA2003
  Unicode tables. Common mappings (`ß`, fullwidth letters/separators, Cyrillic)
  are verified; all historical Unicode edge cases are not proven equivalent.
- PSL uses pinned x/net v0.55.0's bundled snapshot with private suffixes excluded,
  truthful Go provenance and no network updates. Snapshot identity differs from
  tldextract 5.3.1; edge-rule changes require review. Unknown suffixes use the exact
  source fallback table and explicitly marked degraded provenance.
- Backend labels remain declarative legacy requests; parsing does not probe,
  activate or claim those Python/native implementations exist in the Go runtime.
- Settings use same-directory temporary files, file sync and replacement, UTF-8,
  Unix mode 0600 and cleanup on failure. Permission-denied and corrupt reads
  report a warning/error alongside English fallback. Windows runtime semantics,
  power-loss durability of directory metadata and concurrent-writer ordering
  are not established by Linux tests; last successful replacement wins.

No CLI, DNS contact, process execution, database, reports, runtime backend,
network benchmark or release lifecycle belongs to this phase.
