# Phase 3 offline source fixtures

This developer-only fixture set captures observable behavior from the immutable
Windows 0.11.3 Python source for process argument security, Nmap argument/XML
contracts, and Subfaster JSONL/provider provenance. `scripts/build_phase3_fixtures.py` extracts
and executes only the named source definitions (security module definitions are
loaded whole); infrastructure is stubbed only where needed: Nmap platform is
fixed to Linux path behavior, and Subfaster's application JSON loader is mapped
to Python's standard `json.loads`. No subprocess, scanner executable, socket,
network, or third-party dependency is used. XML parser behavior comes from the
standard library. Outputs and exact JSON/XML inputs are recorded in
`fixtures/contracts.json`; source and Linux comparison SHA-256 values are in its
`source` section. `--check` regenerates bytes in memory and compares without
writing fixture files.

The fixtures cover shell-looking literal argv, forbidden control characters,
redaction, safe artifact names, normal and service-detection Nmap argv; complete,
partial, timed-out, malformed, missing and wrong-root XML, including non-whitespace
junk before/after an otherwise complete document; extraport coverage,
unplanned ports, multiple addresses, IPv6, and Unicode hostnames; plus malformed,
array/non-object, falsey, source-list and explicit-source Subfaster rows. The
source family map captures the `unknown_aggregate` fallback; it must remain
visible as transport provenance without counting as an independent upstream
provider/evidence-family vote (the evidence aggregator rule is documented in the
source `evidence/provider.py`).
The inventory case includes two string timestamps for the same provider; the
source selects the earliest value without losing collector provenance.

This set does not invoke the real bundled Nmap/Subfaster binaries and does not
claim native Windows process containment or runtime parity. The Windows source
is development evidence, not an accepted release.

From the workspace root: `python3 -B scripts/build_phase3_fixtures.py --check`.
Scratch XML/JSONL files use `tmp/phase3-fixtures`; fixtures are never overwritten
in check mode. Provider inventory inputs are simple ASCII names; its normalization
stub strips/lowercases these inputs, and JSONL has no background writer. These
stubs do not establish the full provider/normalization contract (phase 2 covers it).

`process_helper/main.go` is a separate, standard-library-only Go test executable,
not a generated Python-source fixture. Tests build it locally to exercise bounded
process IO, cancellation, descendant cleanup, version probes and adapter calls.
It performs no scans or network requests and needs no shell or installed scanner.
Its source belongs to the reviewed phase 3 hash set; compiled temporary copies
are developer test artifacts, not product payload or native-binary parity proof.
