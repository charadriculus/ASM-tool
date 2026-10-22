# ASM Tool portable preparation recipes

These are developer-only recipes and explicit source locks, not release packages.
They run in the phase8 worktree and read existing local inputs. No downloads,
installers, Nmap builds or native payload execution occur. Original audit inputs
and reference snapshots are immutable.

Current candidates:

- `linux-amd64-report-only.lock.json`: Typst 0.15.1, four DejaVu Sans faces, licenses.
  Linux Subfaster and Nmap are omitted; selected modules must pass existing preflight.
- `windows-amd64-no-nmap.lock.json`: initial Typst/Subfaster/x64 Typst CRT candidate.
- `windows-amd64-no-nmap-notices.lock.json`: preferred candidate02 lock; adds 151
  available notices from 105 authenticated Subfaster dependency ZIPs. Notices for
  go-ole v1.2.6 and wmi v1.2.4 are missing. Nmap is omitted.

Existing source paths are specific to this preparation host. Moving those inputs
requires reviewing path changes; their expected bytes, versions and dependency
identities must not be silently changed. A lock is not an upstream attestation.
The Windows source ZIP remains NOT_ACCEPTED development provenance.

To reproduce from the checked-in locks and existing installed developer Go SDK:

```text
python3 tools/portablepayload/reproduce.py --output tmp/new-private-candidate --windows-lock windows-amd64-no-nmap-notices.lock.json
```

The output must not exist, and its parent must be developer-owned with no
concurrent writers. The recipe performs two Linux and two Windows builds,
embeds each canonical bundle SHA, verifies explicit application/provenance
anchors and compares all ZIP/application/bundle/provenance hashes. SDK path is
`/home/charadriculus/opt/go1.26.6/bin/go`; existing private worktree caches are
used with GOPROXY/GOSUMDB/telemetry off, GOTOOLCHAIN local and CGO disabled.
The installed SDK identity is recorded as evidence, not upgraded or downloaded.

`prepare-locks.py` re-derives initial locks from the pinned original Windows ZIP,
accepted Linux Typst pin and existing system fonts/module notices. It refuses to
replace a changed lock. `subfaster-notices.py` creates a new extended lock using
the pinned preparation inventory and local historical cache, recomputing Go
canonical Hash1 against the Windows binary's embedded dependency sums.
`inventory.py` is the recorded static analysis recipe for candidate01 ELF/PE,
imports, package versions and actual linked app notices. It needs its recorded
candidate01/evidence paths; it refuses to replace the original inventory.
The recipes preserve historical evidence instead of automatically rerunning it.

The user ZIP contains the Go application, `payload/`, a fixed candidate README
and authenticated provenance. It contains no developer Python scripts, SDK,
cache, test EXE, Obscura, native HTTPX, AI runtime or research executables.
The preparation scripts require developer Python/Go; end users do not receive
or need them. ZIP metadata is sorted, stored, fixed-time, fixed-mode. No payload
executable is run by the verifier.

External artifact SHA evidence and native Windows/Linux tests are still required.
CRT/Nmap rights and missing notices are not cleared by integrity checks. The
production browser stays BLOCKED and candidate31 remains FAIL. See
`planning/progress/portable-payload-report.md` for actual gates and next options.
