# Linux LGPL/runtime replacement: developer procedure

## Scope and status

The Linux candidate pins every payload file through `payload/bundle.json`; the application also embeds the SHA-256 of the exact manifest bytes in `internal/app.BundleManifestSHA256`. Replacing a checked file without rebuilding the application must fail closed. Do not add runtime overrides or weaken this identity check.

The source corpus and notices are documented in `LINUX_RUNTIME_LICENSES.md`. This procedure describes how a developer can prepare a separate candidate with user-supplied replacement files. It has **not** been executed or qualified. Inclusion of corresponding sources is documented evidence; it does not establish that a replacement/relink route is legally sufficient or publicly approved.

## Prepare a private replacement lock

Start from `packaging/portable/linux-amd64-patch123.lock.json` in a private working copy. Keep the original lock, staged tree, and accepted candidate unchanged. Copy every replacement file and any required source material into a user-controlled source directory; calculate SHA-256 from those copies. Do not put machine-specific or external absolute paths in the copied lock. Source paths are resolved relative to the lock file, and the stager records source-lock metadata in `payload-provenance.json`.

For each source entry corresponding to a replaced payload file:

- Give the source a unique ID containing only ASCII letters, digits, `-`, or `_` (for example `user-libc-replacement`).
- Point `path` at the copied source file, set `archive` to `false`, set `sha256` to that file's actual digest, and retain accurate version, license, and dependency metadata. For a single-file source, `archive:false` is required and no archive member is used.
- In each matching `files` entry, preserve its payload-relative `path`, set `source` to that ID and update `sha256` to the copied file's digest. Remove `member`; retain the correct `size` and `executable` values. `size` is an input-lock extraction check; it is **not** a field in the generated `payload/bundle.json`.
- Keep all unrelated sources, files, tools, runtime metadata, and dependency declarations unchanged. Ensure any referenced source/license material is available in the accompanying source bundle where required by the applicable terms.

The exact lock schema and accepted runtime file paths are enforced by the existing stager. Do not add arbitrary files or change platform/runtime policy as part of this procedure.

## Stage, rebuild, verify, and archive

Build the existing developer-only tool from the matching source checkout, then stage to a new, absent directory. `stage` writes the canonical `payload/bundle.json`, `payload-provenance.json`, and README; its JSON result reports `bundle_sha256` and `provenance_sha256`. Record these exact values and the stage output. Do not hand-edit the generated manifest or provenance.

For example, for Linux x86-64, with `portablepayload` already built from this source revision and a reviewed private lock:

```sh
./portablepayload stage --lock /private/source/linux-replacement.lock.json --out /private/output/linux-replacement-stage
```

Read the two digest values from the command's JSON output. Build a separate application executable and inject the exact `bundle_sha256` returned by `stage`:

```sh
GOOS=linux GOARCH=amd64 go build -buildvcs=false \
  -ldflags "-s -w -buildid= -X asmtool/internal/app.BundleManifestSHA256=<bundle_sha256-from-stage>" \
  -o /private/output/linux-replacement-stage/asm-tool ./cmd/asm-tool
```

Replace the placeholder with the literal 64-character digest. Do not use the digest of a reformatted manifest or a digest from a different stage. Then calculate the executable SHA-256 and verify the staged tree using all three recorded pins:

```sh
sha256sum /private/output/linux-replacement-stage/asm-tool
./portablepayload verify --root /private/output/linux-replacement-stage \
  --app-sha256 <actual-app-sha256> \
  --bundle-sha256 <bundle_sha256-from-stage> \
  --provenance-sha256 <provenance_sha256-from-stage>
```

Only after offline verification succeeds, create a new archive at a path outside the stage root:

```sh
./portablepayload archive --root /private/output/linux-replacement-stage \
  --out /private/output/asm-tool-linux-amd64-replacement.zip \
  --app-sha256 <actual-app-sha256> \
  --bundle-sha256 <bundle_sha256-from-stage> \
  --provenance-sha256 <provenance_sha256-from-stage>
sha256sum /private/output/asm-tool-linux-amd64-replacement.zip
```

The archive tool verifies the closed input tree against the three pins and refuses to replace an existing output. Record the final ZIP SHA-256 separately as the archive identity; the tool does not emit a separate “root hash.” Preserve the lock, exact source files, build command/toolchain identity, stage JSON, verify/archive output, and hashes as developer evidence. Keep complete GNU source archives and applicable patches/notices in the accompanying source bundle; do not treat the staged payload provenance as a corresponding-source offer.

These commands describe the current tool interface and are not evidence that a replacement was built, that the resulting application runs, or that any legal condition is satisfied. No rebuild, runtime test, or legal determination is claimed here. The original candidate and its historical qualification evidence remain unchanged.
