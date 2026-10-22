# Portable payload preparation

`portablepayload` is a developer-only offline staging utility. It does not
download, install, inspect by execution, or launch any bundled binary. In
particular, staging records the version and license claims in the reviewed
lock; it does not prove those claims by invoking Typst, Subfaster, or an
installer. Nmap is not a supported tool in 0.12.1 payload manifests.

The source lock is JSON with `schema_version: 1`, a target `platform`, and
explicit `sources`, `files`, and `tools` arrays. Every source records an ID,
path, whole-source SHA-256, archive flag, version, and license. Every staged
file names one declared source, its archive member when applicable, output
path, expected SHA-256 and size, and executable bit. Tool entries name the
manifest executable, exact version, license, dependencies, capabilities, and
must use `usage: "qualification-only"`. Paths use clean relative slash form
under `payload/`. Relative source paths resolve beside the lock file. A source
archive's entire digest is checked before its members are read; all archive
member names are checked for traversal, duplicates, case collisions and links.

Example commands (after building this developer tool from the repository):

```text
portablepayload stage --lock reviewed-linux.json --out stage-linux
portablepayload verify --root ready-linux --app-sha256 <recorded-app-sha256> --bundle-sha256 <embedded-bundle-sha256> --provenance-sha256 <recorded-provenance-sha256>
portablepayload archive --root ready-linux --out asm-tool-linux-amd64.zip --app-sha256 <recorded-app-sha256> --bundle-sha256 <embedded-bundle-sha256> --provenance-sha256 <recorded-provenance-sha256>
```

`stage` creates a new directory containing `payload/`, `payload-provenance.json`
and a qualification-only README. It refuses to replace any existing output.
The application build is a separate explicit step: copy the target executable
as `asm-tool` or `asm-tool.exe` into that directory and embed the exact
`bundle_sha256` returned by `stage` as the application's trust anchor. The
archive command requires independently recorded application, bundle and provenance
digests. It validates the closed tree against the canonical phase 8 manifest,
then writes a sorted ZIP using stored entries and fixed timestamps. Archive
output must be a new path outside its input root.

The utility imposes limits of 5,000 entries and 512 MiB of staged data. It
checks hashes, file sizes, manifest allowlists and closed-tree membership;
those checks do not establish supply-chain identity. Trust in a lock depends
on the separately approved acquisition and provenance records. This
preparation does not qualify a Linux or Windows payload, authorize a scan, or
unblock the browser. Historical candidate31 remains a security FAIL.

Staging must run in a private developer-owned parent directory with no concurrent writers. Directory publication uses rename after checking that the destination is absent; concurrent directory creation is outside this contract. Archive publication uses an atomic hard link and never replaces an existing destination. Filesystem ACL/reparse behavior on Windows remains NOT_RUN. README bytes are fixed; provenance has a separately recorded external SHA-256 anchor; both are rechecked during archive copy.
