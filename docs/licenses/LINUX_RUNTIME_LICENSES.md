# Linux bundled runtime license and source record

The existing Linux portable candidate contains four copied runtime files under `payload/bin/linux-runtime/`:

| File | SHA-256 | Source binary package | License record |
|---|---|---|---|
| `ld-linux-x86-64.so.2` | `bda779ea9e9ad234f60315477d7cfd0bdde861cd8ddd9df8cdaf62f18c4cec14` | `libc6 2.43-2ubuntu2.4` | glibc Debian copyright, principally LGPL-2.1-or-later with per-file exceptions/additional licenses |
| `libc.so.6` | `85e64f97e348786a8fb4d9f3d52fec289e2fb86bba20f0731dfe61990525e0f7` | `libc6 2.43-2ubuntu2.4` | same complete copyright map |
| `libm.so.6` | `1c488db6f4fe8cecb72456bc018de000b7a9b539c2994864b0416b5e8371b3d8` | `libc6 2.43-2ubuntu2.4` | same complete copyright map |
| `libgcc_s.so.1` | `9d339ecb409578d6a5d587e6c537a8f9589b8a13fefba30d167433a4b5758bee` | `libgcc-s1 16-20260322-1ubuntu1` | GPL-3.0-or-later with GCC Runtime Library Exception 3.1 for libgcc runtime files |

Each hash matches the corresponding installed file and the existing portable artifact. `readelf` on Subfaster confirms `/lib64/ld-linux-x86-64.so.2` as interpreter and `libc.so.6` as a needed library. Binary package `.deb` SHA-256 values from local package metadata are recorded in `LINUX_RUNTIME_PROVENANCE.json`.

The complete Debian copyright files are included along with every full common-license text they explicitly reference: GFDL-1.3, GPL-2, GPL-3, generic GPL, LGPL-2, LGPL-2.1, LGPL-3, and Apache-2.0. The GCC Runtime Library Exception 3.1 text is included in the GCC package copyright file. Glibc is not a single-license source package: its Debian copyright file identifies file groups and exceptions, so consult that full mapping rather than applying LGPL uniformly to every upstream source file. The libgcc runtime exception allows propagation of eligible target code combined with the covered runtime library subject to the exception's conditions; it does not remove GPL obligations for GCC-derived runtime code or automatically cover code based on the runtime library.

The exact corresponding Ubuntu source packages are included under `licenses/patch123/go-runtime/linux-runtime/source/`:

- `glibc 2.43-2ubuntu2.4`, source directory `pool/main/g/glibc`; orig tar SHA-256 `d9c86c6b5dbddb43a3e08270c5844fc5177d19442cf5b8df4be7c07cd5fa3831`, Debian patch tar `28103a7cf808c29901c6053d89a4e8299880abfbb850c0d97a09c8df8533e306`, `.dsc` `da10d551ca51076bf7bf663de38369d04e267386b8211c283c2814e68e482ed3`.
- `gcc-16 16-20260322-1ubuntu1`, source directory `pool/main/g/gcc-16`; orig tar SHA-256 `7be0bbf2ed1797e31161993ea641331d230b9b95f1ca263e7e840a5843b61a4a`, Debian patch tar `d2912b1539846a5bfbe23e22191fb510d70af5d54ec2af5a15edff9b0ab95d9b`, `.dsc` `64a579a45be2dafef92bf8e0984223dd1c009df061d2890f584fd8c08f41b2f2`.

Both Ubuntu InRelease files verified with the locally installed Ubuntu archive keyring (`gpgv` exit 0). The exact compressed Sources indexes and signed metadata are retained. Their signed SHA-256 entries authenticate the index bytes; the index's package records bind the exact `.dsc` and source archive SHA-256 values. The `.dsc` OpenPGP signatures were not independently checked because their signing keys were not locally present; no keys were fetched. The glibc upstream detached signature file is retained but also not independently verified. File hashes, sizes, source-index chain, and signature limitations are itemized in [`LINUX_RUNTIME_PROVENANCE.json`](../../licenses/patch123/go-runtime/LINUX_RUNTIME_PROVENANCE.json).

### User replacement and payload integrity

The app verifies both per-file payload hashes and an embedded SHA-256 anchor for the manifest (`internal/app.BundleManifestSHA256`). Replacing a shared library in an existing ZIP will fail closed. A user who modifies or rebuilds an LGPL/GCC runtime component must retain the applicable source and notices, update the payload file hashes and manifest, then rebuild ASM Tool from source with the new manifest SHA injected into the app. This is the current integrity-preserving replacement path; no runtime override or weaker hash rule is introduced here. The regular app bundle and stager size limits are unchanged.

This record covers the exact Linux runtime found in the candidate, not a release approval or a claim of qualification on every distribution.

The complete license/source corpus file inventory is [`CORPUS.SHA256SUMS`](../../licenses/patch123/go-runtime/CORPUS.SHA256SUMS); the offline verification completed with exit 0 across 185 files. Source archive bytes including signed repository metadata total 124,821,726 bytes.
