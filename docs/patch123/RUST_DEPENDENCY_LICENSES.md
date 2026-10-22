> **Корректировка аудита по exact V8 source, 22.10.2026:** V8 `f68bbb6...` имеет `v8_use_libm_trig_functions = is_clang` в `gni/v8.gni`. При этом флаге `BUILD.gn` включает `:libm` из `third_party/glibc` (LGPL-2.1). Стандартная upstream Linux Obscura release pipeline устанавливает Clang; Rusty V8 выбирает Clang по умолчанию. Это **конкретная условная source-build dependency**, а не просто наличие лицензии в исходниках. Фактические V8 prebuilt GN args/статическое включение и LGPL §6 relinking для конечного бинарника не квалифицированы. Возможный технический путь — самостоятельная пересборка V8/Obscura с `GN_ARGS=v8_use_libm_trig_functions=false` после отдельного функционального/лицензионного теста, **не выполнено**. См. [единый отчёт §11](LICENSE_CONSOLIDATED_0_12_3.md).

> **Актуальный статус, 22.10.2026:** Обе версии Obscura 0.2.2 и Typst 0.15.1 (Linux/Windows) теперь связаны с точными официальными upstream release binaries/archives по SHA-256. Linux obscura-worker и обычный obscura совпадают с upstream побайтно. Стандартный release workflow Obscura включает feature `render`, без `stealth`. Ниже сохранён **исторический source-only** аудит: его фразы `AUTHENTICITY_NOT_VERIFIED` больше не являются текущим статусом происхождения. Остаточный анализ V8 LGPL binary/relinking и полная статическая Rust feature closure не завершены; см. [консолидированный отчёт, §9](LICENSE_CONSOLIDATED_0_12_3.md).

# Rust dependency source and license review — patch 0.12.3

Status: **source-level review, partial dependency closure**. This report records exact source material and notices inspected for Obscura 0.2.2, Typst 0.15.1, and named Rust dependencies. It is not a legal opinion or public-redistribution approval. No build, binary execution, or runtime qualification was performed.

## Evidence and scope

The source archives were retrieved from the upstream GitHub tag archives and the crates.io static archive endpoint. Their byte sizes, SHA-256 values, URLs, versions, per-file hashes, SPDX expressions, and caveats are recorded in [`licenses-index.json`](../../licenses/patch123/rust/licenses-index.json). Exact Obscura/Typst locks and the relevant manifests are preserved under [`licenses/patch123/rust/source-metadata/`](../../licenses/patch123/rust/source-metadata/). The GitHub tag signatures were not independently verified; the archive hashes identify the retrieved bytes, not an authenticated tag signer.

| Source | Version/revision | SHA-256 | Inventory observation |
|---|---|---|---|
| Obscura source archive | `v0.2.2` | `5fc644e4925574975ed4f7d4e6b91c5e0345461983d863dda64cbf4011e1c0f2` | 450 archive members; 28,550,590 expanded bytes; no absolute/traversal paths or special members observed |
| Typst source archive | `v0.15.1` | `c07909e01a2a6941e52c9b616e48c209c755eed416d62bcf5583c37a4aca01a3` | 2,955 members; 10,358,776 expanded bytes; no absolute/traversal paths or special members observed |
| Rusty V8 source archive | tag `v137.3.0` | `fe83ab4d36893d42735dcb2103231b40504be0b97ff7e442d6ee7c6891bb9653` | Rust binding source; Git submodule points to V8 commit `f68bbb6cda689a14d019a6a60cc93963724e7c35`; V8 13.7.152.14 |
| V8 source archive | commit `f68bbb6cda689a14d019a6a60cc93963724e7c35` | `a4a55ee173fd3eb8334bc1c8929976e2079d85a5098c651c3e968988cce642ee` | 18,255 archive members; 153,717,929 expanded bytes; no absolute/traversal paths or special members observed; selected only license files |

The Obscura Cargo.lock has 468 package records and the Typst lock has 425. **These are lockfile package inventories, not the dependency closure of the shipped executables.** Cargo feature selection, target-specific compilation, exact build commands, vendored/prebuilt libraries, and local binary provenance have not been established. No `cargo tree`, build, or binary inspection was performed. In particular, the Linux worker identity hash `1770966b98d1f9c881e7d4f5adda1375b5eec553485d807c35efa5d72a662379` remains `AUTHENTICITY_NOT_VERIFIED`; do not bind these source findings to that executable as a confirmed bill of materials.

The Cargo archives for requested crates were checked against the corresponding lockfile `checksum` values. Vendored `taffy` and `cosmic-text` have no registry checksum in the Obscura lock; their exact manifests and notices come from the Obscura v0.2.2 source archive. `licenses-index.json` distinguishes source/archive integrity from actual binary inclusion.

## Obscura 0.2.2

The source root includes an Apache-2.0 `LICENSE`; no root `NOTICE` file was present in the inspected archive. The source describes `obscura-cli` `render` and `stealth` as optional features, with four release workflow variants. The local Obscura executable's variant and feature set are not evidenced, so all binary inclusion claims remain `UNKNOWN`.

Exact-version notice files retained include:

- Obscura root Apache-2.0;
- vendored `taffy` 0.12.1 MIT;
- vendored `cosmic-text` 0.14.2 Apache-2.0 and MIT notices;
- renderer asset `LICENSE-NOTO-COLOR-EMOJI.txt` (SIL OFL-1.1; asset use in a given build is unknown);
- `deno_core` 0.350.0 MIT, `ring` 0.17.14 Apache-2.0 AND ISC plus its included BoringSSL/Fiat/once_cell notices, `resvg` 0.47.0 Apache-2.0 OR MIT, and `tiny-skia` 0.12.0 BSD-3-Clause.

`v8` 137.3.0's registry crate is MIT-licensed Rust binding/build-script source. It downloads a separate prebuilt V8 static library at build time (`.a` on Linux, `.lib` on Windows); that prebuilt archive is not contained in the `.crate` and was not matched to the local Obscura binary. The upstream Rusty V8 tag references V8 13.7.152.14. The exact V8 submodule source archive and its root/subdirectory notices are retained. These include the V8 BSD-style notices and third-party notices for, among others, glibc (LGPL-2.1), highway (Apache-2.0), jsoncpp, re2, siphash, utf8-decoder, Valgrind, VTune, and WebAssembly API sources. Test-only V8 notices are kept under `v8-source/tests/` and are explicitly not evidence of runtime inclusion.

The exact V8 source tree marks its `third_party/glibc` subset `Shipped: yes` and LGPL 2.1 in `README.v8`. That directory contains 12 files: its `LICENSE`, `METADATA`, `README.v8`, and nine C/header math files. The complete subset is preserved with relative paths under `licenses/patch123/rust/obscura/crates/v8-source/third_party/glibc/` and is independently hashed in the index. This is a source-level finding distinct from the platform's system glibc. Whether any such code is present in the specific prebuilt V8 library, and what corresponding-source, relinkable-object, or recipe obligations apply to that binary, remain **unresolved** until the exact library/build provenance and feature set are established. The staged source subset and license text alone do not satisfy any source-offer or relinking requirement.

## Typst 0.15.1 and `option-ext`

Typst's upstream `LICENSE` and `NOTICE` are preserved byte-for-byte in `licenses/patch123/rust/typst/`. Existing portable Typst `LICENSE`/`NOTICE` files should remain the distribution copies; packaging should not add a second identical pair. The additional `option-ext` notice and source archive are separate.

The lock and checked package manifests establish this potential source dependency path:

`typst-cli` → `typst-kit/system-packages` → `dirs` 6.0.0 → `dirs-sys` 0.5.0 → `option-ext` 0.2.0.

The exact `.crate` SHA-256 values for `dirs`, `dirs-sys`, and `option-ext` match Typst's Cargo.lock checksums. `option-ext` declares MPL-2.0; its checked archive includes `LICENSE.txt`, Cargo metadata, README, and Rust source and is retained under `licenses/patch123/rust/typst/options-ext-0.2.0/`. This is the source material needed to make the exact unmodified option-ext crate source available with a distribution. If this MPL-covered source is modified or shipped as covered source, retain its notice and make the applicable source available under MPL-2.0, including identifying modifications; this report does not determine whether a particular binary statically includes it.

The inspected Typst CLI manifest requests Typst-kit features `bundle`, `embedded-fonts`, `scan-fonts`, `system-packages`, `universe-packages`, `datetime`, `emit-diagnostics`, `system-downloader`, `watcher`, and `timer`; its default CLI features are `embedded-fonts` and `http-server`. The official release workflow also enables `self-update`. This is upstream build configuration, not proof of the feature set used for an existing local Typst binary.

### OpenSSL 3.4.0 source and target-feature findings

The Typst 0.15.1 lock pins five OpenSSL-related packages: `openssl` 0.10.80, `openssl-macros` 0.1.1, `openssl-probe` 0.1.6, `openssl-src` 300.4.1+3.4.0, and `openssl-sys` 0.9.116. Their exact crate archives were fetched from crates.io and SHA-256 matched each lock checksum. Only Cargo manifests and original notices were staged; the full crate archives, including the 9,945,831-byte `openssl-src` crate, remain in the authorized temporary source cache.

The target/feature configuration in the exact Typst manifests is significant:

- `typst-cli` unconditionally requests Typst-kit `system-downloader`; that feature enables `dep:openssl` and `native-tls`.
- Typst-kit declares `openssl` only for targets other than Windows, macOS, iOS, watchOS, and tvOS. Thus the manifest indicates an OpenSSL path for Linux builds using this CLI feature set. This is source-graph analysis, not a build observation.
- The separate `vendor-openssl` feature maps to `openssl/vendored`; `openssl-sys` maps that feature to optional `openssl-src`. Without that feature the source manifests do not request vendoring. The lock alone cannot show whether a particular artifact used a system OpenSSL or the bundled source.
- Typst's v0.15.1 release workflow uses `self-update,vendor-openssl` for its cross-compiled targets, including `x86_64-unknown-linux-musl`. Its non-cross workflow uses only `self-update` for the Windows/MSVC and Apple targets. This upstream recipe suggests vendored OpenSSL in its Linux-musl release artifact and no OpenSSL dependency in its Windows target graph, but does not establish the build flags or provenance of the portable Typst binaries for this project. The workflow does not build a Linux GNU target.

The Rust wrappers declare Apache-2.0 / MIT licenses as recorded per crate. The `openssl-src` package contains OpenSSL 3.4.0 source; its bundled `openssl/VERSION.dat` confirms major 3, minor 4, patch 0 and is preserved at `licenses/patch123/rust/source-metadata/openssl-3.4.0-VERSION.dat`. The source's original `openssl/LICENSE.txt` states Apache License 2.0, and the source archive also contains the vendored Perl Text-Template 1.56 license. All original wrapper licenses, the OpenSSL license, and the Text-Template license are preserved in `licenses/patch123/rust/typst/openssl/`. Typst's existing upstream `NOTICE` does not mention OpenSSL or resvg; retain that file and supplement it with the applicable package notices if the corresponding components are distributed. The exact OpenSSL source license/notice files are not a substitute for confirming which library is in a shipped binary.

No Typst executable was present in this worktree for read-only `readelf` inspection. No dynamic dependency observation is claimed. Even if a future inspection finds no `DT_NEEDED` entry for OpenSSL, that would not exclude statically linked OpenSSL; it would need to be combined with build provenance and feature records.

The exact OpenSSL-related lock checksums and package license declarations are listed in the index. `openssl` declares Apache-2.0; `openssl-macros` and `openssl-probe` declare MIT OR Apache-2.0; `openssl-src` declares MIT OR Apache-2.0 for its Rust crate wrapper, while its bundled OpenSSL 3.4.0 source carries its own Apache-2.0 `LICENSE.txt`; `openssl-sys` declares MIT. The bundled Text-Template 1.56 notice states GPL version 1 or later OR the Artistic License. Original notices are preserved per component so packaging can supplement Typst's upstream NOTICE without replacing or duplicating Typst's own notice.

## Acquisition and verification record

Official source URLs and bounded retrievals:

- `https://github.com/h4ckf0r0day/obscura/archive/refs/tags/v0.2.2.tar.gz`
- `https://github.com/typst/typst/archive/refs/tags/v0.15.1.tar.gz`
- `https://github.com/denoland/rusty_v8/archive/refs/tags/v137.3.0.tar.gz`
- `https://github.com/denoland/v8/archive/f68bbb6.tar.gz` (128 MiB max; actual archive 30,879,655 bytes)
- `https://github.com/denoland/deno_core/archive/refs/tags/0.350.0.tar.gz` (64 MiB max; actual archive 803,405 bytes)
- `https://static.crates.io/crates/{name}/{name}-{version}.crate` for `deno_core`, `resvg`, `ring`, `tiny-skia`, `v8`, `option-ext`, `dirs`, and `dirs-sys` (per-request size caps were applied; Cargo.lock hashes matched).

Archives were listed/inspected without executing their contents. License-only extraction used fixed relative member names after rejecting absolute paths, `..` path components, and special archive members. `sha256sum` and Python `tomllib` were used for integrity/count checks; no package installation, build, runtime test, or external scan occurred.

A broad attempt to retrieve all 740 package archives from the combined locks was rejected by the automatic approval review as excessive for this bounded task and was not retried. Consequently, this report does **not** claim full transitive Rust license closure. Remaining lockfile dependencies and any vendored or prebuilt payloads outside the exact reviewed set require a feature/target-specific build manifest or verified SBOM before a binary-specific notice closure can be asserted.

## Release-facing actions still required

1. Preserve Typst's existing upstream `LICENSE` and `NOTICE` in each relevant portable distribution and add the `option-ext` MPL notice/source archive if the shipped Typst executable includes it.
2. Include the Obscura and V8 notices in distribution documentation if the associated binaries are shipped; preserve the V8 third-party notices and evaluate the LGPL-2.1 glibc source finding against the exact linked library/build.
3. Produce a provenance-bound, target/feature-specific SBOM or equivalent from the actual Obscura and Typst build inputs. Until then, binary closure and license completion remain `UNKNOWN`/`PENDING`, not `PASS`.
4. Have the project owner decide any distribution/legal interpretation after exact executable provenance is available. This source review does not authorize release.
