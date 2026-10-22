> **Актуальный статус, 22.10.2026:** Две CRT DLL 14.51.36247.0 по SHA идентичны подписанным Microsoft System32, Authenticode Valid; остаётся подтвердить права владельца на их redistribution. 509 GUI файлов, 225 deps.json assets и 37/37 Microsoft notice file checks подтверждены. Старые статусы ниже относятся к ранней стадии, когда GUI ещё не был собран. См. [консолидированный отчёт, §9](LICENSE_CONSOLIDATED_0_12_3.md).

> **Канонический статус релиза на 22.10.2026:** [LICENSE_CONSOLIDATED_0_12_3.md](LICENSE_CONSOLIDATED_0_12_3.md). Настоящий документ содержит результаты более раннего, в том числе до-GUI этапа; исторические `NOT_BUILT`/`NOT_RUN` применяются только в описанном исходном scope. Финальный GUI уже собран и статически проверен, но `PUBLIC_REDISTRIBUTION_READY` по-прежнему `NOT_CONFIRMED`.\n\n# Microsoft components provenance — ASM Tool0.12.3

## Evidence boundaries

Official exact NuGet archive sources, archive SHA-256, nuspec license declarations and original texts are in PACKAGE_INVENTORY.json. Source-declared direct references are distinguished from the historical0120 control `.deps.json` and source-nuspec transitive graph. Actual0123 GUI publish/assembly closure has not been produced; neither historical native PASS nor old compiledGUI are reused.

| Historical control file | PE file version observed | SHA-256 | Matched exact NuGet member |
|---|---|---|---|
| directml.dll | 1.15.4.0 | `fcdda5ad91e5b94660c28789cc425e1e5fef8e7ebf7a5a6dd849259f60d99559` | microsoft.windowsappsdk.ml.1.8.2091.nupkg:runtimes-framework/win-x64/native/DirectML.dll |
| microsoft.ml.onnxruntime.dll | 0.0.0.0 | `d1f95c46b5071c8e9d05db257a06a67cd93e9facb94e5fde9867575474544c1d` | microsoft.windowsappsdk.ml.1.8.2091.nupkg:lib/net8.0/Microsoft.ML.OnnxRuntime.dll |
| onnxruntime.dll | 1.23.25.910 | `3f0a2b3c5425a497ad5e24c7163d0da7b36941874f468bd5e1c9898ec66b4da7` | microsoft.windowsappsdk.ml.1.8.2091.nupkg:runtimes-framework/win-x64/native/onnxruntime.dll |
| onnxruntime_providers_shared.dll | 1.23.25.910 | `7fd9fb8d3c8ef810cb78f83094d3eaaa0d234cd185a8cd5e6110d11a171afc2f` | microsoft.windowsappsdk.ml.1.8.2091.nupkg:runtimes-framework/win-x64/native/onnxruntime_providers_shared.dll |
| webview2loader.dll | 1.0.3179.45 | `1970ae5e398666304483203dae64f8bc3327811114ae38bb3484ecbce1386b41` | microsoft.web.webview2.1.0.3179.45.nupkg:build/native/x64/WebView2Loader.dll, microsoft.web.webview2.1.0.3179.45.nupkg:runtimes/win-x64/native/WebView2Loader.dll |

The PE version is read statically from VS_FIXEDFILEINFO; managed assembly0.0.0.0 is not a NuGet package version. Reference member hashes match the exact official NuGet package content, but this is historical binary identity evidence, not publisher-signature verification or new0123 runtime evidence. Do not state all Windows runtime is MIT: the pinned WindowsAppSDK packages include Microsoft Software License Terms, while .NET runtime uses MIT with separate third-party notices.

## Existing Go payload CRT (separate from GUI runtime)

- `payload/bin/vcruntime140.dll`: PE version 14.51.36247.0, SHA-256 `d1f4225df2cd877dbf130d5668a021dce3f94118455ff5ec952061c30afc9ce7`, x64 machine0x8664. Input archive `ASM_Tool_0.11.3-win64-development.zip (historical input archive; local absolute path omitted)`, SHA-256 `c45b1218ca200ae9bd13a0aa7bc507403b3635e79b0418178f6a9454d731b99c`, member `ASM_Tool_0.11.3-win64-development/runtime/vcruntime140.dll`. Status **LICENSING_NOT_CLEARED**.
- `payload/bin/vcruntime140_1.dll`: PE version 14.51.36247.0, SHA-256 `a7146c08f89fe5b04541ab507cdb59ff7b44534d4ba3c668a426c6450a03434e`, x64 machine0x8664. Input archive `ASM_Tool_0.11.3-win64-development.zip (historical input archive; local absolute path omitted)`, SHA-256 `c45b1218ca200ae9bd13a0aa7bc507403b3635e79b0418178f6a9454d731b99c`, member `ASM_Tool_0.11.3-win64-development/runtime/vcruntime140_1.dll`. Status **LICENSING_NOT_CLEARED**.

The archive establishes existing file identity but does not establish the distributor's licensed Visual Studio/REDIST entitlement. Microsoft redistribution conditions apply to the specific files and licensed distributor; adding license text alone does not prove compliance. No matching original x64 Microsoft REDIST installer/entitlement evidence was available in the inspected inputs. Existing Nmap x86 CRT installer material is unrelated and not used; Nmap is absent.

## Rights and prerequisites

Official guidance: [Visual C++ redistribution](https://learn.microsoft.com/en-us/cpp/windows/redistributing-visual-cpp-files?view=msvc-170); [Windows App SDK deployment overview](https://learn.microsoft.com/en-us/windows/apps/windows-app-sdk/deploy-overview); [self-contained deployment](https://learn.microsoft.com/en-us/windows/apps/windows-app-sdk/self-contained-deploy); [NuGet content-hash definition](https://github.com/NuGet/Home/wiki/Nupkg-Metadata-File).

The GUI source requests SelfContained=true and WindowsAppSDKSelfContained=true. These are build settings, not proof that every runtime dependency is present. A native Windows builder must inspect the produced file closure, DLL loading, bootstrap requirements and WebView2 usage. Runtime setup, installation or system policy changes were not performed. Final publish requires no Python, GoSDK or .NETSDK at user runtime, but this assertion remains untested until a real new GUI publish exists.

`DEVELOPMENT_READY` for a complete GUI bundle is BLOCKED by the unavailable Windows build environment. `PUBLIC_REDISTRIBUTION_READY` is NOT_CONFIRMED: actual GUI closure, notices/terms compliance and CRT entitlement require separate evidence. Existing components are preserved; no license-related substitution was made.
