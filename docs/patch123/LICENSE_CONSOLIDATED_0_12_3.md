> **Решение владельца 22.10.2026:** правообладатель MIT подтверждён — Зуев Иван Алексеевич. Ранние обозначения MIT-holder как `OPEN` являются историческими; действующий статус в §10. Публичное распространение пока не разрешено из-за отдельных условий сторонних компонентов.

# ASM Tool 0.12.3 — консолидированный лицензионный статус

**Дата:** 22.10.2026. **Версия и релиз:** `v0.12.3`. **Статус:** `SOURCE_NOTICE_CORPUS_REVIEWED / PACKAGE_INTEGRITY_PASS / PUBLIC_REDISTRIBUTION_NOT_CONFIRMED`.

Этот документ — **единая актуальная точка входа** для результатов лицензионных проверок. Он объединяет уже выполненные проверки 0.12.0–0.12.3 и разделяет исторические отчёты о промежуточной стадии от фактического окончательного комплекта. Это не юридическое заключение. Никакие продуктовые исходники, бинарники и архивы Release при этой консолидации не изменялись.

## 1. Идентичность финального кандидата и границы проверки

| Архив | Размер | SHA-256 |
|---|---:|---|
| `ASM_Tool_0.12.3-linux-x86_64.zip` | 296102932 | `695d48df48d8b840f5e8ac240b3a29a025d61b85511b8458fa9de5246d19046a` |
| `ASM_Tool_0.12.3-windows-x64.zip` | 239602994 | `6dc9b4e8289453a598982d957e952b930b448ac0e6d95da3a2619151816d710b` |
| `ASM_Tool_0.12.3-Linux-Windows.zip` | 535801302 | `fdd111db5de8320dce4a0d65b751be8fb8f1d96bea0c53a86eb00e0fe8970dc5` |

Эти SHA подтверждены предыдущими offline ZIP/manifest/CRC-проверками и метаданными текущего приватного Draft Release; файл `SHA256SUMS` включён в Release. Последняя коррекция версии Go `47a73ed` не пересобирала Windows GUI и не изменяла его runtime, CRT и сторонние файлы: были скорректированы Go CLI/метаданные и связанные manifest/hashes. Подробности: [RELEASE_ARTIFACT_VERIFICATION.md](RELEASE_ARTIFACT_VERIFICATION.md).

**Важно:** архивная комплектность, тесты Go и статический анализ импортов не заменяют разрешение на распространение чужих бинарников и не доказывают весь фактический состав статически слинкованных зависимостей.

## 2. Сводная матрица — уже исследовано / осталось подтвердить

| Область | Подтверждённые ранее результаты | Текущая граница |
|---|---|---|
| Собственный Go / WinUI код | Владелец выбрал MIT для собственного кода; корневой файл `LICENSE` имеется | **OPEN:** поле copyright holder всё ещё placeholder; завершить реквизиты по решению правообладателя |
| Windows GUI и .NET | **BUILT_AND_PACKAGED**. По owner handoff: Windows 10 build 19045, .NET SDK 10.0.402, `BUILD_PASS`. Финальная сборка содержит 509 GUI файлов, `ASMTool.exe`/`ASMTool.dll` 0.12.3.0, .NET 10.0.13; 225 assets из фактического `.deps.json` присутствуют | Реальный Windows runtime/native/clean-machine запуск и полное сопоставление актуального binary closure с лицензионными notices **NOT_RUN / PARTIAL**; исходный GUI source ZIP не был независимо сопоставлен с transfer archive |
| Статические зависимости GUI | Исследованы 273 PE, 1260 обычных и 101 delayed import; подтверждённых недостающих private DLL нет; дополнительных GUI CRT-копий не требуется | Не включает динамический `LoadLibrary`, P/Invoke, COM/WinRT activation и реальные платформенные runtime checks |
| Microsoft CRT в Go payload | Две DLL `vcruntime140.dll` и `vcruntime140_1.dll` идентифицированы по версиям 14.51.36247.0 и SHA-256; скопированы из исторического Windows 0.11.3 ZIP. Общая схема разрешённого Microsoft Redistributable ранее изучена | **OPEN:** привязка именно этих двух копий к официальному источнику и права конкретного распространителя по Visual Studio/REDIST условиям в сохранённых доказательствах 0.12.3 не установлена. Это **не** утверждение о запрете распространять CRT |
| Microsoft Windows App SDK / .NET / WebView2 / ML | Сохранены 15 наборов exact-version license/notice/nuspec и SHA-256 NuGet-пакетов; отдельные компоненты официальных NuGet исторически сопоставлены по хешам | Нужна итоговая проверка notices против фактического `ASMTool.deps.json` и состава DLL 0.12.3. Windows App SDK и WebView2 не следует обозначать «весь MIT» |
| Linux glibc и libgcc | Четыре runtime файла идентифицированы и сопоставлены с exact Ubuntu source packages; сохранены glibc/GCC orig/patch/.dsc, Debian/Ubuntu copyright maps, GNU license тексты, подписанные indexes. 185-файловый corpus проверен по хешам (`exit 0`) | Подписи отдельных `.dsc` и glibc upstream не были проверены; достаточность LGPL §6 по конечной поставке нельзя заключить из самого факта наличия исходников |
| LGPL replacement | В прежнем исследовании сообщалось о **9 лабораторных PASS**, включая замену `libm.so.6`: старый manifest отклоняет изменённый payload, пересобранный manifest принимает. Документирована процедура rebuild anchor + verify | Результат относится к предыдущему эксперименту, не является подтверждённой полной пользовательской сборкой и юридической `§6`-квалификацией окончательного ZIP 0.12.3 |
| Go/Subfaster | MIT и notices собраны, 185 corpus entries (включая Linux runtime); H1 проверялся для общих/платформенных Go модулей, Linux 108 и Windows 107 package records | Windows main-module H1 в build info не указан; физический исполняемый файл не доказан как полный source-to-binary BOM; не надо проводить весь аудит заново |
| Obscura и V8 | Obscura 0.2.2 Apache-2.0, исходные notices и релевантные source archives собраны; исходный V8 `third_party/glibc` (LGPL-2.1) и license corpus сохранён | **OPEN:** точный V8 prebuilt archive, linking/build features и включение `third_party/glibc` в реально поставленный Obscura worker не аттестованы. Linux worker `AUTHENTICITY_NOT_VERIFIED` |
| Typst / Rust | Typst 0.15.1 upstream LICENSE/NOTICE сохранены; ранее исследовались 403 crates, в актуальном `Cargo.lock` 425 записей; verified exact crates/notices `option-ext` MPL-2.0, OpenSSL 3.4.0 и wrapper notices имеются | Lock-файлы не эквивалентны установленному SBOM и не доказывают feature closure конечного бинарника; требования MPL и другие notices проверять только для реально вошедших компонентов |
| Nmap | Удалён из ASM Tool 0.12.3; отсутствие в ZIP проверено | Старые проверки NPSL/Nmap не являются текущим блокером или задачей повторного аудита |

## 3. Windows GUI: исправление исторически устаревшего статуса

Ранние [GUI_DEPENDENCY_LICENSES.md](GUI_DEPENDENCY_LICENSES.md), [GUI_THIRD_PARTY_NOTICES.md](GUI_THIRD_PARTY_NOTICES.md) и [MICROSOFT_COMPONENTS_PROVENANCE.md](MICROSOFT_COMPONENTS_PROVENANCE.md) создавались **до** передачи готового Windows GUI. Формулировки «new GUI has not been built» и «GUI publish closure NOT_RUN» в них — *состояние первоначального этапа*, не итоговой упаковки.

Позднее, 22.10.2026, независимые `gui-handoff`/artifact/static-DLL reviews подтвердили по переданным артефактам:
- 509 GUI файлов и совпадение хешей со входным handoff;
- фактические `ASMTool.exe` и `ASMTool.dll` версии 0.12.3.0, PE AMD64 для основного EXE;
- полноту **225** assets `ASMTool.deps.json` в выполненном статическом объёме;
- 273 статически разобранных PE, отсутствие доказанных отсутствующих private DLL;
- отсутствие необходимости добавлять копии `vcruntime140*.dll` в **корень GUI**.

Результат: **`GUI_BUILT_AND_PACKAGED / STATIC_DEPENDENCY_COMPLETENESS_PASS / NATIVE_NOT_RUN`**. Точный числовой exit code Windows build в переданном handoff не записан; установленный `BUILD_PASS` — сообщение владельца, не независимая пересборка. Подлинность source transfer и настоящий clean-machine старт отдельно не подтверждены.

**GUI CRT и Go payload CRT — разные вопросы.** Отсутствие CRT импортов в самом GUI не устраняет две DLL в `payload/bin/`; считать эти DLL автоматически разрешёнными к распространению на основании импорта GUI нельзя.

## 4. Microsoft CRT — что означает прежний «вопрос закрыт»

Ранее была исследована общая применимость официальной схемы Visual C++ Redistributable, и повторять её изначально не требуется. Это **положительный технический/лицензионный маршрут**, а не доказательство лицензии для каждой перенесённой DLL. Актуальное руководство Microsoft допускает app-local файлы, но связывает распространение с лицензированным Visual Studio пользователем и Software License Terms.

Точный открытый вопрос минимален: наличие соответствующего законного лицензированного источника и право владельца распространить **две имеющиеся x64 DLL** в `payload/bin/`; по возможности сопоставление hash именно с official REDIST/VS redistributable. Их исторический `0.11.3-development.zip` подтверждает только lineage. Если доказательство предоставлено — достаточно оформить запись для этих двух SHA без полного повторного CRT-аудита. **Без этого подтверждения итоговый статус остаётся `CRT_REDISTRIBUTION_EVIDENCE_PENDING`.**

Идентификаторы уже зафиксированы:
- `vcruntime140.dll`: `d1f4225df2cd877dbf130d5668a021dce3f94118455ff5ec952061c30afc9ce7`;
- `vcruntime140_1.dll`: `a7146c08f89fe5b04541ab507cdb59ff7b44534d4ba3c668a426c6450a03434e`.

Официальные условия: https://learn.microsoft.com/en-us/cpp/windows/redistributing-visual-cpp-files .

## 5. GNU runtime и V8 — разные LGPL-вопросы

Для **bundled glibc** оригинальные source archives/copyright и подтверждённые hashes уже собраны. Старые лабораторные тесты замены библиотеки — полезное подтверждение механизма fail-closed для манифеста и управляемой пересборки, но не доказательство, что конечный пользователь при распространении сможет реализовать предусмотренную LGPL 2.1 §6 замену/перелинковку.

Для **V8** возможный LGPL код `third_party/glibc` выявлен в upstream source tree; неизвестно, включён ли он в **конкретный предварительно собранный V8** внутри Obscura. Нельзя механически переносить готовность системной glibc на V8. Закрывающий артефакт — доказуемая source/build связь конкретного Obscura worker, V8 static library и target features, после чего можно определить применимые obligations.

Условия LGPL 2.1, включая §6: https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html .

## 6. Материалы, которые сохраняются и не требуют повторного сбора

В дереве `licenses/patch123/` оставлены соответствующие source archives для Linux, GNU notices, `CORPUS.SHA256SUMS`, Go/Subfaster notices, оригинальные Microsoft NuGet licenses/NOTICES, Rust manifests/locks и запрошенные по точным версиям upstream notices. Удалять их только ради уменьшения размера GitHub нельзя.

Основные существующие документы остаются техническими приложениями к **настоящему** актуальному отчёту:
- [LINUX_RUNTIME_LICENSES.md](LINUX_RUNTIME_LICENSES.md) и [LGPL_REPLACEMENT.md](LGPL_REPLACEMENT.md);
- [GO_DEPENDENCY_LICENSES.md](GO_DEPENDENCY_LICENSES.md);
- [RUST_DEPENDENCY_LICENSES.md](RUST_DEPENDENCY_LICENSES.md);
- [GUI_DEPENDENCY_LICENSES.md](GUI_DEPENDENCY_LICENSES.md), [GUI_THIRD_PARTY_NOTICES.md](GUI_THIRD_PARTY_NOTICES.md);
- [MICROSOFT_COMPONENTS_PROVENANCE.md](MICROSOFT_COMPONENTS_PROVENANCE.md), [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md);
- [SPDX_MATRIX.json](SPDX_MATRIX.json) (проверенная source-матрица, не полный binary SBOM);
- [RELEASE_ARTIFACT_VERIFICATION.md](RELEASE_ARTIFACT_VERIFICATION.md).

Исторические аудиторские акты и полные журналы были исключены из очищенной `main`; ранее считанные результаты GUI handoff и старой лабораторной LGPL-проверки изложены здесь с их **доказательственными границами**. Их нельзя представлять как результат новых тестов 22.10.2026.

## 7. Остаточные задачи строго по отсутствующим доказательствам

1. **MIT holder:** подтвердить юридически корректное имя правообладателя и заменить placeholder в корневом `LICENSE` / `PROJECT_LICENSE_METADATA.json`.
2. **Microsoft CRT:** связать две x64 DLL с допустимыми к распространению файлами Visual Studio/REDIST и подтвердить применимость условий к распространяющему лицу. GUI не нуждается в дополнительном наборе этих DLL.
3. **GUI notices:** сопоставить уже имеющийся 225-file `deps.json` closure и distributable files с текущими Microsoft/.NET/WebView2 notice records; сохранять условия Microsoft раздельно от MIT.
4. **V8/Obscura:** установить build provenance/фактически использованный V8 prebuilt archive/feature set и применимые LGPL requirements; не повторять исходный сбор notices без изменения версии.
5. **GNU LGPL:** зафиксировать пригодный для получателя пакет соответствующего source и выбранный механизм LGPL 2.1 §6 для конечного Linux runtime; при необходимости подтвердить реальный user replacement workflow для exact 0.12.3.
6. **Финальный комплект:** сформировать бинарно обусловленный notices checklist на основе подтверждённого фактического состава; проверить, что обязанность доступа к исходникам выполняется в выбранном канале распространения.
7. **Отдельно от лицензий:** Windows runtime/compatibility/security qualification (`NOT_RUN`) и browser isolation (`NOT_SECURITY_QUALIFIED`) остаются техническими ограничениями, а не лицензионными дефектами.

Эти пункты **не означают**, что нужно снова собирать с нуля NuGet/Cargo/Go-лицензии и GNU исходники.

## 8. Итоговое решение

- **`LICENSE_AND_NOTICE_SOURCE_COLLECTION = PASS_WITH_SCOPE`** — для ранее инвентаризованных комплектов.
- **`WINDOWS_GUI_BUILT_AND_PACKAGED = PASS_WITH_HANDOFF_BOUNDARY`**.
- **`RELEASE_ASSET_INTEGRITY = PASS`** для трёх окончательных ZIP.
- **`BINARY_SPECIFIC_LICENSE_CLOSURE = PARTIAL`**.
- **`PUBLIC_REDISTRIBUTION_READY = NOT_CONFIRMED`**, пока не подтверждены точные открытые пункты §7.

Не менять GitHub visibility или переводить Draft Release в опубликованный выпуск на основании одного этого документа. Результаты юридического решения владельца и новых binary-provenance проверок вносить **сюда**, не плодить взаимоисключающие заключения.

## 9. Дополнительная независимая проверка бинарного происхождения — 22.10.2026

Этот раздел имеет приоритет над устаревшими статусами старых source-only отчётов. Выполнены read-only SHA-256, Windows Authenticode, upstream Release и упаковочные сверки. Приложение, GUI и релизные архивы **не изменялись**, GUI/runtime не запускались, юридическая квалификация не проводилась.

### 9.1 Microsoft CRT

На Windows 10 Pro 19045 обнаружен установленный x64 VC Runtime версии 14.51.36247.0 (реестр VisualStudio/14.0/VC/Runtimes/x64, Installed=1).

| Файл в System32 | SHA-256, совпавший с ASM Tool Windows payload | Authenticode |
|---|---|---|
| vcruntime140.dll | d1f4225df2cd877dbf130d5668a021dce3f94118455ff5ec952061c30afc9ce7 | Valid; Microsoft Windows Software Compatibility Publisher |
| vcruntime140_1.dll | a7146c08f89fe5b04541ab507cdb59ff7b44534d4ba3c668a426c6450a03434e | Valid; Microsoft Windows Software Compatibility Publisher |

**Подлинность файлов — PASS.** Это подтверждает идентичность подписанных Microsoft DLL, но **не устанавливает право данного распространителя копировать их** в комплект. Microsoft связывает распространение individual runtime DLL с лицензированным пользователем Visual Studio и условиями конкретной лицензии: https://learn.microsoft.com/cpp/windows/redistributing-visual-cpp-files . Статус entitlement: **PENDING_OWNER_CONFIRMATION**. Отсутствие необходимости CRT в самом GUI не устраняет две DLL Go payload.

### 9.2 Windows GUI и Microsoft notices

Windows 10: повторно сверены GUI SHA-256 с ранее проверенным handoff — ASMTool.exe = afb74f947a480c39fea5fa6d167f528f2c69bbeb476cd8dda0f4b9d2009790a8; ASMTool.dll = dcb49a6c0fb23deecc98af9aad8b3012dfa0d9d7b7e8f8e444c7dbf7f00b602a. GUI содержит **509 файлов**, фактический ASMTool.deps.json — **13 library/package records и 225 assets (206 runtime + 19 native)**. Все 225 asset-имён найдены на диске. Эта повторная проверка сопоставляла имена; ранее 509 файлов были отдельно проверены по SHA.

Сверка GitHub: в licenses/patch123/microsoft/PACKAGE_INVENTORY.json значится 15 NuGet-пакетов и 37 исходных файлов license/notice/nuspec; все **37/37** представлены по ожидаемым путям и с правильными SHA-256 в packaging/portable/windows-amd64-patch123.lock.json. Missing = 0; mismatches = 0. Статус **GUI_ASSET_PRESENCE_PASS / MICROSOFT_NOTICE_MANIFEST_PASS_WITH_SCOPE**. Это не делает все Microsoft лицензии MIT и не заменяет проверку условий распространения.

### 9.3 Obscura v0.2.2: подтверждённый официальный upstream

С официального GitHub Release получен архив Linux и проверен SHA-256 внешнего пакета и двух распакованных исполняемых файлов.

| Файл | SHA-256 | Результат |
|---|---|---|
| obscura-x86_64-linux.tar.gz | 9e5d9d081909ea983bc8c94999bb3d411fd6b74a9788504295b7e25f84310505 | Official upstream archive MATCH |
| Linux obscura | c1b4548e36549a0228c39c1cc842df425bc7253af2b0a56bd2a538d8ff7e3406 | ASM Tool lock MATCH |
| Linux obscura-worker | 1770966b98d1f9c881e7d4f5adda1375b5eec553485d807c35efa5d72a662379 | ASM Tool lock MATCH |
| obscura-x86_64-windows.zip | db5a3c951f7172eb8f25e6d71bd7120c7128f70f6daed55a6cc4caaabe1674d6 | Official upstream archive digest equals ASM Tool lock |

Upstream: https://github.com/h4ckf0r0day/obscura/releases/tag/v0.2.2 . Точное release workflow для обычного архива задаёт cargo build --release --target [target] -p obscura-cli --bins --features render. Следовательно, использован стандартный вариант **render, без stealth**. Старый статус Linux worker AUTHENTICITY_NOT_VERIFIED **закрыт**; статус UPSTREAM_ORIGIN_VERIFIED.

Однако Cargo features не доказывают пофайловый статический состав V8 prebuilt library. Выявленный ранее исходный V8 third_party/glibc LGPL-2.1 требует отдельного решения о бинарном включении и применимости LGPL/relinking. Это не автоматически закрывается найденным upstream archive.

### 9.4 Typst v0.15.1: происхождение обеих платформ подтверждено

| Файл | SHA-256 | Результат |
|---|---|---|
| Официальный Linux musl tar.xz | a6d077d0a95eed5a2eba715b2dae06be954f624ccbf85758a03f389ded33118c | Official release digest MATCH |
| Распакованный Linux typst (55 739 488 байт) | 29273eaa04f6d00edd0c2bec578f565fc9c65be856bfbffc894567c68ed0b237 | ASM Tool Linux lock MATCH |
| Официальный Windows MSVC ZIP | 19ce3551153c2fe7ee9fa2f95208310c8f4d3209fedb699e0333faf8913f6736 | Official release digest MATCH |
| Распакованный Windows typst.exe (52 487 680 байт) | 081217a463adb006f8894b44227fe4b9c9e91fc85f5463d5948e8370db9bb31e | ASM Tool Windows lock MATCH |

Upstream: https://github.com/typst/typst/releases/tag/v0.15.1 . Источник обеих бинарных поставок **VERIFIED**. Применимые лицензии компонентов Typst (включая MPL-2.0 option-ext при фактическом включении) продолжают действовать; происхождение бинарника не заменяет проверку лицензий.

### 9.5 Сохранённые ранее GNU/LGPL материалы

185-файловый GNU/Go source-and-notice корпус, соответствующие исходники glibc/GCC и Ubuntu signed repository metadata уже присутствуют. Исторические 9/9 лабораторных проверок замены libm.so.6 полезны как функциональное свидетельство механизма replacement, но не равны подтверждённой юридической LGPL §6-квалификации для всей поставки 0.12.3. Особая ситуация V8 third_party/glibc оценивается отдельно.

### 9.6 Границы окончательной готовности

**PASS:** происхождение Obscura Linux и Windows, Typst Linux и Windows, CRT hash/подписи, комплектность 225 GUI assets по имени, включение 37 Microsoft license/notice/nuspec записей по SHA и предыдущие проверки источников в их scope.

**Остаётся OPEN:** утверждённый MIT правообладатель, права конкретного распространителя на две Microsoft CRT DLL, фактическое включение LGPL-фрагментов V8 и достаточный механизм их замены/перелинковки, итоговая юридическая квалификация всех бинарно-обусловленных notices. Полный Rust binary-SBOM не утверждён.

**PUBLIC_REDISTRIBUTION_READY = NOT_CONFIRMED.** Отсутствие доказательства — не обнаружение нарушения, но и не разрешение выпускать продукт публично. Не менять версию, бинарники, тег, Draft Release и visibility на основании данного исследования.

## 10. Решение правообладателя и Microsoft CRT — 22.10.2026

**Правообладатель собственного кода подтверждён лично владельцем:** **Зуев Иван Алексеевич**. Корневой `LICENSE` и `licenses/patch123/PROJECT_LICENSE_METADATA.json` приведены в соответствие с этим подтверждением, год — 2026. **`MIT_COPYRIGHT_HOLDER = CLOSED`.** Лицензия MIT действует на собственный код проекта; лицензии сторонних бинарников не подменяются MIT.

**Цель распространения подтверждена владельцем:** исходники на публичном GitHub под MIT, бесплатные готовые ZIP для Linux и Windows. Наличие бесплатного релиза не устраняет обязательств по сторонним лицензиям. До их выполнения GitHub продолжает быть PRIVATE, Release — DRAFT.

**Visual Studio не используется владельцем.** Для варианта app-local не требуется включать IDE Visual Studio в ZIP: пакет содержит только нужные DLL (в ASM Tool — две `vcruntime140*.dll`). Однако Microsoft официально ограничивает распространение пакета/отдельных файлов Visual C++ Runtime лицензированными пользователями Visual Studio с соблюдением Microsoft Software License Terms. Подлинность обеих DLL и их Microsoft Authenticode уже установлены, но она не доказывает наличие соответствующих лицензионных прав конкретного распространителя. См. https://learn.microsoft.com/cpp/windows/redistributing-visual-cpp-files и https://visualstudio.microsoft.com/license-terms/ .

**Два допустимых направления без упаковки Visual Studio:** (A) подтвердить подходящую лицензию Visual Studio (для отдельного разработчика может подойти бесплатная Community, в пределах её актуальных условий) и выполнить все applicable redistributable conditions, сохранив DLL; (B) изменить комплектацию, исключив локальные CRT DLL, и использовать системный Visual C++ Redistributable, установленный пользователем отдельно на условиях Microsoft. Направление B **изменяет SHA-256 итоговых ZIP**, требует нового кандидата, manifest/test проверки и не может считаться уже выполненным. Ни один вариант не одобрен автоматически без проверки условий. Один лишь факт установки свободно скачиваемого Redistributable на Windows не доказывает право **его повторного распространения**.

**Остаётся:** `CRT_REDISTRIBUTION_ENTITLEMENT = OPEN`, `V8_LGPL_BINARY_OBLIGATIONS = OPEN`, `PUBLIC_REDISTRIBUTION_READY = NOT_CONFIRMED`. Продуктовые Go/C# исходники и бинарники на этом шаге не изменялись; утверждение авторства не означает разрешения публиковать при нерешённых сторонних условиях.

## 11. Предрелизная проверка первичных лицензионных условий, 22.10.2026

### 11.1 Проверка Microsoft Visual C++ 2026 на соответствие конкретным условиям

Проверенные **первичные** документы:
- REDIST-лист для Visual Studio 2026: https://learn.microsoft.com/en-us/visualstudio/releases/2026/redistribution
- Правила распространения Microsoft Visual C++: https://learn.microsoft.com/en-us/cpp/windows/redistributing-visual-cpp-files?view=msvc-170
- Актуальные правила лицензирования VS: https://www.microsoft.com/licensing/guidance/Visual-Studio
- Исходный договор Community 2026: https://visualstudio.microsoft.com/license-terms/vs2026-ga-community/
- Исходный договор VC++ v14 Redistributable: https://visualstudio.microsoft.com/license-terms/vs2026-ga-visualcpp-v14-redist-runtime/

REDIST-лист 2026 говорит: если распространитель располагает **validly licensed copy** VS Community, Professional, Enterprise либо Build Tools, ему разрешено копировать и передавать вместе со своей программой неизменённые файлы из `[VisualStudioFolder]\VC\redist` с соблюдением дополнительных условий договора. Это **условное**, а не общедоступное разрешение на перекомплектацию любых файлов из Windows System32.

**Установленные факты по ASM Tool:** две x64 retail DLL 14.51.36247.0 в `payload/bin` идентичны действительным Microsoft-подписанным System32 DLL; хеши записаны в §9; лицензия MIT относится только к собственному коду; проект является самостоятельным приложением; распространение заявлено бесплатным.

**Принципиальное отличие:** факт присутствия DLL на Windows 10/11 не означает их включение в гарантированный стандартный образ. Встроен `UCRT`/`ucrtbase.dll`; `vcruntime140*.dll` требуют отдельного Visual C++ v14 runtime и/или установку другим ПО, гарантии наличия на чистой ОС нет. Источник: https://learn.microsoft.com/en-us/cpp/windows/universal-crt-deployment?view=msvc-170 .

**Не выполнена проверка условия наличия действительной лицензии:** правообладатель прямо сообщил, что Visual Studio не использует. Microsoft разрешает индивидуальным разработчикам бесплатную Community, но **возможность её получить не равна владению действительной лицензией**. Не найден документ, устанавливающий, что простая регистрация на сайте либо чтение соглашения автоматически предоставляет право на отдельное распространение DLL без приобретения/принятия лицензионного продукта. Текст EULA 2026 размещён Microsoft встроенным DOCX, получить и полностью сопоставить его раздел о redistribution в текущем сеансе не удалось; НЕ считать эту часть договора проверенной.

**Разрешённая схема зафиксирована достаточно определённо:** (1) иметь применимую действительную лицензию VS/Build Tools; (2) использовать разрешённые неизменённые REDIST-библиотеки; (3) соблюдать остальные условия фактического договора, включая правила передачи и ограничения на использование. Из этих трёх блоков (2) технически подтверждён; (1) и полная проверка (3) — **NOT ESTABLISHED**. Факт подписания DLL Microsoft не решает (1).

**Юридический вывод:** отсутствие технического нарушения в самих DLL не равняется разрешению на публикацию их копий в ZIP. Публичный выпуск с двумя DLL без установленного лицензионного основания **не следует квалифицировать как compliant**. Пока приватный Draft Release не публикуется, заявленная публичная передача не выполнена.

**Законные маршруты без упаковки самой Visual Studio:**
- `KEEP_DLLS`: разработчик легально приобретает/использует подходящую бесплатную Community (либо иную допустимую лицензию), документирует её применимость и исполняет redistributable terms. Существующие DLL сохраняются, если источник/объём и условия договора допускают это; загрузка IDE в ZIP **не требуется**.
- `SYSTEM_PREREQUISITE`: разработчик не передаёт DLL и установщик Redistributable в ZIP; получатель самостоятельно устанавливает их с сайта Microsoft. Предусмотреть проверку наличия и сообщение со ссылкой на официальный пакет; такой переход **требует пересборки, нового набора SHA и native-smoke на чистой Windows**. Отсутствие CRT нельзя считать безопасным для Windows Obscura без запуска на системе без VC Redistributable.
- Отдельно от CRT: Windows GUI runtime и условия других Microsoft SDK остаются в сфере уже собранных package-specific notices; REDIST-лист не делает их общим MIT.

### 11.2 Конкретный исходный LGPL-триггер в V8 13.7.152.14

Ранее `RUST_DEPENDENCY_LICENSES.md` трактовал `third_party/glibc` как теоретически включаемую часть V8. Дополнительная проверка **точного V8 submodule commit `f68bbb6cda689a14d019a6a60cc93963724e7c35`** даёт более сильное утверждение:

1. `denoland/v8` `gni/v8.gni`, строка 166: **`v8_use_libm_trig_functions = is_clang`**. https://github.com/denoland/v8/blob/f68bbb6cda689a14d019a6a60cc93963724e7c35/gni/v8.gni
2. `denoland/v8` `BUILD.gn`: при этом флаге в зависимости включён `:libm`, а в `source_set("libm")` перечислены девять `third_party/glibc/src/sysdeps/ieee754/dbl-64/...` исходников. https://github.com/denoland/v8/blob/f68bbb6cda689a14d019a6a60cc93963724e7c35/BUILD.gn
3. `denoland/rusty_v8` `build.rs` для `v137.3.0`: при сборке из исходников выбирается Clang, если не выставлен `DISABLE_CLANG`, и допускается `GN_ARGS`; стандартный режим также может загружать prebuilt static lib. https://github.com/denoland/rusty_v8/blob/v137.3.0/build.rs
4. Upstream release workflow Obscura `v0.2.2` устанавливает Clang на Linux и выпускает стандартный `render` вариант. https://github.com/h4ckf0r0day/obscura/blob/v0.2.2/.github/workflows/release.yml
5. `third_party/glibc/README.v8` маркирует код **LGPL 2.1, Shipped: yes**. https://github.com/denoland/v8/blob/f68bbb6cda689a14d019a6a60cc93963724e7c35/third_party/glibc/README.v8

**Вывод:** включение LGPL-исходников в сборочный граф V8 при стандартной конфигурации Clang **обоснованно ожидается**, а не является только предположением из каталога лицензий. При этом сборочный граф ещё не доказывает включение каждого объектного файла в фактический `obscura` и `obscura-worker`, поскольку статическое линкование может исключать невостребованные секции; точный архив prebuilt V8/его GN args и бинарное включение не аттестованы.

**Условие LGPL §6:** если исполняемый файл статически включает LGPL-покрытую библиотеку, при его передаче получатель должен получить применимые уведомления и один из предусмотренных §6 способов модификации/перелинковки (например, соответствующий исходный код библиотеки плюс объектные файлы/исходники «работы, использующей библиотеку», позволяющие создать изменённый исполняемый файл), либо корректную альтернативу §6. Перечень отдельных исходных LGPL файлов и текст LGPL в архиве не доказывает выполнения этого условия. Источник: https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html .

**Два инженерных способа устранения риска:**
- `RELINK_SUPPORT`: обеспечить реально проверенный соответствующий комплект source + build/linkable objects и инструкцию для exact upstream binaries, с воспроизводимым тестом модификации LGPL-кода. Простого списка Cargo.lock и notice недостаточно.
- `REBUILD_WITHOUT_GLIBC_FORK`: собрать собственные Obscura worker/CLI из exact источников, используя `V8_FROM_SOURCE=1` и проверенное `GN_ARGS=v8_use_libm_trig_functions=false`; проверить GN args, отсутствие именно этих glibc objects/символов в итоговом V8 и пересобранном Obscura, качество браузерных проверок, прочие лицензии и оба OS payload manifest. Это **предлагаемая модификация**, **не выполненный факт**.

Выбор способа требует доступа к реальному V8 static lib или пересборки Obscura, а не нового текстового пересказа лицензии. Исследованного текста достаточно, чтобы оценить текущую LGPL-ситуацию как **конкретный риск нарушения условий при публикации**, а не сообщать `PASS`.

### 11.3 Остаток по состоянию текущего audit

| Направление | Установленное состояние |
|---|---|
| Правообладатель и MIT | **CLOSED**: Зуев Иван Алексеевич, исходный код под MIT |
| Windows CRT подлинность и REDIST category | **PASS** |
| Windows CRT право распространения именно данным владельцем | **NOT ESTABLISHED**, публичная передача данных DLL не одобрена |
| GUI 509-файловый handoff, 225 deps assets, 37/37 Microsoft notice lock | **PASS_WITH_STATIC_SCOPE** |
| Obscura/Typst upstream hashes | **PASS**, см. §9 |
| V8 LGPL в типовом Clang-графе | **CONDITIONALLY INCLUDED**, теперь подкреплено точными GN исходниками |
| V8 actual static-linked code, §6 relink method | **NOT QUALIFIED** |
| GNU runtime source and other notices | Старые PASS только в пределах документированных источников/хешей |
| Публикация GitHub/ZIP | **NOT APPROVED**, тег и приватный Draft не затронуты |

Это закрывающий *фактический* вывод в пределах доступных первичных материалов, а не требование выполнить тот же аудит ещё раз. Не заменять unresolved gates формальным `PASS` и не считать отсутствие предыдущих претензий юридическим разрешением.

### 11.4 Проверка готовности тега `v0.12.3`

Read-only проверка **содержимого точного Git-тега**, а не только ветки `main`, установила отдельный документальный дефект: `LICENSE` в `v0.12.3` **до сих пор содержит `[COPYRIGHT HOLDER — TO BE CONFIRMED]`**, а `licenses/patch123/PROJECT_LICENSE_METADATA.json` в теге имеет `UNCONFIRMED`. В `main` они уже корректно установлены на `Зуев Иван Алексеевич`.

Следовательно, **перед публикацией** недостаточно исправить только `main`. Нужно подготовить новый согласованный релизный коммит/tag/ZIP, где MIT holder и license/notice материалы соответствуют итоговой поставке; затем проверить exact tar/ZIP content, SHA256SUMS и тег. Существующий приватный тег и Draft ZIP в ходе этой проверки **не изменялись**. Статус `RELEASE_TAG_LICENSE_METADATA = STALE`.
