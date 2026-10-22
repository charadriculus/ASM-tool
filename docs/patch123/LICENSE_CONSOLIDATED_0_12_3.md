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
