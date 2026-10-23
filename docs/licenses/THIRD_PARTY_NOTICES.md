> **Канонический статус релиза на 22.10.2026:** [LICENSE_CONSOLIDATED_0_12_3.md](LICENSE_CONSOLIDATED_0_12_3.md). Настоящий документ содержит результаты более раннего, в том числе до-GUI этапа; исторические `NOT_BUILT`/`NOT_RUN` применяются только в описанном исходном scope. Финальный GUI уже собран и статически проверен, но `PUBLIC_REDISTRIBUTION_READY` по-прежнему `NOT_CONFIRMED`.\n\n# Сторонние компоненты и уведомления — ASM Tool 0.12.3

Этот файл является навигацией по сохранённым исходным текстам лицензий и provenance. Используйте оригинальные файлы уведомлений из кандидата и их SHA-256 manifests; этот краткий обзор не заменяет их. Запись о найденном source package не доказывает, что компонент вошёл в конкретный исполняемый файл.

## Go, Subfaster и Linux runtime

- Subfaster v2.18.0: Linux payload SHA-256 `bbbe5e8c4adeb71d94e209bf5c9e269b90dbbe2ac63ff7497bac4c4fc830bd30`; Windows x64 SHA-256 `14f1d2beeb07f5660759bec1fb1f82ca6ff0e342165c1c86870fa52a1a341ba2`. Исходный MIT `LICENSE.md` и notices включены в описанный corpus. Фактический запуск не выполнялся; Windows main-module H1 отсутствует, поэтому идентичность его исходника не подтверждена полностью.
- Go-зависимости: версии, исходные notices, хеши и границы проверки описаны в [GO_DEPENDENCY_LICENSES.md](GO_DEPENDENCY_LICENSES.md). Контрольный corpus содержит 185 файлов; предшествующая проверка хешей corpus завершилась с exit 0. Это проверка целостности перечисленных документов, не полная проверка executable closure.
- Linux `ld-linux`, `libc`, `libm`, `libgcc_s`: исходные файлы, copyright map, package versions и source archives перечислены в [LINUX_RUNTIME_LICENSES.md](LINUX_RUNTIME_LICENSES.md). Комплект содержит соответствующие Linux source archives и notices. Подписи `.dsc` и upstream glibc detached signatures не были независимо проверены. Пользовательская замена runtime-библиотек описана отдельно в [LGPL_REPLACEMENT.md](LGPL_REPLACEMENT.md).

## Windows GUI и Microsoft

- Сохранённые NuGet package license/notice файлы перечислены в [GUI_DEPENDENCY_LICENSES.md](GUI_DEPENDENCY_LICENSES.md) и [GUI_THIRD_PARTY_NOTICES.md](GUI_THIRD_PARTY_NOTICES.md).
- Source references фиксируют Windows App SDK и BuildTools. Реальный WinUI publish closure не создан, поэтому фактический набор DLL и применимые к нему условия остаются `UNKNOWN/NOT_RUN`.
- Go payload содержит CRT файлы, совпавшие по хешам с файлами исторического development ZIP. Право их распространения не установлено: статус `LICENSING_NOT_CLEARED`. См. [MICROSOFT_COMPONENTS_PROVENANCE.md](MICROSOFT_COMPONENTS_PROVENANCE.md).

## Rust / Obscura / Typst

[RUST_DEPENDENCY_LICENSES.md](RUST_DEPENDENCY_LICENSES.md) содержит проверенные исходные license/notice материалы и явно перечисляет неизвестные для конкретных бинарников компоненты. Obscura 0.2.2 — Apache-2.0; Typst 0.15.1 сохраняет upstream `LICENSE`/`NOTICE`. Cargo locks не являются SBOM бинарников: активные features, prebuilt V8 library и точное build provenance неизвестны. Linux Obscura worker authenticity не подтверждена. Для Typst также зафиксированы потенциальные MPL/OpenSSL notices, но фактическое включение отдельных зависимостей в кандидат не установлено.

## Правообладатель проекта

Владелец выбрал MIT для собственного кода ASM Tool. `LICENSE` содержит незаполненный `UNCONFIRMED` правообладатель; здесь он не домысливается. MIT не распространяется автоматически на третьи компоненты. См. [LICENSE_COMPLIANCE_REPORT.md](LICENSE_COMPLIANCE_REPORT.md).

Исторический пофайловый payload mapping `planning/patch123/evidence/LICENSE_PAYLOAD_MAPPING.json` оставлен вне очищенной Git-истории. Для текущего проверяемого состава используются `packaging/portable/linux-amd64-patch123.lock.json` и `packaging/portable/windows-amd64-patch123.lock.json`. По Windows lock независимо проверены 37/37 SHA license/notice/nuspec из Microsoft inventory, без расхождений. Это проверка состава, а не самостоятельное юридическое разрешение на распространение.
