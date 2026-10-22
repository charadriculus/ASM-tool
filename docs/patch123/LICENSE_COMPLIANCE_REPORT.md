> **Актуализация 22.10.2026:** после первоначальной source-only проверки собран новый Windows portable с GUI и подтверждена целостность финальных архивов. Это снимает историческое утверждение, что GUI *вообще не собран*, но **не** устанавливает полный фактический DLL/SBOM closure, права распространения Microsoft CRT или лицензионную готовность. `PUBLIC_REDISTRIBUTION_READY = NOT_CONFIRMED` остаётся в силе. Исходные аудиторские выводы ниже относятся к зафиксированной проверке исходников.

# Лицензионная подготовка ASM Tool 0.12.3

## Вывод

Подготовлены и проверены исходные license/notice материалы в пределах указанных source/package inputs. Это не юридическое заключение и не подтверждение полного состава исполняемых файлов. Состояние публичного распространения — **NOT CONFIRMED**. Подготовка для закрытой разработки не равна разрешению на публичный релиз.

## Собственный код ASM Tool

Владелец проекта выбрал MIT для исходного кода ASM Tool, GUI, Linux TUI и собственных скриптов. `LICENSE` намеренно сохраняет `UNCONFIRMED` вместо выдуманного copyright holder. Запись `licenses/patch123/PROJECT_LICENSE_METADATA.json` указывает `public_redistribution_ready: false`. Правообладателя должен подтвердить владелец до завершения metadata.

## Компоненты и статус

| Область | Подтверждено | Открытое ограничение |
|---|---|---|
| Go dependencies / Subfaster | Лицензии и 185-файловый notice corpus имеют локальные hash records; предшествующая проверка corpus завершилась exit 0 | Это не доказывает полную dependency closure конкретных бинарников; см. [GO_DEPENDENCY_LICENSES.md](GO_DEPENDENCY_LICENSES.md) |
| Linux glibc / libgcc runtime | Четыре runtime-файла сопоставлены с пакетами; соответствующие source archives, copyright maps и license texts включены | Подписи `.dsc` и upstream glibc signature не проверены; replacement workflow не испытан; для бинарника V8 остаётся отдельный неизвестный LGPL-вопрос. См. [LINUX_RUNTIME_LICENSES.md](LINUX_RUNTIME_LICENSES.md) |
| Obscura / Typst / Rust closure | Источники и некоторые exact-version notices сохранены | Cargo locks не равны бинарному BOM; features и фактический состав prebuilt V8 неизвестны. Linux Obscura worker имеет `AUTHENTICITY_NOT_VERIFIED`. См. [RUST_DEPENDENCY_LICENSES.md](RUST_DEPENDENCY_LICENSES.md) |
| Windows GUI dependencies | Оригинальные license/notice файлы и NuGet hashes сохранены | Новый GUI publish closure отсутствует (`NOT_RUN`); Microsoft terms могут применяться независимо от MIT проекта |
| Microsoft CRT | Идентичность двух существующих x64 CRT DLL сопоставлена с историческим ZIP | Право конкретного распространителя на redistribution не подтверждено: `LICENSING_NOT_CLEARED`. Текст лицензии сам по себе entitlement не устанавливает. См. [MICROSOFT_COMPONENTS_PROVENANCE.md](MICROSOFT_COMPONENTS_PROVENANCE.md) |

## Границы review

Отдельный source-only review license corpus получил `APPROVE_SOURCE_ONLY`: замечаний к согласованности проверенных файлов и формулировок статусов не найдено. Он подтвердил внутреннюю целостность части hash inventories; он не проверял законность, publisher signatures, полный бинарный BOM, новый Windows GUI build или публичные права распространения.

До любого публичного распространения остаются как минимум: подтвердить правообладателя ASM Tool; зафиксировать точную Linux/Windows binary closure и соответствующие notices; разрешить CRT redistribution; оценить неизвестные V8/Obscura LGPL и прочие feature-specific obligations по фактическому build; проверить итоговые payload/manifests. Эти пункты нельзя объявлять закрытыми на основании source ZIP или исторических бинарников.
