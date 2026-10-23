# ASM Tool 0.12.3 — проверка наличия лицензионных файлов в GitHub

**Дата:** 2026-10-23  
**Scope:** проверка путей реестров и соответствующих файлов в приватном `main` (`46ec294a8ce528a671106c4d5bc0820cea8d65ef`); проверка наличия записей в обоих `packaging/portable/*-patch123.lock.json`. Не является новым пересмотром лицензионных прав.

## Результат по GitHub

| Корпус | Записей | Файлов присутствует в main | Отсутствует |
| --- | ---: | ---: | ---: |
| `licenses/patch123/go-runtime/CORPUS.SHA256SUMS` | 185 | 185 | 0 |
| `licenses/patch123/microsoft/PACKAGE_INVENTORY.json` | 37 | 37 | 0 |
| `licenses/patch123/rust/licenses-index.json` | 101 | 101 | 0 |
| **Итого (уникальные пути)** | **323** | **323** | **0** |

В `licenses/` на момент проверки 329 файлов: 323 файла корпусов плюс 6 файлов метаданных/индексов (`PROJECT_LICENSE_METADATA.json`, `CORPUS.SHA256SUMS`, `CONTROL_FILE_PROVENANCE.json`, `GO_PAYLOAD_CRT_PROVENANCE.json`, `PACKAGE_INVENTORY.json`, `licenses-index.json`).

Оба реестра `packaging/portable/*-patch123.lock.json` содержат ожидаемые лицензионные file entries: Linux — 313, Windows — 327. Из них на GitHub-относительные входные исходники ссылаются Linux — 286, Windows — 148; **для всех этих ссылок файлы в `main` найдены (0 отсутствующих)**. Остальные записи берут исходные байты из документированных локальных inputs/архивов (Linux — 27, Windows — 179), а не из `main`. Это не отсутствие соответствующих лицензий в готовом ZIP: payload path и source origin различаются.

Windows lock включает все 37 файлов из реестра Microsoft с совпадающими ожидаемыми SHA-256. Rust-реестр включает 101 record, из которых 99 прямо сопоставляются с путями в обоих locks; отдельные корневые Typst LICENSE/NOTICE записаны в ZIP по иным путям. Из 185 элементов Go/GNU corpus не все должны поставляться под исходными путями `licenses/patch123/go-runtime/`: lock компонует лицензии под другими `payload/licenses/*` именами либо сохраняет исходные файлы в source corpus.

**Граница проверки:** факт существования 323 GitHub-путей подтверждён деревом GitHub; эта проверка не повторно скачивала и хешировала все 323 содержимого и не скачивала приватные бинарные Release Assets. Ранее зафиксированы проверки release SHA/CRC, 37/37 Microsoft notices и corpus SHA-256; их scope не расширяется.

## Дефект в релизном MIT LICENSE: требуется перепаковка

Корневой `main/LICENSE` содержит `Copyright (c) 2026 Зуев Иван Алексеевич`.

Аннотированный `v0.12.3` tag содержит прежнее `Copyright (c) 2026 [COPYRIGHT HOLDER — TO BE CONFIRMED]`. SHA-256 этой исторической редакции: `697adf4a5f42ca1332cb122a4b964080acf316d56f2996ce4d0fba63b0f0dd75`; точно такая сумма прописана для `payload/licenses/asm-tool/LICENSE` в Linux и Windows locks. Новая редакция `main/LICENSE` имеет SHA-256 `a5bf620fdf5bcdc1f6cb74f98b363c74a5a7e2d498b20fd0a5d94add7758329d`.

Таким образом, **в старых собранных ZIP лежит неверная редакция (не отсутствующий файл)** по зафиксированному payload lock. Исправление должно затронуть staged LICENSE и архивы; SHA-256 файлов и архивов пересчитываются, версия релизного тега приводится в соответствие новой сборке. Нельзя менять только `main` или только текст реестра без реального ZIP. Текущий приватный Draft Release и его бинарники на этом аудите не изменялись.

## Вывод по вопросу комплектности

**SOURCE_LICENSE_FILES_PRESENT = PASS (323/323 в main).**  
**RELATIVE_BUILD_INPUTS_PRESENT = PASS (0 отсутствующих относительных входных файлов в обоих locks).**  
**PUBLISHED_BINARY_LICENSE_CONTENT_CURRENT = FAIL (устаревшая редакция MIT LICENSE в старом релизном кандидате).**  
**ZIP_BYTE_REAUDIT_IN_THIS_PASS = NOT_RUN.**

Это заключение именно о присутствии файлов. Оно не переоткрывает уже принятые владельцем решения по сторонним лицензиям и не служит отдельным юридическим заключением.
