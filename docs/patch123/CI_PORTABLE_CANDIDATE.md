# ASM Tool 0.12.3: приватная сборка в GitHub Actions

Workflow: `.github/workflows/asm-0123-portable.yml`. Изменения подготавливаются в отдельной ветке и не изменяют приватный Draft Release, его SHA или старый тег.

## Архитектура

1. В чистом Linux runner используется Go 1.26.6. GitHub Actions получает из **приватного Draft Release** ровно два ранее принятых platform ZIP; каждый обязан побайтно соответствовать закреплённым SHA-256 и размеру. Доступ к черновику ограничивается отдельным job с `contents: write`, поскольку для просмотра Draft Release требуется push-доступ; остальные jobs имеют только `contents: read`. Рабочие scripts не содержат GitHub write/publish операций.
2. `tools/ci/portable_candidate.py prepare-lock` проверяет закрытый `SHA256SUMS` прежнего релиза и совпадение всех `payload` файлов с платформенным `lock`. По каждому файлу сохраняется исходный hash, кроме одного: `payload/licenses/asm-tool/LICENSE` заменяется на актуальный корневой MIT LICENSE. Сгенерированные CI locks содержат относительные пути и не зависят от исходных `/home/charadriculus/...` путей.
3. `portablepayload stage` создаёт новый `payload/bundle.json` и `payload-provenance.json`. Go CLI обеих платформ компилируется из исходников checkout с новым embedded `BundleManifestSHA256`, затем проходит `portablepayload verify`. Runtime Linux payload остаётся исторически pinned: glibc, Typst, Obscura, Subfaster, DLL, шрифты и другие сторонние объекты **не перекомпилируются в данном CI**.
4. Go stager tests на Linux используют DejaVu fonts, извлечённые из SHA-проверенного старого Linux архива, без использования неидентичных системных шрифтов на GitHub runner.
5. Windows runner получает пересобранный `asm-tool.exe` и новый `payload`; .NET 10 и WinUI3 GUI публикуется заново из C# исходников. Имеющийся `ui/windows/scripts/Publish-GoGuiBundle.ps1` проверяет Go SHA256SUMS и native `--version` без сетевых сканирований.
6. Новый Windows GUI zip проверяется независимо двумя allowlists: внутренний Go-only `SHA256SUMS` и полный `GUI_DISTRIBUTION_MANIFEST.sha256`. Сравнивается новый `payload/licenses/asm-tool/LICENSE` с `main/LICENSE` целевой ветки.
7. Комбинированный ZIP включает оба platform ZIP и их SHA-256. Это **новая композиция**, вложенные архивы под `linux-x86_64/` и `windows-x64/`; она отличается от исторической схемы 0.12.3 и требует новой проверки потребительских инструкций.

## Условия и ограничения

- Обязателен доступ Actions к приватным Draft Release assets. Отказ API означает техническую блокировку, не разрешение заменить бинарники случайными скачиваниями.
- Исполнители: `ubuntu-24.04`, `windows-2025`, настройка .NET 10.
- Workflow по умолчанию не публикует релизы, не заменяет существующие asset hashes, не меняет теги, не использует RDC/Codex, не запускает сканирование внешних целей. Создаёт лишь приватные Actions artifacts со сроком хранения 3 дня.
- Успешные результаты build/integrity **не доказывают** повторную полную GUI usability/security qualification, отсутствие лицензионных ограничений или эквивалентность old ZIP побайтно.
- Неподписанный Actions ZIP не подменяет официальную дистрибуцию; перед публикацией необходимо независимо проверить полный архив, документацию и конечные контрольные суммы.
- **Примечание к лицензиям:** аудит наличия исходного GitHub-корпуса показал 323/323; этот workflow решает только физическую упаковку и identity pin, не переоткрывает юридическое толкование.

## Результаты прогонов

Смотреть вкладку Actions репозитория, workflow `ASM Tool 0.12.3 private candidate`. Для каждого run проверять фактическое завершение всех трёх jobs и скачивать attached CI artifacts. Не переносить статус одного шага на всю сборку.
