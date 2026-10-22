# ASM Tool 0.12.3 — готовая GUI-сборка, 22 октября 2026

Получен готовый unpackaged/self-contained WinUI 3 GUI для Windows x64. По переданному GUI_BUILD_REPORT.json он собран .NET SDK 10.0.402 на Windows 10 build 19045; статус BUILD_PASS. Пересборка, изменение GUI/Go и повторение прежних регрессий не выполняются. Проверки этого этапа ограничены новыми входными файлами и компоновкой архивов.

Предыдущий BLOCKED_NO_WINDOWS_BUILDER относится к подготовке 21 октября и больше не описывает доступность GUI-бинарников. **Запуск GUI, C# unit/integration, GUI automation, Windows10/Windows11 runtime и Job/cleanup проверки здесь NOT_RUN.** Успешная сборка не приравнивается к этим проверкам. Переданный Windows build report не содержит отдельного числового exit code, поэтому он не придумывается.

В Windows-комплекте ASMTool.exe запускает GUI, asm-tool.exe — CLI. Оба находятся в одном каталоге с неизменённым payload/. GUI runtime и ресурсы сохраняются из переданного архива. Никаких старых compiled GUI0.12.0 или недокументированных замен компонентов нет. Для запуска предусмотрен bundled .NET runtime 10.0.13; установка .NET SDK, Go, Python, Node или WSL пользователю не требуется по структуре комплекта. Это статически проверенная комплектация, не подтверждённый запуск на чистой Windows.

SHA256SUMS охватывает все файлы Windows-комплекта кроме себя. GUI_BUILD_FILES.sha256 фиксирует исходные файлы GUI build. GUI_DISTRIBUTION_MANIFEST.sha256 охватывает весь комплект кроме себя и SHA256SUMS; эти два исключения исключают циклическую зависимость, а окончательный SHA256SUMS включает GUI_DISTRIBUTION_MANIFEST.sha256. Внутренние payload/bundle.json, payload-provenance.json, Go CLI и embedded anchor остаются неизменными: GUI размещается рядом с CLI, а не внутри его payload allowlist.

Полученный .deps.json и runtimeconfig фиксируются в GUI_RUNTIME_PROVENANCE.json. Лицензионные материалы предыдущего этапа сохранены; версии пакетов нового GUI сопоставлены с существующим корпусом, без скачиваний или нового лицензионного исследования. Первоначальные corpus indexes и review matrix являются датированными source/notice evidence. Новый фактический GUI inventory дополняет их и не объявляется доказательством всех redistribution rights.

Проверка source_sha256 из Windows report ограничена его сохранением: исходный transfer archive с таким digest не предоставлен в handoff. Это не выдаётся за независимо проверенное соответствие бинарника исходникам и не блокирует использование переданной владельцем сборки для компоновки. Оригинальный publish log и report сохраняются побайтно.

DEVELOPMENT/OWNER TRIAL: пакет подготовлен, runtime qualification ожидает владельца. PUBLIC_REDISTRIBUTION_READY: NOT_CONFIRMED; прежние вопросы MIT holder, CRT entitlement, Rust/V8 closure и authenticity Linux worker не закрываются компоновкой. Не выполнялись release, push, merge, freeze или deployment.

Исторические candidate31 FAIL и Linux network FAIL сохранены. Browser доступен как NOT_SECURITY_QUALIFIED owner-trial функциональность; возможные вне-scope контакты, Subfaster UDP startup behaviour, robots.txt и redirects ограничения не исправлялись. Windows strict network и Windows11 qualification остаются NOT_RUN. Использовать только разрешённые цели; этот этап не проводит сетевых исследований.
