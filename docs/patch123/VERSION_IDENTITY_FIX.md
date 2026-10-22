# ASM Tool 0.12.3 — исправление идентификатора версии

22 октября 2026. Версия приложения остаётся `0.12.3-go`.

Причина: passive completeness producer записывал `0.12.0-go`, тогда как приложение передавало отчёту `0.12.3-go`. Строгая проверка отклоняла свежий артефакт с `passive completeness artifact identity mismatch`.

Теперь `internal/version/version.go` — единый источник runtime identity. Его используют CLI/help, конфигурационный User-Agent, passive completeness и HTTP User-Agent по умолчанию. Run summary и вход отчётности получают идентификатор через существующий `app.Version`. Второй найденный устаревший идентификатор HTTP fallback исправлен; пользовательский User-Agent сохраняется. Версии native-компонентов и исторические fixtures не менялись.

Проверка версии, домена и схемы в генераторе отчётов не изменена. Старые результаты сканирований не исправлялись и не перезаписывались; архивы предыдущих кандидатов сохранены. Это исправление действует на новые запуски. Обработка старых артефактов с несовпадающей версией по-прежнему завершается строгой ошибкой.

Регрессия выполняет настоящий passive producer с in-memory HTTP fixture и читает его артефакт через report.Load/SQLite. До исправления воспроизведён исходный FAIL (exit1); после исправления PASS (exit0), включая отказ при подмене версии/домена/схемы. Отдельно проверены фактически передаваемый HTTP User-Agent на loopback fixture, его явное переопределение, CLI identity, source defaults и связанные проверки completeness. Полные повторные tests/race/native qualification не выполнялись.

Пересобраны только Go CLI Linux amd64 и Windows amd64, offline. Готовый Windows GUI, native payload, DLL, шрифты и лицензии сохранены побайтно; GUI не требовал пересборки или новой передачи через Samba. Обновлены BUILD_INFO и закрытые SHA-256 inventories, включая Windows GUI distribution manifest. Точная исходная фиксация и application hashes находятся в BUILD_INFO.json; команды и exit codes — planning/patch123/evidence/version-fix-*.

Windows runtime/GUI startup и Windows11 остаются NOT_RUN. Browser NOT_SECURITY_QUALIFIED, candidate31 FAIL, исторический Linux network FAIL, Windows strict network NOT_RUN, Subfaster startup UDP и прежние robots.txt/redirect ограничения сохраняются. Эта коррекция не является полной квалификацией безопасности или публикацией release. Внешние цели и native backend при подготовке не запускались.
