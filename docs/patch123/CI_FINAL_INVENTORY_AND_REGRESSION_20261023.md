# ASM Tool 0.12.3 — финальный отчёт по комплектности и CI-сборке (23.10.2026)

## Результат: упаковка восстановлена, функциональная квалификация ещё не закрыта

**SUCCESS** — GitHub Actions run [39965001949](https://github.com/charadriculus/ASM-tool/actions/runs/39965001949), SHA исходного checkout `c2c775a07b1ce2fa168ca93b4766fa1d885248bb`. Все три build/archive jobs PASS.

**FAIL** — отдельный расширенный прогон Go-регрессии [39965790744](https://github.com/charadriculus/ASM-tool/actions/runs/39965790744): Linux и Windows содержат тесты, не проходящие на GitHub-hosted runners. Это **не** нарушает SHA-256 упаковки и **не** означает, что все функции runtime были квалифицированы.

| Комплект | SHA-256 ZIP | Файлов | Историческое число | Итог |
| --- | --- | ---: | ---: | --- |
| `ASM_Tool_0.12.3-linux-x86_64.zip` | `ab86f19ce73b7997a4332e46ed2991cf4a66219d6c879caaf98542ac48aed2c9` | 357 | 357 | BUILD / HASH PASS |
| `ASM_Tool_0.12.3-windows-x64.zip` | `2e7ca7f96d1dd324c44a01d59c80e68470a7dda63f1e46eaab46c478b3983368` | 880 | 880 | BUILD / HASH PASS |
| `ASM_Tool_0.12.3-Linux-Windows.zip` | `8356a77e46d0bc0a560a04210162a0bf22a835c825fdcf8dfd86b0ff24ccf933` | 1241 | 1241 | BUILD / HASH PASS |

Тройная проверка `sha256sum -c` — OK, закрытый manifest Linux — PASS, Windows Go `SHA256SUMS` и полный GUI `GUI_DISTRIBUTION_MANIFEST.sha256` — PASS, Windows native `dotnet publish` — PASS. Срок существования CI artifacts данного run — 26 октября 2026 около 13:56–14:01 UTC.

## 27 потерянных ранее файлов: CLOSED

Два исходных platform ZIP проверены по закреплённым SHA-256:
- Linux старый `695d48df48d8b840f5e8ac240b3a29a025d61b85511b8458fa9de5246d19046a`.
- Windows старый `6dc9b4e8289453a598982d957e952b930b448ac0e6d95da3a2619151816d710b`.

**27 дополнительных root paths идентичны** в двух исходных архивных комплектах. Включают:
- 15 документов `docs/patch123/*`;
- `BUILD_INFO.json`, `LICENSE`, `LICENSE_PAYLOAD_MAPPING.json`, `README_RU.md`, `config.example.yml`, `GUI_INTEGRATION_REPORT.md`, `GUI_RUNTIME_PROVENANCE.json`, `VERSION_IDENTITY_FIX.md`;
- четыре `evidence/gui-build/*`.

`tools/ci/legacy_extras.py` извлекает **ровно 27** файлов с проверкой исходных bytes/sha256 и строгим allowlist. Существующие репозиторные документы берутся из текущей ветки; собственный `LICENSE` и `BUILD_INFO` обновляются; исторические свидетельства GUI и отсутствующий в репозитории `LICENSE_PAYLOAD_MAPPING.json` сохраняются байт-в-байт из старого авторизованного ZIP. Содержание прежних `GUI_RUNTIME_PROVENANCE.json` и `evidence/gui-build/*` нужно трактовать **как историческое**, относящееся к предыдущей сборке, а не как доказательство квалификации нового CI GUI.

Исходный комбинированный ZIP проверен отдельно по SHA-256 `fdd111db5de8320dce4a0d65b751be8fb8f1d96bea0c53a86eb00e0fe8970dc5` в run [39964763072](https://github.com/charadriculus/ASM-tool/actions/runs/39964763072). Его четыре корневых файла: `BUILD_INFO.json`, `README_RU.md`, `VERSION_IDENTITY_FIX.md`, `SHA256SUMS`. Эти четыре файла восстановлены; в комбинированном ZIP нет дополнительного корневого `LICENSE`, но корректный MIT LICENSE присутствует в обоих платформенных каталогах и в `payload/licenses/asm-tool/LICENSE`.

## Лицензии

Реестры исходных лицензий в `main` проверены: **185 Go/GNU + 37 Microsoft + 101 Rust = 323/323 присутствующих файлов**. Новый `LICENSE` имеет SHA-256 `a5bf620fdf5bcdc1f6cb74f98b363c74a5a7e2d498b20fd0a5d94add7758329d`, в т. ч. внутри обоих платформенных payload. Старый placeholder правообладателя в этих путях устранён. Текущий отчёт **не переоткрывает** прежние юридические решения по CRT/V8, он проверяет физическую комплектность.

## Расширенная регрессия — блокирующие отклонения

В workflow `.github/workflows/asm-0123-regression.yml` запущен `go test -short -count=1 ./internal/... ./cmd/... ./tools/...` на Linux и Windows, исключая из обхода папку vendor/licenses за пределами основного Go-модуля. Сами Go-тесты не отключались.

Linux: большинство пакетов PASS. FAIL:
1. `internal/config/TestFixturesSourceIdentity` — в исходном репозитории отсутствует `reference/windows-0.11.3-development/asm_tool/*`.
2. `internal/report/TestPatch121ReplaysConfirmedHumanWarningCounterexample` — отсутствует `planning/progress/g28-evidence/oracle-02/shared-report-input.json`.
3. `internal/pipeline/TestPipelineStreamsEligibleWebBeforeOtherDNSWorkersFinish` — не соблюдено ожидаемое временное перекрытие DNS/web при конкурентном тестировании (функциональный дефект или flaky timing требуют отдельного изучения).

Windows: `TEMP` и `TMP` перенесены на `C:\\asmtool-ci-tmp`, после чего массовые `output parent contains symlinks` исчезли. Но остаются:
1. те же отсутствующие исторические фикстуры `internal/config`, `internal/report`;
2. `internal/browser/TestVerifiedLaunchPlanUsesTypedServeArguments`, `internal/portable/TestVerifyRequestedObscuraRequiresBothPinnedExecutables`, `internal/portable/TestVerifyRequestedObscuraRejectsMissingOrWrongVersion`: синтетическая Windows Obscura fixture не содержит `bin/vcruntime140.dll`;
3. `internal/config/TestOperationalLegacyConfiguration`: `artifact paths lost` — требует предметной проверки Windows-правил путей.

**Важное разграничение:** эти тесты доказывают наличие реальных gaps в новой квалификации. Нельзя записывать общий `ALL_TESTS_PASS`. Сведения о том, что отдельные тестовые fixture-файлы отсутствуют, не означают отсутствие лицензий в уже собранных ZIP.

## Оставшиеся действия до окончательной публикации

1. Найти исходные эталонные тестовые фикстуры (точные bytes и hashes) и восстановить в проверяемой source/test сборке, **не изобретая замен**.
2. Повторить тест временного перекрытия DNS/web, разобрать Windows path и CRT fixture тесты без ослабления проверок.
3. Выполнить нативные функциональные испытания Windows 10/11 GUI и Linux CLI сверх `--version`, отдельно browser/screenshot workflows по назначению. CI headless build GUI не равнозначен полноценному пользовательскому runtime PASS.
4. Сопоставить исторические отчёты GUI в ZIP с текущими собранными бинарниками и добавить явную новую квалификацию/свидетельства.
5. Только после этих пунктов переводить PR в `main`, обновлять tag и Draft Release assets.

**Инварианты:** серверы и локальные компьютеры пользователя не использованы; RDC и Codex не использованы; `main`, исходный tag `v0.12.3` и исходный Draft Release сохранены без изменений.
