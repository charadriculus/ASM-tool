# ASM Tool 0.12.3 — результат GitHub Actions, 23.10.2026

**Фактический run:** https://github.com/charadriculus/ASM-tool/actions/runs/39947720952  
**Head SHA:** `122427fe1fe5162cde33bae9b5f0025fec0a6ca4`  
**Workflow:** `.github/workflows/asm-0123-portable.yml`  
**Status:** SUCCESS, все три jobs завершены (Linux/Go, Windows native WinUI3, combined archive).  
**UTC завершения:** 2026-10-23T11:47:41Z.  
**Дистрибуция:** приватные GitHub Actions artifacts, **НЕ** опубликованы в Release.

## Проверенные архивы (SHA-256 самого релизного ZIP, не transport-обёртки Actions)

| Имя | SHA-256 | Файлов в ZIP |
| --- | --- | ---: |
| `ASM_Tool_0.12.3-linux-x86_64.zip` | `02c55d75f0fb3351d31025494124f9dd4d7a70604935e83e50f222183c33c121` | 330 |
| `ASM_Tool_0.12.3-windows-x64.zip` | `43af311f5d6dd67f60e7befbff26db003472130b8a83991eacc3e94bb14e06b2` | 853 |
| `ASM_Tool_0.12.3-Linux-Windows.zip` | `8903dbb9e7f42107fb31082f5ac127f6dd2545a566606c71f0f5ed6b204a96ac` | 1186 |

`sha256sum -c` для трёх файлов — OK; Linux full SHA256SUMS — PASS; Windows Go SHA256SUMS (341 файлов), GUI distribution manifest (853 файла, включая сам manifest) — PASS. Windows `dotnet publish` (.NET 10/WinUI3) и нативный `asm-tool.exe --version` в рамках publish script — PASS. Go приложения Linux/Windows собраны из source checkout с обновлённым embedded bundle manifest anchor. SHA обновлённого `payload/licenses/asm-tool/LICENSE` в обеих платформах: `a5bf620fdf5bcdc1f6cb74f98b363c74a5a7e2d498b20fd0a5d94add7758329d`; старый placeholder исключён из этого payload path. Third-party payload сохранён от pinned historical input ZIP, с проверкой всех байтов по старым SHA256SUMS/lock.

## Место получения

Artifacts данного run:
- `asm-0123-linux-candidate`, ID `12498608507`
- `asm-0123-windows-candidate`, ID `12499725269`
- `asm-0123-combined-candidate`, ID `12498684398`
- `asm-0123-go-evidence`, ID `12498987189`
- `asm-0123-go-windows-stage`, ID `12499141652`

Срок истечения — 2026-10-26 около 11:42–11:47 UTC. Контрольная сумма transport-обёртки GitHub Actions artifact **отличается** от SHA ZIP, указанного выше. Оригинальный Draft Release и tag `v0.12.3` не затронуты.

## Отличие состава от прежних архивов

Исторический инвентарный отчёт: Linux **357**, Windows **880** файлов. Новый ZIP: Linux **330**, Windows **853** файлов, то есть **на 27 файлов меньше на каждой платформе**. Исторические дополнительные записи вне зафиксированного platform payload не воспроизведены в новой CI composition. Это потенциально root-level документация и notices: **точные пути пропущенных 27 файлов должны быть сопоставлены с прежними ZIP** до признания финальной пользовательской комплектации полной. Закрытая проверка того, что **в новом** архиве нет неучтённых файлов, не доказывает сохранение всех исторических документов. Все 325 Linux / 337 Windows original payload-lock entries перенесены, кроме закономерной замены собственного MIT LICENSE, но root extras требуют отдельного инвентарного контроля.

## Граница квалификации

- **PASS:** три jobs, компиляция Go/Linux/Windows и WinUI3 GUI, upstream SHA, payload locks, новый MIT, ZIP closure, native Windows CLI `--version` и архивные SHA.
- **NOT RUN:** полная функциональная GUI qualification, полные native Windows 10/11 user scenarios, browsers/Obscura security qualification, сравнение всех non-payload legacy extras.
- **NOT PUBLISHED:** новый GitHub Release/tag не создавался, main не модифицировался.
- **НЕ ЗАКРЫТО ЭТИМ ОТЧЁТОМ:** юридический пересмотр лицензий; ранее подтверждённый исходный реестр 323/323 в main сохраняется отдельно.

**Вывод:** техническая CI-сборка PASS, но автоматическая публикация не допускается без диффа старого/нового ZIP и полной квалификации пользовательской дистрибуции.
