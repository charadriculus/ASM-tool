# ASM Tool 0.12.3 — независимая проверка лицензионных ограничений, 23.10.2026

## Метод и зафиксированная база

Проверена приватная ветка `main` GitHub (`46ec294a8ce528a671106c4d5bc0820cea8d65ef` на момент чтения), актуальная документация, оба platform packaging locks, API GitHub Draft Release и первичные источники Microsoft, GNU, V8, rusty_v8 и Obscura. Никакие пользовательские бинарники и архивы не заменялись, исходники Go/C# не менялись, программы из portable не запускались. Результаты статического анализа исходников не равнозначны новой квалификации бинарников.

## Новые и подтверждённые наблюдения

1. `main/LICENSE` и `licenses/patch123/PROJECT_LICENSE_METADATA.json` уже содержат подтверждённого правообладателя Зуев Иван Алексеевич (MIT, 2026). Старые указания `AGENTS.md` о неподтверждённом правообладателе исправлены в audit-ветке. **Старый tag v0.12.3 остаётся с placeholder.**
2. Draft release остаётся приватным и неопубликованным. API показал три ZIP, включая Linux 296102932 байта с SHA-256 `695d48df48d8b840f5e8ac240b3a29a025d61b85511b8458fa9de5246d19046a` и Windows 239602994 байта с SHA-256 `6dc9b4e8289453a598982d957e952b930b448ac0e6d95da3a2619151816d710b`; combined 535801302 байта SHA-256 `fdd111db5de8320dce4a0d65b751be8fb8f1d96bea0c53a86eb00e0fe8970dc5`. Эти метаданные GitHub **не заменяют** повторного прочтения байтов ZIP.
3. Windows lock реально включает `payload/bin/vcruntime140.dll` и `payload/bin/vcruntime140_1.dll` и их pinned SHA-256. Microsoft прямо ограничивает право распространять отдельные Visual C++ runtime binaries лицензированными пользователями Visual Studio и соответствующими Microsoft Software License Terms: https://learn.microsoft.com/en-us/cpp/windows/redistributing-visual-cpp-files. REDIST 2026: https://learn.microsoft.com/en-us/visualstudio/releases/2026/redistribution. Проверка, что DLL оригинальные, **не подтверждает** права разработчика на копирование и распространение. Принять лицензию Community/Build Tools от имени владельца в этом исследовании невозможно; не записывать `PASS`.
4. Upstream `obscura` `v0.2.2` release workflow действительно запускает сборку `--features render` и на Linux устанавливает `clang`. Но версия `rusty_v8` `v137.3.0` при `V8_FROM_SOURCE` false **по умолчанию скачивает prebuilt static lib**, то есть настройка Clang в сборке Obscura **не доказывает**, какой Clang/GN использовался для V8. Утверждения `is_clang` в V8 применимы только к компиляции самой V8.
5. Зафиксированный коммит V8 `f68bbb6cda689a14d019a6a60cc93963724e7c35` задаёт `v8_use_libm_trig_functions = is_clang` и содержит `third_party/glibc/README.v8`: `License: LGPL 2.1`, `Shipped: yes`. Это сильный **условный source-build trigger**, но не доказательство включения кода в shipped Obscura. Нужны exact prebuilt `librusty_v8` и, по возможности, build metadata, link map или воспроизведение компоновки.
6. LGPL 2.1 §6 требует применимых notices и одного из законных вариантов предоставления исходных и перелинковочных материалов при соответствующей статической компоновке. Недостаточно автоматически включить `README.v8` и объявить `PASS`. Текст: https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html.
7. Reproducible read-only gate добавлен как `tools/patch123/licensing_gate.py`. Он проверяет точные ZIP hashes и каждый file hash из platform lock, отдельно позволяет показать потенциально значимые архивные members V8, всегда оставляет **legal gates unresolved**, даже при техническом `PASS`. Exit `3` означает `TECHNICAL_INTEGRITY_PASS / LEGAL_BLOCKED`, `2` означает провал технической проверки. Инструмент **не был запущен на трёх реальных GitHub Release ZIP**; автоматический отчёт фактического выполнения не создан.

## Применение в доверенной рабочей копии

```bash
python3 tools/patch123/licensing_gate.py \
  --linux /path/to/ASM_Tool_0.12.3-linux-x86_64.zip \
  --windows /path/to/ASM_Tool_0.12.3-windows-x64.zip \
  --out /path/to/evidence/license_gate_0123.json
```

Опционально `--v8-static /path/to/exact/librusty_v8_release_x86_64_unknown_linux_gnu.a.gz`. **Не подменять** точный upstream build любым локальным архивом. Имя объекта в `ar t` является эвристикой, не доказательством точного статического включения. В частности, отсутствие строковых имён не является отрицательным выводом по лицензии.

## Статус и блокирующие свидетельства

| Gate | Статус |
| --- | --- |
| Собственный MIT copyright | CLOSED в main; stale в old tag |
| Источник двух CRT и подписанный Microsoft runtime | PASS в пределах сохранённых предыдущих проверок |
| Лицензия распространителя на CRT | **NOT ESTABLISHED** |
| V8 glibc LGPL source trigger | CONFIRMED CONDITIONAL |
| Exact V8 prebuilt/archive build flags | **NOT ESTABLISHED** |
| LGPL static linkage / §6 relink sufficiency | **NOT ESTABLISHED** |
| Released ZIP byte-level reinspection in current audit | NOT RUN |
| Windows native GUI и браузерная security qualification | NOT RUN / NOT QUALIFIED |
| Полная бинарная notice closure | NOT ESTABLISHED |
| **PUBLIC_REDISTRIBUTION_READY** | **FALSE** |

Отдельно: в исходных packaging locks существуют абсолютные исторические пути к рабочим файлам. Сам по себе push документации в GitHub не даёт возможность воспроизвести сборку ZIP; перед выпуском source/rebuild strategy должна отделить upstream pinned inputs от локальной машинной среды.

## Обязательные условия готовности нового release candidate

Подтвердить лицензионное право на CRT **или** создать новый Windows вариант без app-local CRT и проверить prerequisites на чистой машине. Зафиксировать actual prebuilt V8 и включённые в бинарники LGPL-объекты; при наличии статической LGPL-компоновки предоставить юридически корректный и **проверенный** replacement/relink route либо пересобрать V8 и Obscura без данного glibc subset с полноценной повторной функциональной проверкой. Затем пересобрать релиз с корректным MIT holder в новом tag, прочитать и проверить новые ZIP, пройти Windows и Linux native tests, проверить notices и сохранить хеши. Старый приватный Draft Release и tag не изменять до получения доказательств.

**Это audit/evidence улучшение, а не устранение CRT/V8 правовых препятствий. Не публиковать текущие 0.12.3 архивы на основании этого PR.**
