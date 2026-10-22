> **Актуализация 22.10.2026.** Этот документ зафиксировал исходную *заблокированную* стадию интеграции, когда Windows/.NET-стенд был недоступен. Позднее собран полный Windows ZIP с `ASMTool.exe`, и проверена целостность окончательных архивов. Исторические статусы `GUI BUILD NOT_RUN/BLOCKED` ниже относятся исключительно к предыдущей стадии. Полная повторная Windows native-квалификация после итогового исправления версии **не выполнялась**. Актуальный комплект и хеши — [RELEASE_ARTIFACT_VERIFICATION.md](RELEASE_ARTIFACT_VERIFICATION.md).

# Windows 0.12.3: оставшийся этап сборки и целевых проверок

**NOT_RUN / BLOCKED:** текущий Linux-стенд не имеет Windows, .NET SDK и PowerShell. В build kit нет нового ASMTool.exe GUI; файл asm-tool.exe внутри GoBundle/ — свежий CLI. Старые скомпилированные GUI и runtime из контрольного ZIP не использованы. Ни исторические 43/35/5 тестов, ни прошлый Windows 10 PASS не перенесены на 0.12.3.

Распакуйте kit в короткий пользовательский путь, например `C:\ASM123Build`. Свежий проверяемый Go-комплект уже находится в каталоге `GoBundle/`. Проверьте внешний ZIP SHA-256 по независимому SHA256SUMS. Внутренний SHA256SUMS перечисляет все файлы, кроме себя; доверие к нему требует проверенного внешнего хеша. Для подпапок не используйте junction/symlink.

Нужен существующий доверенный Windows x64 builder: .NET 10 SDK, Windows SDK/WinUI build tools и соответствующий cache NuGet. Это требования к developer build, а не к пользовательскому запуску portable. Не устанавливать их автоматически и не использовать старый GUI EXE вместо сборки. Зафиксируйте `dotnet --info`, SHA SDK, `project.assets.json`, lock/restore log и все exit codes. Проверяйте исходные pins Microsoft.WindowsAppSDK 1.8.250916003 и Windows.SDK.BuildTools 10.0.26100.4654; исторический runtime 10.0.13 не является доказанным новым publish runtime. Любое отличие implicit/transitive graph от подготовленного индекса нужно явно оценить до передачи сборки.

Из корня kit в PowerShell (впишите свой существующий DotNetPath):

```powershell
$DotNetPath = 'C:\TrustedSDK\dotnet.exe'
& $DotNetPath --info
& $DotNetPath build .\ui\windows\ASMTool.Gui\ASMTool.Gui.csproj -c Release -r win-x64 -p:Platform=x64 --no-restore
& $DotNetPath run --project .\ui\windows\tests\ASMTool.Gui.SelfTests\ASMTool.Gui.SelfTests.csproj -c Release --no-restore
& $DotNetPath build .\ui\windows\tests\FakeCore\FakeCore.csproj -c Release -r win-x64 --no-restore
$env:ASM_GUI_TEST_FAKE_EXE = (Resolve-Path .\ui\windows\tests\FakeCore\bin\Release\net10.0\win-x64\FakeCore.exe).Path
& $DotNetPath run --project .\ui\windows\tests\ASMTool.Gui.IntegrationTests\ASMTool.Gui.IntegrationTests.csproj -c Release --no-restore
.\ui\windows\scripts\Publish-GoGuiBundle.ps1 -GoBundlePath .\GoBundle -OutputDirectory .\NewGuiOutput -DotNet $DotNetPath
```

Если restore ещё не выполнен, эти команды ожидаемо не пройдут. Сначала подготовьте cache/restore из одобренных точных версий под контролем владельца, сохраните graph и notices. Publish script вызывает dotnet publish со стандартной restore-семантикой; offline запускать его только с подготовленным cache и отключёнными сетевыми источниками NuGet. В текущем цикле restore не выполнялся. После любого ненулевого exit code остановить последовательность и сохранить журнал, не приписывать последующим шагам PASS.

Проверить Release build без критических предупреждений, generated App.xbf/MainWindow.xbf/ASMTool.pri, actual ASMTool.deps.json, self-contained .NET и WindowsAppSDK composition, отсутствие Nmap/Python и тестовых EXE в финальном publish ZIP. Корневой `GUI_DISTRIBUTION_MANIFEST.sha256` охватывает новый GUI и Go-файлы; `SHA256SUMS` остаётся манифестом исходного Go-комплекта для CorePackageVerifier. Обе области обязательны; это checksums, не подпись издателя.

Целевые offline/native GUI проверки проводить отдельно на Windows 10 и Windows 11: запуск и layout/клавиатура, поиск core и повреждённый SHA, validate-only без network scan, синтетические complete/incomplete/error/повреждённый run_status и worker errors, ArgumentList/авторизация, Unicode-каталог, отказ Go, подтверждение принудительной остановки, Job cleanup. Существующие сценарии находятся в ui/windows/tests; не запускать произвольный набор автоматически. `GoBundle` содержит активные Subfaster/Obscura: их запуск для данных GUI-проверок не нужен, `Subfaster -version` запрещён из-за UDP probe. Полную браузерную/сетевую/performance квалификацию не проводить.

Cooperative cancel API отсутствует; force termination не гарантирует частичные результаты. Сохраняется стартовая гонка назначения Job Object. Прошедший GUI smoke не закрывает candidate31 FAIL, browser NOT_SECURITY_QUALIFIED, strict network gate, CRT rights, Rust closure или публичную готовность.
