> **Актуализация 22.10.2026:** нижеследующий отчёт фиксирует *первоначальный этап переноса исходников*, когда Windows builder отсутствовал и GUI build имел статус `NOT_RUN/BLOCKED`. Позднее подготовлен полный Windows portable с `ASMTool.exe` и выполнены проверки комплектации; исправление `47a73ed` изменило только Go CLI, а GUI и native-файлы сохранились побайтно. Полная Windows native-квалификация после последней коррекции версии **не повторялась**. Итоговые ZIP и SHA см. [RELEASE_ARTIFACT_VERIFICATION.md](RELEASE_ARTIFACT_VERIFICATION.md). Исторические результаты ниже сохранены для точного разграничения стадий.

# Windows GUI integration — ASM Tool 0.12.3

## Scope and result

Adapted the supplied WinUI 3/.NET 10 source for the existing Go 0.12.2 CLI.
The layout and existing settings remain. The obsolete service-detection
control was removed while native Go TCP port selection remains. Browser checks
now follow the Go active-mode default; the opt-out is unchecked by default and
the active screen displays the unqualified status and candidate31 network
security failure.

The status reader now differentiates a not-yet-created file from malformed,
oversized, unreadable, unsupported, or missing-final status. Damaged/missing
final status cannot be treated as success. The existing `ArgumentList`, active
authorization confirmation, force-stop confirmation, and kill-on-close Job
Object remain in use. No Go source or research algorithm was changed by this
GUI work. Failed worker state and message are parsed and displayed; worker
errors suppress determinate progress and prevent exit0 + complete +
incomplete=false from being reported as success. Exit4 with a truthful
incomplete status remains classified as incomplete.

## Changed paths

- `ui/windows/ASMTool.Gui/Models/ScanOptions.cs`
- `ui/windows/ASMTool.Gui/Services/RunStatusReader.cs`
- `ui/windows/ASMTool.Gui/Services/CoreRunner.cs`
- `ui/windows/ASMTool.Gui/MainWindow.xaml`
- `ui/windows/ASMTool.Gui/MainWindow.xaml.cs`
- `ui/windows/ASMTool.Gui/ASMTool.Gui.csproj`
- `ui/windows/tests/ASMTool.Gui.SelfTests/Program.cs`
- `ui/windows/tests/ASMTool.Gui.IntegrationTests/Program.cs`
- `ui/windows/tests/FakeCore/Program.cs`
- `ui/windows/scripts/Make-SourceArchive.ps1`
- `ui/windows/scripts/Publish-GoGuiBundle.ps1`
- `ui/windows/README_0_12_3_GUI.md`
- `ui/windows/GUI_GO_CONTRACT_0_12_3.md`
- `docs/patch123/GUI_GO_COMPATIBILITY_MATRIX.md`
- `docs/patch123/GUI_INTEGRATION_REPORT.md`

The Windows publish script treats the Go `SHA256SUMS` as the input allow-list,
rejects unmanifested files/reparse paths and Nmap/Python runtime filenames,
checks the verified executable reports `0.12.3-go`, copies every verified
manifest path plus the root checksum file, and fails on GUI output collisions.

## Verification status

No C# build, C# test, GUI launch, or Windows native test was run. The local
Linux environment has no .NET SDK/PowerShell and no Windows device was
available to this implementation worker. Those checks are `BLOCKED/NOT_RUN`.
Source edits and test scenarios are prepared; they must not be described as
runtime PASS.

On a Windows x64 machine with the pinned .NET 10 SDK and restored package cache,
from the repository root run:

```powershell
$ErrorActionPreference = 'Stop'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_NOLOGO = '1'
dotnet build .\ui\windows\ASMTool.Gui\ASMTool.Gui.csproj -c Release -r win-x64 -p:Platform=x64 --no-restore
dotnet run --project .\ui\windows\tests\ASMTool.Gui.SelfTests\ASMTool.Gui.SelfTests.csproj -c Release
dotnet build .\ui\windows\tests\FakeCore\FakeCore.csproj -c Release -r win-x64
$env:ASM_GUI_TEST_FAKE_EXE = (Resolve-Path .\ui\windows\tests\FakeCore\bin\Release\net10.0\win-x64\FakeCore.exe).Path
$env:ASM_GUI_TEST_ACCEPTED_GO_EXE = (Resolve-Path .\path\to\verified\asm-tool.exe).Path
dotnet run --project .\ui\windows\tests\ASMTool.Gui.IntegrationTests\ASMTool.Gui.IntegrationTests.csproj -c Release
```

Then publish the GUI only against a freshly verified 0.12.3 Windows Go bundle:

```powershell
.\ui\windows\scripts\Publish-GoGuiBundle.ps1 `
  -GoBundlePath .\dist\ASM_Tool_0.12.3\Windows\ `
  -OutputDirectory .\dist\ASM_Tool_0.12.3\assembled
```

The placeholder accepted-Go path in the test command must be replaced with the
actual verified candidate path. Run the existing `ui/windows/tests/native_windows`
smoke, missing-core, fake-core, layout, accessibility, and crash-containment
scripts on Windows after packaging. These steps are instructions, not completed
checks.

## Known limits

- Browser network isolation remains `NOT_SECURITY_QUALIFIED`; historical
  candidate31 remains `FAIL`. Enabling its existing CLI path does not resolve
  that defect.
- Cooperative cancellation is not implemented. User-confirmed forced process
  termination may leave partial results; the existing Job Object assignment
  startup window remains.
- Windows App SDK/.NET self-contained publish and WinUI runtime compatibility
  were not verified in this Linux environment.
- This report does not establish license or public redistribution readiness;
  those results are maintained in the separate project license reports.
