# Сборка из исходников

Описанные команды компилируют собственный код ASM Tool. Сторонние инструменты и runtime-файлы в полном portable payload приобретаются, лицензируются и проверяются отдельно.

## Go CLI

Нужен Go, совместимый с `go.mod`.

Linux:
```sh
go version
go build -trimpath -o asm-tool ./cmd/asm-tool
./asm-tool --help
```

Windows:
```powershell
go build -trimpath -o asm-tool.exe ./cmd/asm-tool
.\asm-tool.exe --help
```

Отдельные функции требуют проверенного `payload/`; исходная компиляция не заменяет сборку полного дистрибутива.

## Windows GUI

Нужны Windows x64, .NET 10 SDK и зависимости WinUI 3.

```powershell
dotnet restore .\ui\windows\ASMTool.Gui\ASMTool.Gui.csproj -r win-x64 -p:Platform=x64
dotnet publish .\ui\windows\ASMTool.Gui\ASMTool.Gui.csproj -c Release -r win-x64 -p:Platform=x64 --self-contained true
```

Сборка GUI без проверенного Go payload не является готовым пользовательским установочным комплектом.

## Проверки

```sh
go test -short ./internal/... ./cmd/... ./tools/portablepayload
```

Некоторые тесты могут требовать дополнительных фикстур и подходящей ОС. Перед публикацией готового ZIP обязательны контроль его состава, сохранение сторонних notices, проверка SHA-256 и нативные функциональные испытания. Исходный снимок не зависит от архивов предыдущих версий.
