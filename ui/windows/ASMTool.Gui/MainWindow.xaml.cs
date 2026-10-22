using ASMTool.Gui.Models;
using ASMTool.Gui.Services;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.Storage.Pickers;
using WinRT.Interop;

namespace ASMTool.Gui;

public sealed partial class MainWindow : Window
{
    private readonly GuiSettingsStore _settings = new();
    private readonly CoreRunner _runner = new();
    private bool _busy, _compactLayout, _closeDialogActive, _closeAfterStop, _wasForceTerminated;
    private string? _lastResults;

    private readonly FrameworkElement[] _optionsRight;
    private readonly int[] _optionWideRows;

    public MainWindow()
    {
        InitializeComponent();
        Title = "ASM Tool 0.12.3";
        AppWindow.Resize(new Windows.Graphics.SizeInt32(980, 640));
        AppWindow.Closing += OnWindowClosing;

        _optionsRight = new FrameworkElement[]
        {
            SourcesInput.Parent as FrameworkElement ?? SourcesInput, FullReportInput,
            WildcardInput, DisableBrowserInput
        };
        _optionWideRows = new[] { 0, 1, 2, 3 };
        for (var i = SettingsGrid.RowDefinitions.Count; i < 10; i++)
            SettingsGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        ProfileInput.SelectedIndex = 0;
        SourcesInput.SelectedIndex = 0;
        ReportLanguageInput.SelectedIndex = 1;
        ResultsRootInput.Text = _settings.LoadResultsRoot();
        UpdateProfileFields();
    }

    private void OnRootSizeChanged(object sender, SizeChangedEventArgs args)
    {
        if (InputGrid is null || ResultsColumn is null || SettingsGrid is null)
            return;
        var compact = args.NewSize.Width < 760;
        if (compact == _compactLayout) return;
        _compactLayout = compact;
        if (compact)
        {
            ResultsColumn.MinWidth = 0;
            ResultsColumn.Width = new GridLength(0);
            Grid.SetColumn(ResultsPanel, 0);
            Grid.SetColumnSpan(ResultsPanel, 2);
            Grid.SetRow(ResultsPanel, 1);
            InputGrid.RowSpacing = 10;

            SettingsGrid.ColumnDefinitions[1].Width = new GridLength(0);
            var controls = new FrameworkElement[]
            {
                DnsBudgetInput.Parent as FrameworkElement ?? DnsBudgetInput,
                SourcesInput.Parent as FrameworkElement ?? SourcesInput,
                ReportLanguageInput.Parent as FrameworkElement ?? ReportLanguageInput,
                FullReportInput, PrimaryDomainOnlyInput, WildcardInput,
                AllowHttpFallbackInput, DisableBrowserInput,
                PortsPanel, BrowserRiskNotice
            };
            for (var i = 0; i < controls.Length; i++)
            {
                Grid.SetColumn(controls[i], 0);
                Grid.SetRow(controls[i], i);
            }
            ExecutionGrid.ColumnDefinitions[1].Width = new GridLength(0);
            Grid.SetColumn(ActionsPanel, 0);
            Grid.SetRow(ActionsPanel, 4);
            Grid.SetRowSpan(ActionsPanel, 1);
            ActionsPanel.Orientation = Orientation.Horizontal;
        }
        else
        {
            ResultsColumn.Width = new GridLength(2, GridUnitType.Star);
            ResultsColumn.MinWidth = 220;
            Grid.SetColumnSpan(ResultsPanel, 1);
            Grid.SetColumn(ResultsPanel, 2);
            Grid.SetRow(ResultsPanel, 0);
            InputGrid.RowSpacing = 0;

            SettingsGrid.ColumnDefinitions[1].Width = new GridLength(1, GridUnitType.Star);
            var left = new FrameworkElement[]
            {
                DnsBudgetInput.Parent as FrameworkElement ?? DnsBudgetInput,
                ReportLanguageInput.Parent as FrameworkElement ?? ReportLanguageInput,
                PrimaryDomainOnlyInput, AllowHttpFallbackInput
            };
            for (var i = 0; i < left.Length; i++)
            {
                Grid.SetColumn(left[i], 0);
                Grid.SetRow(left[i], i);
                Grid.SetColumn(_optionsRight[i], 1);
                Grid.SetRow(_optionsRight[i], _optionWideRows[i]);
            }
            ExecutionGrid.ColumnDefinitions[1].Width = GridLength.Auto;
            Grid.SetColumn(ActionsPanel, 1);
            Grid.SetRow(ActionsPanel, 0);
            Grid.SetRowSpan(ActionsPanel, 4);
            ActionsPanel.Orientation = Orientation.Vertical;
        }
    }

    private ScanProfile SelectedProfile => ProfileInput.SelectedIndex switch
    {
        1 => ScanProfile.Verify,
        2 => ScanProfile.Full,
        _ => ScanProfile.Passive
    };
    private static string TagOf(ComboBox box, string fallback)
        => (box.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? fallback;

    private void OnProfileChanged(object sender, SelectionChangedEventArgs e)
        => UpdateProfileFields();

    private void UpdateProfileFields()
    {
        if (PrimaryDomainOnlyInput is null) return;
        var active = SelectedProfile != ScanProfile.Passive;
        var full = SelectedProfile == ScanProfile.Full;
        foreach (var item in new FrameworkElement[]
                 { PrimaryDomainOnlyInput, WildcardInput, AllowHttpFallbackInput, DisableBrowserInput })
            item.Visibility = active ? Visibility.Visible : Visibility.Collapsed;
        BrowserRiskNotice.Visibility = active ? Visibility.Visible : Visibility.Collapsed;
        PortsPanel.Visibility = full ? Visibility.Visible : Visibility.Collapsed;
        if (!active)
        {
            PrimaryDomainOnlyInput.IsChecked = false;
            WildcardInput.IsChecked = false;
            AllowHttpFallbackInput.IsChecked = false;
        }
        if (!full)
        {
            PortsInput.Text = "";
        }
    }

    private async void OnBrowseClicked(object sender, RoutedEventArgs e)
    {
        try
        {
            var picker = new FolderPicker { SuggestedStartLocation = PickerLocationId.DocumentsLibrary };
            picker.FileTypeFilter.Add("*");
            InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(this));
            var folder = await picker.PickSingleFolderAsync();
            if (folder is null) return;
            ResultsRootInput.Text = folder.Path;
            _settings.SaveResultsRoot(folder.Path);
        }
        catch (Exception ex) { await ShowMessageAsync("Каталог результатов", ex.Message); }
    }

    private ScanOptions? CollectOptions(out string? problem)
    {
        problem = null;
        var n = DnsBudgetInput.Value;
        if (double.IsNaN(n) || !double.IsFinite(n) || n % 1 != 0 || n is < 1 or > 1_000_000)
        {
            problem = "Лимит DNS-кандидатов должен быть целым числом от 1 до 1 000 000.";
            return null;
        }
        var options = new ScanOptions(
            DomainInput.Text.Trim(), SelectedProfile, ResultsRootInput.Text.Trim(),
            (int)n, TagOf(SourcesInput, "standard"), TagOf(ReportLanguageInput, "en"),
            FullReportInput.IsChecked == true,
            PrimaryDomainOnlyInput.IsChecked == true,
            WildcardInput.IsChecked == true,
            SelectedProfile == ScanProfile.Full ? PortsInput.Text : null,
            AllowHttpFallbackInput.IsChecked == true,
            DisableBrowserInput.IsChecked == true);
        problem = options.Validate();
        return problem is null ? options : null;
    }

    private async void OnRunButtonClicked(object sender, RoutedEventArgs e)
    {
        if (_busy)
        {
            await RequestForceStopAsync(false);
            return;
        }
        var options = CollectOptions(out var problem);
        if (options is null)
        {
            await ShowMessageAsync("Параметры исследования", problem ?? "Проверьте параметры.");
            return;
        }
        var authorized = false;
        if (options.Profile != ScanProfile.Passive)
        {
            authorized = await ShowChoiceAsync("Подтверждение разрешения",
                "Подтвердите наличие разрешения на активные проверки указанного домена.",
                "Подтверждаю");
            if (!authorized) return;
        }
        try
        {
            var runPath = RunDirectoryFactory.Propose(options.OutputDirectory);
            _lastResults = runPath;
            var actual = options with { OutputDirectory = runPath };
            _busy = true;
            _wasForceTerminated = false;
            _closeAfterStop = false;
            SetBusy(true);
            StatusText.Text = "Запуск исследования…";
            ProgressLabel.Text = "Подготовка";
            RunProgress.Value = 0;
            RunProgress.IsIndeterminate = true;
            ResourcesText.Text = "CPU: н/д   RAM: н/д   Сеть: н/д   Диск: н/д";

            var result = await _runner.RunAuthorizedAsync(actual, authorized,
                update => DispatcherQueue.TryEnqueue(() => ShowCoreUpdate(update)));
            if (_wasForceTerminated || result.ForceTerminated)
                StatusText.Text = "Принудительно завершено. Результаты могут быть неполными";
            else if (result.Status?.HasWorkerErrors == true)
                StatusText.Text = "Ошибка рабочего модуля: " + result.Status.WorkerErrorDiagnostic;
            else if (result.VerifiedSuccess)
                StatusText.Text = "Исследование успешно завершено";
            else if (result.VerifiedIncomplete)
                StatusText.Text = "Завершено с неполными результатами";
            else if (result.VerifiedInterrupted)
                StatusText.Text = "Исследование остановлено";
            else if (result.Status?.State == "error" && !string.IsNullOrWhiteSpace(result.Status.Message))
                StatusText.Text = "Ошибка ядра: " + result.Status.Message;
            else
                StatusText.Text = result.StatusDiagnostic is { } statusError
                    ? "Статус ядра не подтверждён: " + statusError
                    : "Исследование завершилось с ошибкой (код " + result.ExitCode + ")";
            ProgressLabel.Text = result.Status?.HasWorkerErrors == true
                ? "Есть ошибка рабочего модуля; проверьте частичные результаты и журнал"
                : result.VerifiedSuccess ? "Завершено" : "См. диагностический журнал";
            RunProgress.IsIndeterminate = result.Status?.HasWorkerErrors == true;
            RunProgress.Value = result.VerifiedSuccess ? 100 : 0;
        }
        catch (Exception ex)
        {
            RunProgress.IsIndeterminate = false;
            RunProgress.Value = 0;
            StatusText.Text = "Не удалось выполнить исследование";
            await ShowMessageAsync("Ошибка ASM Tool", ex.Message);
        }
        finally
        {
            _busy = false;
            SetBusy(false);
            OpenResultsButton.Visibility = _lastResults is not null && Directory.Exists(_lastResults)
                ? Visibility.Visible : Visibility.Collapsed;
            if (_closeAfterStop)
            {
                _closeAfterStop = false;
                Close();
            }
        }
    }

    private async Task<bool> RequestForceStopAsync(bool closeAfterStop)
    {
        if (!_busy || _wasForceTerminated) return false;
        var confirmed = await ShowChoiceAsync("Остановить исследование?",
            "Go 0.12.3 не поддерживает кооперативную отмену из GUI. " +
            "Доступно только принудительное завершение. Часть результатов может быть потеряна.",
            "Принудительно завершить");
        if (!confirmed || !_busy) return false;
        _closeAfterStop = closeAfterStop;
        try
        {
            _wasForceTerminated = true;
            StatusText.Text = "Принудительное завершение исследования…";
            _runner.ForceTerminateAfterUserConfirmation();
            return true;
        }
        catch (Exception ex)
        {
            _wasForceTerminated = false;
            _closeAfterStop = false;
            await ShowMessageAsync("Остановка", ex.Message);
            return false;
        }
    }

    private void ShowCoreUpdate(RunUpdate update)
    {
        if (!_busy) return;
        var status = update.Status;
        if (update.StatusDiagnostic is { } damaged)
        {
            StatusText.Text = "Повреждён статус ядра: " + damaged;
            RunProgress.IsIndeterminate = true;
            ProgressLabel.Text = "Результат не подтверждён файлом run_status.json";
        }
        else if (status is not null)
        {
            StatusText.Text = RunStatusReader.CompactDisplay(status);
            if (status.HasWorkerErrors)
            {
                RunProgress.IsIndeterminate = true;
                RunProgress.Value = 0;
                ProgressLabel.Text = "Ошибка рабочего модуля: " + status.WorkerErrorDiagnostic;
            }
            else if (status.IsStale)
            {
                ProgressLabel.Text = "Сигнал от ядра устарел";
                RunProgress.IsIndeterminate = true;
            }
            else if (status.ActiveProgress is { } worker)
            {
                RunProgress.IsIndeterminate = false;
                RunProgress.Value = worker.Fraction * 100;
                ProgressLabel.Text = (worker.Operation ?? status.Stage ?? "Операция") + " — " +
                    worker.Completed + "/" + worker.Planned +
                    " (" + Math.Round(worker.Fraction * 100) + "%)";
            }
            else
            {
                RunProgress.IsIndeterminate = !status.Terminal;
                ProgressLabel.Text = status.Stage ?? "Выполнение";
                if (status.SinceProgress is { } age && age > TimeSpan.FromSeconds(90))
                    ProgressLabel.Text += " · нет полезного прогресса " +
                        ((int)age.TotalSeconds) + " с";
            }
        }
        else
        {
            StatusText.Text = update.StatusPending
                ? "Ожидание файла статуса от ядра"
                : "Статус ядра отсутствует";
            RunProgress.IsIndeterminate = true;
            ProgressLabel.Text = "Подготовка";
        }
        if (update.Resources is { } r)
        {
            ResourcesText.Text = "CPU " + Percent(r.CpuPercent) + "   RAM Σ " +
                Size(r.SumWorkingSet) + "   Время " + r.Elapsed.ToString(@"hh\:mm\:ss") +
                "\nСеть интерфейса ≈ ↓ " + Rate(r.InterfaceRxBytesPerSecond) +
                "  ↑ " + Rate(r.InterfaceTxBytesPerSecond) +
                "   Диск процессов ↓ " + Rate(r.ProcessReadBytesPerSecond) +
                "  ↑ " + Rate(r.ProcessWriteBytesPerSecond);
        }
    }

    private static string Percent(double? value) =>
        value is { } v && double.IsFinite(v) ? v.ToString("F1") + "%" : "н/д";
    private static string Size(long? bytes) => bytes is { } b
        ? (b / 1048576d).ToString("F1") + " MiB" : "н/д";
    private static string Rate(double? bytes) => bytes is { } b && double.IsFinite(b)
        ? (b / 1048576d).ToString("F2") + " MiB/s" : "н/д";

    private void SetBusy(bool busy)
    {
        DomainInput.IsEnabled = !busy;
        ProfileInput.IsEnabled = !busy;
        BrowseButton.IsEnabled = !busy;
        SettingsScroll.IsEnabled = !busy;
        RunButton.Content = busy ? "Остановить" : "Начать исследование";
        RunButton.IsEnabled = true;
    }

    private async void OnOpenResultsClicked(object sender, RoutedEventArgs e)
    {
        if (_lastResults is null || !Directory.Exists(_lastResults))
        {
            await ShowMessageAsync("Результаты", "Каталог исследования недоступен.");
            return;
        }
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = "explorer.exe", UseShellExecute = true,
                ArgumentList = { _lastResults }
            });
        }
        catch (Exception ex) { await ShowMessageAsync("Результаты", ex.Message); }
    }

    private void OnWindowClosing(AppWindow sender, AppWindowClosingEventArgs args)
    {
        if (!_busy) return;
        args.Cancel = true;
        if (!_closeDialogActive) _ = ConfirmCloseAsync();
    }

    private async Task ConfirmCloseAsync()
    {
        _closeDialogActive = true;
        try { await RequestForceStopAsync(true); }
        finally { _closeDialogActive = false; }
    }

    private async Task<bool> ShowChoiceAsync(string title, string text, string positive)
    {
        var dialog = new ContentDialog
        {
            XamlRoot = RootGrid.XamlRoot, Title = title, Content = text,
            PrimaryButtonText = positive, CloseButtonText = "Отмена",
            DefaultButton = ContentDialogButton.Close
        };
        return await dialog.ShowAsync() == ContentDialogResult.Primary;
    }

    private async Task ShowMessageAsync(string title, string text)
    {
        var dialog = new ContentDialog
        {
            XamlRoot = RootGrid.XamlRoot, Title = title, Content = text,
            CloseButtonText = "Закрыть"
        };
        await dialog.ShowAsync();
    }
}
