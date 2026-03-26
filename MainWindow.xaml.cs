using System.Collections.Concurrent;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using Microsoft.Win32;

namespace ScanCharSecExploit
{
    public partial class MainWindow : Window
    {
        private CancellationTokenSource? _cts;
        private readonly FileLogger _fileLogger = new();
        private int _logLineCount;

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FlashWindowEx(ref FLASHWINFO pwfi);

        [StructLayout(LayoutKind.Sequential)]
        private struct FLASHWINFO
        {
            public uint cbSize;
            public nint hwnd;
            public uint dwFlags;
            public uint uCount;
            public uint dwTimeout;
        }

        private const uint FLASHW_ALL = 3;
        private const uint FLASHW_TIMERNOFG = 12;

        // Source code file extensions to scan
        private static readonly HashSet<string> SourceExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".cs", ".csx", ".vb",
            ".py", ".pyw", ".pyi",
            ".js", ".jsx", ".mjs", ".cjs",
            ".ts", ".tsx", ".mts",
            ".java", ".kt", ".kts", ".scala",
            ".c", ".h", ".cpp", ".hpp", ".cc", ".cxx", ".hxx",
            ".go", ".rs", ".swift", ".m", ".mm",
            ".rb", ".php", ".pl", ".pm", ".lua",
            ".r", ".R", ".jl",
            ".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd",
            ".sql", ".graphql", ".gql",
            ".html", ".htm", ".css", ".scss", ".sass", ".less",
            ".xml", ".xaml", ".xsl", ".xslt", ".svg",
            ".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg",
            ".md", ".markdown", ".rst", ".txt", ".tex",
            ".proto", ".thrift", ".avsc",
            ".dockerfile", ".tf", ".hcl",
            ".makefile", ".cmake",
            ".gradle", ".sbt", ".pom",
            ".vue", ".svelte", ".astro",
            ".dart", ".ex", ".exs", ".erl", ".hrl",
            ".zig", ".nim", ".cr", ".v", ".d",
            ".fs", ".fsx", ".fsi", ".ml", ".mli",
            ".clj", ".cljs", ".cljc", ".edn",
            ".hs", ".lhs", ".elm", ".purs",
            ".sol", ".move",
            ".env", ".gitignore", ".editorconfig",
        };

        // Filenames without extensions that are source/config files
        private static readonly HashSet<string> SourceFilenames = new(StringComparer.OrdinalIgnoreCase)
        {
            "Makefile", "CMakeLists.txt", "Dockerfile", "Vagrantfile",
            "Gemfile", "Rakefile", "Podfile", "Brewfile",
            ".gitignore", ".gitattributes", ".dockerignore",
            ".editorconfig", ".eslintrc", ".prettierrc",
        };

        public MainWindow()
        {
            InitializeComponent();
            ResultsGrid.SelectionChanged += ResultsGrid_SelectionChanged;
            AppendLog("Application started. Select a folder and click Scan.");
            AppendLog($"Log file: {_fileLogger.LogFilePath}");
        }

        private void AppendLog(string message)
        {
            _fileLogger.Log(message);
            Dispatcher.Invoke(() =>
            {
                if (_logLineCount >= 600)
                {
                    LogTextBlock.Text = "";
                    _logLineCount = 0;
                    LogTextBlock.Text += $"[{DateTime.Now:HH:mm:ss}] ── Log cleared (600 line cap). Full log: {_fileLogger.LogFilePath} ──\n";
                    _logLineCount++;
                }
                LogTextBlock.Text += $"[{DateTime.Now:HH:mm:ss}] {message}\n";
                _logLineCount++;
                LogScrollViewer.ScrollToEnd();
            });
        }

        protected override void OnClosed(EventArgs e)
        {
            _fileLogger.Dispose();
            base.OnClosed(e);
        }

        private static bool IsFileWritable(string filePath)
        {
            try
            {
                var info = new FileInfo(filePath);
                if (info.IsReadOnly) return false;
                using var fs = info.Open(FileMode.Open, FileAccess.Write, FileShare.None);
                return true;
            }
            catch (UnauthorizedAccessException) { return false; }
            catch (IOException) { return false; }
        }

        private void FlashWindow()
        {
            var helper = new WindowInteropHelper(this);
            var info = new FLASHWINFO
            {
                cbSize = (uint)Marshal.SizeOf<FLASHWINFO>(),
                hwnd = helper.Handle,
                dwFlags = FLASHW_ALL | FLASHW_TIMERNOFG,
                uCount = 5,
                dwTimeout = 0
            };
            FlashWindowEx(ref info);
        }

        private void SetScanning(bool scanning)
        {
            if (scanning)
            {
                ScanButton.Content = "⏹ Stop";
                ScanButton.Style = (Style)FindResource("DangerButton");
            }
            else
            {
                ScanButton.Content = "▶ Scan";
                ScanButton.Style = (Style)FindResource("ActionButton");
            }
            ScanButton.IsEnabled = true;
            UpdateRemoveButtons();
            ScanProgress.Visibility = scanning ? Visibility.Visible : Visibility.Collapsed;
            StatusText.Text = scanning ? "Scanning..." : "Ready";
        }

        private void UpdateRemoveButtons()
        {
            var items = ResultsGrid.ItemsSource as List<ScanResult>;
            bool hasRemovableResults = items != null && items.Any(i => i.HasRemovableHiddenChars);
            bool hasSelectedRemovableResults = ResultsGrid.SelectedItems.Cast<ScanResult>().Any(i => i.HasRemovableHiddenChars);
            RemoveAllButton.IsEnabled = hasRemovableResults;
            RemoveSelectedButton.IsEnabled = hasSelectedRemovableResults;
        }

        private void ResultsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            UpdateRemoveButtons();
        }

        private void CopyPreview_Click(object sender, RoutedEventArgs e)
        {
            if (ResultsGrid.SelectedItem is ScanResult item && !string.IsNullOrEmpty(item.DecodedPreview))
            {
                Clipboard.SetText(item.DecodedPreview);
                AppendLog($"Copied decoded preview for: {item.FilePath}");
            }
        }

        private void CopyFilePath_Click(object sender, RoutedEventArgs e)
        {
            if (ResultsGrid.SelectedItem is ScanResult item)
            {
                Clipboard.SetText(item.FilePath);
                AppendLog($"Copied file path: {item.FilePath}");
            }
        }

        private static bool IsSourceFile(string filePath)
        {
            var ext = Path.GetExtension(filePath);
            if (!string.IsNullOrEmpty(ext) && SourceExtensions.Contains(ext))
                return true;
            var name = Path.GetFileName(filePath);
            return SourceFilenames.Contains(name);
        }

        private void BrowseButton_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFolderDialog
            {
                Title = "Select folder to scan",
                InitialDirectory = PathTextBox.Text
            };
            if (dialog.ShowDialog() == true)
            {
                PathTextBox.Text = dialog.FolderName;
                AppendLog($"Selected folder: {dialog.FolderName}");
            }
        }

        private async void ScanButton_Click(object sender, RoutedEventArgs e)
        {
            // If already scanning, cancel
            if (_cts != null && !_cts.IsCancellationRequested)
            {
                _cts.Cancel();
                AppendLog("Stopping scan...");
                ScanButton.IsEnabled = false;
                return;
            }

            var path = PathTextBox.Text.Trim();
            if (string.IsNullOrEmpty(path) || !Directory.Exists(path))
            {
                MessageBox.Show("Please select a valid folder.", "Invalid Path",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            _cts = new CancellationTokenSource();
            SetScanning(true);
            ResultsGrid.ItemsSource = null;
            AppendLog($"Starting scan of: {path}");

            try
            {
                var report = await Task.Run(() => ScanDirectory(path, _cts.Token), _cts.Token);

                ResultsGrid.ItemsSource = report.FilesWithFindings;
                UpdateRemoveButtons();
                StatusText.Text = $"Done — {report.FilesScanned} source files scanned, {report.FilesWithFindings.Count} with findings";
                AppendLog($"Scan complete. {report.FilesScanned} source files scanned, {report.FilesWithFindings.Count} files with findings.");
                FlashWindow();
            }
            catch (OperationCanceledException)
            {
                AppendLog("Scan cancelled.");
                StatusText.Text = "Scan cancelled";
            }
            catch (Exception ex)
            {
                AppendLog($"Error: {ex.Message}");
                StatusText.Text = "Scan failed";
            }
            finally
            {
                SetScanning(false);
            }
        }

        private ScanReport ScanDirectory(string rootPath, CancellationToken ct)
        {
            var report = new ScanReport();
            var files = new List<string>();

            try
            {
                foreach (var file in Directory.EnumerateFiles(rootPath, "*", new EnumerationOptions
                {
                    RecurseSubdirectories = true,
                    IgnoreInaccessible = true,
                    AttributesToSkip = FileAttributes.System
                }))
                {
                    if (IsSourceFile(file))
                        files.Add(file);
                }
            }
            catch (Exception ex)
            {
                AppendLog($"Error enumerating files: {ex.Message}");
            }

            report.FilesScanned = files.Count;
            AppendLog($"Found {files.Count} source code files to scan.");

            var results = new ConcurrentBag<ScanResult>();
            int processed = 0;

            Parallel.ForEach(files, new ParallelOptions
            {
                CancellationToken = ct,
                MaxDegreeOfParallelism = Environment.ProcessorCount
            }, file =>
            {
                try
                {
                    // Fast byte-level pre-check to skip clean files
                    var rawBytes = File.ReadAllBytes(file);
                    bool mayContainHidden = CharSecScanner.MayContainHiddenChars(rawBytes);
                    bool mayContainSuspiciousText = CharSecScanner.MayContainSuspiciousText(rawBytes);
                    if (!mayContainHidden && !mayContainSuspiciousText)
                    {
                        Interlocked.Increment(ref processed);
                        return;
                    }

                    var text = Encoding.UTF8.GetString(rawBytes);
                    var result = CharSecScanner.Analyze(text, file, includeHiddenCharPass: mayContainHidden);
                    if (result.HasFindings)
                    {
                        results.Add(result);
                        AppendLog($"⚠ Findings detected: {file} ({result.HiddenCharCount} hidden chars, severity: {result.Severity})");
                        if (result.HiddenByteCount > 0)
                            AppendLog($"   ↳ VS payload: {result.HiddenByteCount} decoded bytes");
                        if (result.Base64DecodedPreview != null)
                            AppendLog($"   ↳ Base64 payload detected: {result.Base64DecodedPreview}");
                        if (result.SuspiciousPatterns.Count > 0)
                            AppendLog($"   ↳ Suspicious patterns: {result.SuspiciousPatternSummary}");
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
                catch (DecoderFallbackException) { }

                int current = Interlocked.Increment(ref processed);
                if (current % 200 == 0)
                {
                    int pct = (int)((double)current / files.Count * 100);
                    Dispatcher.Invoke(() =>
                    {
                        ScanProgress.Value = pct;
                        StatusText.Text = $"Scanning... {current}/{files.Count} files ({pct}%)";
                    });
                }
            });

            report.Results = results.ToList();
            return report;
        }

    private async void RemoveSelected_Click(object sender, RoutedEventArgs e)
        {
            var selected = ResultsGrid.SelectedItems.Cast<ScanResult>().Where(i => i.HasRemovableHiddenChars).ToList();
            if (selected.Count == 0)
            {
                MessageBox.Show("The current selection has no hidden Unicode characters to strip. Pattern-only/IOC findings are informational and are not auto-remediated.", "Nothing Removable",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            await RemoveHiddenFromFiles(selected, $"selected {selected.Count} file(s)");
        }

        private async void RemoveAll_Click(object sender, RoutedEventArgs e)
        {
            var items = ResultsGrid.ItemsSource as List<ScanResult>;
            var removableItems = items?.Where(i => i.HasRemovableHiddenChars).ToList();
            if (removableItems == null || removableItems.Count == 0)
            {
                MessageBox.Show("There are no hidden Unicode findings to remove. Pattern-only/IOC findings need manual review.", "Nothing Removable",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            await RemoveHiddenFromFiles(removableItems, $"all {removableItems.Count} file(s)");
        }

        private async Task RemoveHiddenFromFiles(List<ScanResult> files, string description)
        {
            var result = MessageBox.Show(
                $"This will strip hidden characters from {description}.\n\nThe files themselves will NOT be deleted — only the invisible hidden characters will be removed from their content.\n\nThis cannot be undone. Continue?",
                "Confirm Removal", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (result != MessageBoxResult.Yes) return;

            SetScanning(true);
            AppendLog($"Removing hidden data from {description}...");

            try
            {
                var filesToProcess = files.ToList();
                var removeReport = await Task.Run(() =>
                {
                    var rr = new RemoveReport();
                    foreach (var item in filesToProcess)
                    {
                        try
                        {
                            if (!IsFileWritable(item.FilePath))
                            {
                                AppendLog($"⛔ Skipped (access denied): {item.FilePath} — file is read-only or in a protected directory. Try running as Administrator.");
                                rr.FilesProcessed++;
                                continue;
                            }

                            var text = File.ReadAllText(item.FilePath, Encoding.UTF8);
                            if (CharSecScanner.ContainsHiddenData(text))
                            {
                                int hidden = CharSecScanner.CountHiddenChars(text);
                                string cleaned = CharSecScanner.StripHiddenData(text);
                                File.WriteAllText(item.FilePath, cleaned, Encoding.UTF8);
                                rr.FilesModified.Add(item.FilePath);
                                rr.BytesRemoved += hidden;
                                AppendLog($"✅ Cleaned: {item.FilePath} ({hidden} hidden chars removed)");
                            }
                        }
                        catch (UnauthorizedAccessException)
                        {
                            AppendLog($"⛔ Access denied: {item.FilePath} — try running as Administrator.");
                        }
                        catch (Exception ex)
                        {
                            AppendLog($"❌ Failed to clean {item.FilePath}: {ex.Message}");
                        }
                        rr.FilesProcessed++;
                    }
                    return rr;
                });

                // Remove cleaned items from the list
                var allItems = ResultsGrid.ItemsSource as List<ScanResult>;
                if (allItems != null)
                {
                    var modifiedPaths = new HashSet<string>(removeReport.FilesModified);
                    allItems.RemoveAll(i => modifiedPaths.Contains(i.FilePath));
                    ResultsGrid.ItemsSource = null;
                    ResultsGrid.ItemsSource = allItems;
                }

                StatusText.Text = $"Removed {removeReport.BytesRemoved} hidden chars from {removeReport.FilesModified.Count} file(s)";
                AppendLog($"Removal complete. {removeReport.FilesModified.Count} files modified, {removeReport.BytesRemoved} hidden chars removed.");
                UpdateRemoveButtons();
            }
            catch (Exception ex)
            {
                AppendLog($"Error during removal: {ex.Message}");
            }
            finally
            {
                SetScanning(false);
            }
        }
    }
}
