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
        }

        private void AppendLog(string message)
        {
            Dispatcher.Invoke(() =>
            {
                LogTextBlock.Text += $"[{DateTime.Now:HH:mm:ss}] {message}\n";
                LogScrollViewer.ScrollToEnd();
            });
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
            ScanButton.IsEnabled = !scanning;
            UpdateRemoveButtons();
            ScanProgress.Visibility = scanning ? Visibility.Visible : Visibility.Collapsed;
            StatusText.Text = scanning ? "Scanning..." : "Ready";
        }

        private void UpdateRemoveButtons()
        {
            var items = ResultsGrid.ItemsSource as List<ScanResult>;
            bool hasResults = items != null && items.Count > 0;
            RemoveAllButton.IsEnabled = hasResults;
            RemoveSelectedButton.IsEnabled = ResultsGrid.SelectedItems.Count > 0;
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

                ResultsGrid.ItemsSource = report.FilesWithHiddenData;
                UpdateRemoveButtons();
                StatusText.Text = $"Done — {report.FilesScanned} source files scanned, {report.FilesWithHiddenData.Count} with hidden data";
                AppendLog($"Scan complete. {report.FilesScanned} source files scanned, {report.FilesWithHiddenData.Count} files with hidden data.");
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
                    if (!CharSecScanner.MayContainHiddenChars(rawBytes))
                    {
                        Interlocked.Increment(ref processed);
                        return;
                    }

                    var text = Encoding.UTF8.GetString(rawBytes);
                    var result = CharSecScanner.Analyze(text, file);
                    if (result.HasFindings)
                    {
                        results.Add(result);
                        AppendLog($"⚠ Hidden data found: {file} ({result.HiddenCharCount} hidden chars, severity: {result.Severity})");
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
            var selected = ResultsGrid.SelectedItems.Cast<ScanResult>().ToList();
            if (selected.Count == 0)
            {
                MessageBox.Show("No files selected.", "Nothing Selected",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            await RemoveHiddenFromFiles(selected, $"selected {selected.Count} file(s)");
        }

        private async void RemoveAll_Click(object sender, RoutedEventArgs e)
        {
            var items = ResultsGrid.ItemsSource as List<ScanResult>;
            if (items == null || items.Count == 0) return;
            await RemoveHiddenFromFiles(items, $"all {items.Count} file(s)");
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