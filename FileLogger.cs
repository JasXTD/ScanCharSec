using System.IO;

namespace ScanCharSecExploit
{
    /// <summary>
    /// Simple file logger that writes timestamped entries to a logs folder.
    /// </summary>
    public sealed class FileLogger : IDisposable
    {
        private readonly StreamWriter _writer;
        private readonly object _lock = new();
        private bool _disposed;

        public string LogFilePath { get; }

        public FileLogger()
        {
            var logDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs");
            Directory.CreateDirectory(logDir);

            var fileName = $"ScanCharSec_{DateTime.Now:yyyy-MM-dd_HHmmss}.log";
            LogFilePath = Path.Combine(logDir, fileName);

            _writer = new StreamWriter(LogFilePath, append: true) { AutoFlush = true };
            _writer.WriteLine($"=== ScanCharSec Log Started: {DateTime.Now:yyyy-MM-dd HH:mm:ss} ===");
        }

        public void Log(string message)
        {
            if (_disposed) return;
            var line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {message}";
            lock (_lock)
            {
                try { _writer.WriteLine(line); }
                catch { /* swallow to avoid crashing the app */ }
            }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            lock (_lock)
            {
                _writer.WriteLine($"=== Log Ended: {DateTime.Now:yyyy-MM-dd HH:mm:ss} ===");
                _writer.Dispose();
            }
        }
    }
}
