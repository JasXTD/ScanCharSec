using System.IO;
using System.Text;

namespace ScanCharSecExploit
{
    /// <summary>
    /// Detects and removes hidden Unicode variation selector characters in text files.
    /// Variation selectors (U+FE00–U+FE0F, U+E0100–U+E01EF) can encode arbitrary
    /// bytes invisibly after a carrier character.
    /// </summary>
    public static class CharSecScanner
    {
        private const int VsStart = 0xFE00;
        private const int VsEnd = 0xFE0F;
        private const int VssStart = 0xE0100;
        private const int VssEnd = 0xE01EF;

        /// <summary>
        /// Returns the hidden byte value if the code point is a variation selector, or -1 otherwise.
        /// </summary>
        private static int VsToByte(int codePoint)
        {
            if (codePoint >= VsStart && codePoint <= VsEnd)
                return codePoint - VsStart;
            if (codePoint >= VssStart && codePoint <= VssEnd)
                return codePoint - VssStart + 16;
            return -1;
        }

        /// <summary>
        /// Quick byte-level pre-check: returns true if the file bytes contain
        /// any UTF-8 sequences that could be variation selectors.
        /// VS1-VS16 encode as EF B8 80..8F, VSS encode as F3 A0 84 80..F3 A0 87 AF.
        /// Checking for 0xEF or 0xF3 is a fast filter before full parsing.
        /// </summary>
        public static bool MayContainVS(byte[] data)
        {
            for (int i = 0; i < data.Length - 2; i++)
            {
                byte b = data[i];
                if (b == 0xEF && i + 2 < data.Length && data[i + 1] == 0xB8 && data[i + 2] >= 0x80 && data[i + 2] <= 0x8F)
                    return true;
                if (b == 0xF3 && i + 3 < data.Length && data[i + 1] == 0xA0 && data[i + 2] >= 0x84 && data[i + 2] <= 0x87)
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Single-pass analysis: checks for hidden data, counts bytes, and generates preview.
        /// Returns null if no hidden data found.
        /// </summary>
        public static ScanResult? Analyze(string text, string filePath)
        {
            var allBytes = new List<byte>();
            for (int i = 0; i < text.Length; i++)
            {
                int cp = char.ConvertToUtf32(text, i);
                if (char.IsHighSurrogate(text[i])) i++;
                int b = VsToByte(cp);
                if (b >= 0)
                    allBytes.Add((byte)b);
            }

            if (allBytes.Count == 0)
                return null;

            string? preview = FormatPreview(allBytes);
            if (preview != null && preview.Length > 120)
                preview = preview[..120] + "...";

            return new ScanResult
            {
                FilePath = filePath,
                HiddenByteCount = allBytes.Count,
                DecodedPreview = preview ?? "(binary data)"
            };
        }

        /// <summary>
        /// Returns true if the text contains at least one variation selector character.
        /// </summary>
        public static bool ContainsHiddenData(string text)
        {
            for (int i = 0; i < text.Length; i++)
            {
                int cp = char.ConvertToUtf32(text, i);
                if (char.IsHighSurrogate(text[i])) i++;
                if (VsToByte(cp) >= 0)
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Counts the number of hidden variation selector characters in the text.
        /// </summary>
        public static int CountHiddenBytes(string text)
        {
            int count = 0;
            for (int i = 0; i < text.Length; i++)
            {
                int cp = char.ConvertToUtf32(text, i);
                if (char.IsHighSurrogate(text[i])) i++;
                if (VsToByte(cp) >= 0)
                    count++;
            }
            return count;
        }

        /// <summary>
        /// Strips all variation selector characters from the text.
        /// </summary>
        public static string StripHiddenData(string text)
        {
            var sb = new StringBuilder(text.Length);
            for (int i = 0; i < text.Length; i++)
            {
                int cp = char.ConvertToUtf32(text, i);
                bool isSurrogate = char.IsHighSurrogate(text[i]);
                if (VsToByte(cp) < 0)
                {
                    sb.Append(text[i]);
                    if (isSurrogate)
                        sb.Append(text[i + 1]);
                }
                if (isSurrogate) i++;
            }
            return sb.ToString();
        }

        private static string? FormatPreview(List<byte> bytes)
        {
            if (bytes.Count == 0) return null;
            var arr = bytes.ToArray();

            try
            {
                var decoded = Encoding.UTF8.GetString(arr);
                if (decoded.Length > 0 && IsMostlyPrintable(decoded))
                    return decoded;
            }
            catch { }

            return "0x " + BitConverter.ToString(arr).Replace("-", " ");
        }

        private static bool IsMostlyPrintable(string text)
        {
            int printable = 0;
            foreach (char c in text)
            {
                if (!char.IsControl(c))
                    printable++;
            }
            return printable > 0 && (double)printable / text.Length > 0.5;
        }
    }

    public class ScanResult
    {
        public string FilePath { get; set; } = "";
        public int HiddenByteCount { get; set; }
        public string? DecodedPreview { get; set; }
    }

    public class ScanReport
    {
        public int FilesScanned { get; set; }
        public List<ScanResult> FilesWithHiddenData { get; set; } = new();
        public bool Found => FilesWithHiddenData.Count > 0;
    }

    public class RemoveReport
    {
        public int FilesProcessed { get; set; }
        public List<string> FilesModified { get; set; } = new();
        public int BytesRemoved { get; set; }
    }
}
