using System.Text;
using System.Text.RegularExpressions;

namespace ScanCharSecExploit
{
	// ─────────────────────────────────────────────────────────────────────────────
	// CharSecScanner  –  Detects hidden Unicode payloads in source files
	//
	// Covers:
	//   1. Variation Selectors   (VS1–VS16: U+FE00–U+FE0F,
	//                             VSS:      U+E0100–U+E01EF)
	//   2. Bidi Override chars   (Trojan Source – CVE-2021-42574)
	//   3. Zero-width chars      (ZWS, ZWJ, ZWNJ, Word Joiner, BOM …)
	//   4. Other invisible fmt   (Soft Hyphen, various control chars)
	//   5. Suspicious JS patterns (VS-decoder + eval payload combos)
	// ─────────────────────────────────────────────────────────────────────────────

	// ── Enumerations ─────────────────────────────────────────────────────────────

	public enum CharType
	{
		Normal,
		VariationSelector,   // Hidden-byte carrier
		BidiOverride,        // Trojan Source – CRITICAL
		ZeroWidth,           // Invisible but low-severity
		InvisibleFormatting  // Soft hyphen, BOM, etc.
	}

	public enum Severity
	{
		Clean,
		Info,
		Warning,
		Critical
	}

	// ── Data classes ──────────────────────────────────────────────────────────────

	public class HiddenCharOccurrence
	{
		/// <summary>Linear character index inside the source string.</summary>
		public int Position { get; set; }
		public int Line { get; set; }
		public int Column { get; set; }
		public int CodePoint { get; set; }
		public CharType Type { get; set; }

		/// <summary>Up to 10 visible characters surrounding the hidden char.</summary>
		public string CarrierContext { get; set; } = "";

		public string CodePointHex => $"U+{CodePoint:X4}";

		public string Description => Type switch
		{
			CharType.VariationSelector => "Variation Selector (hidden byte carrier)",
			CharType.BidiOverride => "Bidi Override – Trojan Source (CRITICAL)",
			CharType.ZeroWidth => "Zero-Width character",
			CharType.InvisibleFormatting => "Invisible formatting character",
			_ => "Normal"
		};
	}

	public class PatternMatch
	{
		public string PatternName { get; set; } = "";
		public string Description { get; set; } = "";
		public int Line { get; set; }
		public Severity Severity { get; set; }
	}

	public class ScanResult
	{
		public string FilePath { get; set; } = "";

		// ── Hidden-character findings ──────────────────────────────────────────
		public int HiddenByteCount { get; set; }
		public string DecodedPreview { get; set; } = "";
		public string? Base64DecodedPreview { get; set; }
		public List<HiddenCharOccurrence> Occurrences { get; set; } = new();

		// ── Suspicious-pattern findings ───────────────────────────────────────
		public List<PatternMatch> SuspiciousPatterns { get; set; } = new();

		// ── Computed severity ─────────────────────────────────────────────────
		public Severity Severity
		{
			get
			{
				if (Occurrences.Any(o => o.Type == CharType.BidiOverride) ||
						SuspiciousPatterns.Any(p => p.Severity == Severity.Critical))
					return Severity.Critical;

				if (Occurrences.Any(o => o.Type == CharType.VariationSelector) ||
						SuspiciousPatterns.Any(p => p.Severity == Severity.Warning))
					return Severity.Warning;

				if (Occurrences.Count > 0 || SuspiciousPatterns.Count > 0)
					return Severity.Info;

				return Severity.Clean;
			}
		}

		public bool HasFindings => Occurrences.Count > 0 || SuspiciousPatterns.Count > 0;
	}

	public class ScanReport
	{
		public int FilesScanned { get; set; }
		public List<ScanResult> Results { get; set; } = new();
		public List<ScanResult> FilesWithHiddenData => Results.Where(r => r.HasFindings).ToList();
		public bool Found => FilesWithHiddenData.Count > 0;
	}

	public class RemoveReport
	{
		public int FilesProcessed { get; set; }
		public List<string> FilesModified { get; set; } = new();
		public int BytesRemoved { get; set; }
	}

	// ── Main scanner ──────────────────────────────────────────────────────────────

	public static class CharSecScanner
	{
		// ── Variation-selector ranges ─────────────────────────────────────────
		private const int VsStart = 0xFE00;
		private const int VsEnd = 0xFE0F;
		private const int VssStart = 0xE0100;
		private const int VssEnd = 0xE01EF;

		// ── Bidi override code-points (Trojan Source – CVE-2021-42574) ────────
		private static readonly HashSet<int> BidiOverrides = new()
				{
						0x202A, // LRE  – Left-to-Right Embedding
            0x202B, // RLE  – Right-to-Left Embedding
            0x202C, // PDF  – Pop Directional Formatting
            0x202D, // LRO  – Left-to-Right Override
            0x202E, // RLO  – Right-to-Left Override  ← most dangerous
            0x2066, // LRI  – Left-to-Right Isolate
            0x2067, // RLI  – Right-to-Left Isolate
            0x2068, // FSI  – First Strong Isolate
            0x2069, // PDI  – Pop Directional Isolate
        };

		// ── Zero-width code-points ────────────────────────────────────────────
		private static readonly HashSet<int> ZeroWidthChars = new()
				{
						0x200B, // ZWSP  – Zero Width Space
            0x200C, // ZWNJ  – Zero Width Non-Joiner
            0x200D, // ZWJ   – Zero Width Joiner
            0x2060, // WJ    – Word Joiner
            0xFEFF, // BOM / Zero Width No-Break Space (outside position 0)
        };

		// ── Invisible-formatting code-points ─────────────────────────────────
		private static readonly HashSet<int> InvisibleFormatting = new()
				{
						0x00AD, // Soft Hyphen
            0x034F, // Combining Grapheme Joiner
            0x115F, // Hangul Choseong Filler
            0x1160, // Hangul Jungseong Filler
            0x17B4, // Khmer Vowel Inherent Aq
            0x17B5, // Khmer Vowel Inherent Aa
            0x3164, // Hangul Filler
            0xFFA0, // Halfwidth Hangul Filler
        };

		// ── Suspicious JS/TS patterns ─────────────────────────────────────────
		//  Each tuple: (regex, name, description, severity)
		private static readonly (string Pattern, string Name, string Description, Severity Sev)[]
				SuspiciousPatterns =
		{
            // Variation-selector decoder loops
            (@"codePointAt\s*\(\s*0\s*\)[\s\S]{0,120}0xFE0",
						 "VS-Decoder Loop",
						 "Code iterates codePointAt(0) and checks against VS range 0xFE00–0xFE0F",
						 Severity.Critical),

						(@"0xE0100[\s\S]{0,60}0xE01EF",
						 "VSS-Decoder Loop",
						 "Code checks against supplemental variation-selector range 0xE0100–0xE01EF",
						 Severity.Critical),

            // eval + Buffer.from (the exact attack in the screenshot)
            (@"eval\s*\([\s\S]{0,80}Buffer\.from",
						 "eval(Buffer.from(…))",
						 "Decodes a buffer and immediately evals it – classic hidden-payload execution",
						 Severity.Critical),

						(@"eval\s*\([\s\S]{0,80}\.toString\s*\(\s*['""]utf-?8['""]",
						 "eval(…toString('utf-8'))",
						 "eval with UTF-8 decode – strong indicator of variation-selector payload execution",
						 Severity.Critical),

            // Generic dangerous eval combos
            (@"eval\s*\(\s*(?:atob|Buffer\.from|unescape|decodeURIComponent)",
						 "eval(decode(…))",
						 "eval wrapping a decode function – obfuscated code execution",
						 Severity.Warning),

            // Function constructor abuse
            (@"new\s+Function\s*\([\s\S]{0,200}Buffer\.from",
						 "new Function(Buffer.from(…))",
						 "Dynamic function creation from decoded buffer",
						 Severity.Critical),

            // filter(n => n !== null) is the canonical VS-decoder tail
            (@"\.filter\s*\(\s*\w+\s*=>\s*\w+\s*!==\s*null\s*\)",
						 "VS-Filter Tail",
						 "Canonical null-filter used at the end of variation-selector decoders",
						 Severity.Warning),

            // Suspicious require/import inside eval
            (@"eval\s*\([\s\S]{0,200}require\s*\(",
						 "eval(require(…))",
						 "eval containing a require() call – possible code-injection vector",
						 Severity.Warning),
				};

		// ═════════════════════════════════════════════════════════════════════════
		// Public API
		// ═════════════════════════════════════════════════════════════════════════

		/// <summary>
		/// Fast byte-level pre-check. Returns true if the raw bytes could contain
		/// variation selectors (EF B8 8x or F3 A0 84–87 xx). Use to skip files
		/// that definitely contain no hidden data before full UTF-16 analysis.
		/// </summary>
		public static bool MayContainVS(byte[] data)
		{
			for (int i = 0; i < data.Length - 2; i++)
			{
				// VS1–VS16: EF B8 80–8F
				if (data[i] == 0xEF && data[i + 1] == 0xB8 &&
						data[i + 2] >= 0x80 && data[i + 2] <= 0x8F)
					return true;

				// VSS: F3 A0 84 80 – F3 A0 87 AF
				if (i + 3 < data.Length &&
						data[i] == 0xF3 && data[i + 1] == 0xA0 &&
						data[i + 2] >= 0x84 && data[i + 2] <= 0x87)
					return true;
			}
			return false;
		}

		/// <summary>
		/// Full analysis: detects hidden variation-selector data AND suspicious
		/// source-code patterns. Returns a complete ScanResult (never null).
		/// </summary>
		public static ScanResult Analyze(string text, string filePath)
		{
			var result = new ScanResult { FilePath = filePath };

			// ── Pass 1: hidden character detection ────────────────────────────
			var lines = BuildLineIndex(text);
			var hiddenBytes = new List<byte>();

			for (int i = 0; i < text.Length; i++)
			{
				int cp = char.ConvertToUtf32(text, i);
				bool isSurrogate = char.IsHighSurrogate(text[i]);

				CharType ctype = ClassifyCodePoint(cp);

				if (ctype != CharType.Normal)
				{
					var (line, col) = GetLineCol(lines, i);
					result.Occurrences.Add(new HiddenCharOccurrence
					{
						Position = i,
						Line = line,
						Column = col,
						CodePoint = cp,
						Type = ctype,
						CarrierContext = GetContext(text, i, 10)
					});

					int b = VsToByte(cp);
					if (b >= 0)
						hiddenBytes.Add((byte)b);
				}

				if (isSurrogate) i++;
			}

			// ── Decode reconstructed bytes ────────────────────────────────────
			if (hiddenBytes.Count > 0)
			{
				result.HiddenByteCount = hiddenBytes.Count;
				result.DecodedPreview = Truncate(FormatPreview(hiddenBytes), 160);
				result.Base64DecodedPreview = TryDecodeBase64(hiddenBytes);
			}

			// ── Pass 2: suspicious-pattern detection ─────────────────────────
			result.SuspiciousPatterns = DetectSuspiciousPatterns(text);

			return result;
		}

		/// <summary>Strips ALL hidden / invisible characters from the text.</summary>
		public static string StripHiddenData(string text)
		{
			var sb = new StringBuilder(text.Length);
			for (int i = 0; i < text.Length; i++)
			{
				int cp = char.ConvertToUtf32(text, i);
				bool surr = char.IsHighSurrogate(text[i]);

				if (ClassifyCodePoint(cp) == CharType.Normal)
				{
					sb.Append(text[i]);
					if (surr) sb.Append(text[i + 1]);
				}
				if (surr) i++;
			}
			return sb.ToString();
		}

		/// <summary>Returns true if any hidden/invisible char is present.</summary>
		public static bool ContainsHiddenData(string text)
		{
			for (int i = 0; i < text.Length; i++)
			{
				int cp = char.ConvertToUtf32(text, i);
				if (char.IsHighSurrogate(text[i])) i++;
				if (ClassifyCodePoint(cp) != CharType.Normal) return true;
			}
			return false;
		}

		/// <summary>Counts hidden/invisible characters.</summary>
		public static int CountHiddenChars(string text)
		{
			int count = 0;
			for (int i = 0; i < text.Length; i++)
			{
				int cp = char.ConvertToUtf32(text, i);
				if (char.IsHighSurrogate(text[i])) i++;
				if (ClassifyCodePoint(cp) != CharType.Normal) count++;
			}
			return count;
		}

		/// <summary>Scans source code text for suspicious decoder/eval patterns.</summary>
		public static List<PatternMatch> DetectSuspiciousPatterns(string sourceCode)
		{
			var matches = new List<PatternMatch>();
			var lineStarts = BuildLineIndex(sourceCode);

			foreach (var (pattern, name, description, sev) in SuspiciousPatterns)
			{
				var rx = new Regex(pattern, RegexOptions.Multiline | RegexOptions.IgnoreCase);
				foreach (Match m in rx.Matches(sourceCode))
				{
					var (line, _) = GetLineCol(lineStarts, m.Index);
					matches.Add(new PatternMatch
					{
						PatternName = name,
						Description = description,
						Line = line,
						Severity = sev
					});
				}
			}
			return matches;
		}

		// ═════════════════════════════════════════════════════════════════════════
		// Private helpers
		// ═════════════════════════════════════════════════════════════════════════

		/// <summary>Classifies a Unicode code-point.</summary>
		private static CharType ClassifyCodePoint(int cp)
		{
			if ((cp >= VsStart && cp <= VsEnd) || (cp >= VssStart && cp <= VssEnd))
				return CharType.VariationSelector;
			if (BidiOverrides.Contains(cp))
				return CharType.BidiOverride;
			if (ZeroWidthChars.Contains(cp))
				return CharType.ZeroWidth;
			if (InvisibleFormatting.Contains(cp))
				return CharType.InvisibleFormatting;
			return CharType.Normal;
		}

		/// <summary>
		/// Maps a variation selector code-point to its hidden byte value (0-255),
		/// or returns -1 if the code-point is not a variation selector.
		/// </summary>
		private static int VsToByte(int cp)
		{
			if (cp >= VsStart && cp <= VsEnd) return cp - VsStart;          //  0–15
			if (cp >= VssStart && cp <= VssEnd) return cp - VssStart + 16;    // 16–255
			return -1;
		}

		/// <summary>Builds an array of character-index positions for each line start.</summary>
		private static int[] BuildLineIndex(string text)
		{
			var starts = new List<int> { 0 };
			for (int i = 0; i < text.Length; i++)
				if (text[i] == '\n')
					starts.Add(i + 1);
			return starts.ToArray();
		}

		/// <summary>Converts a char index to 1-based (line, column).</summary>
		private static (int Line, int Col) GetLineCol(int[] lineStarts, int charIndex)
		{
			int lo = 0, hi = lineStarts.Length - 1;
			while (lo < hi)
			{
				int mid = (lo + hi + 1) / 2;
				if (lineStarts[mid] <= charIndex) lo = mid;
				else hi = mid - 1;
			}
			return (lo + 1, charIndex - lineStarts[lo] + 1);
		}

		/// <summary>Returns up to `radius` visible characters around position `pos`.</summary>
		private static string GetContext(string text, int pos, int radius)
		{
			int start = Math.Max(0, pos - radius);
			int end = Math.Min(text.Length, pos + radius + 1);
			var sb = new StringBuilder();
			for (int i = start; i < end; i++)
			{
				int cp = char.ConvertToUtf32(text, i);
				bool surr = char.IsHighSurrogate(text[i]);
				if (ClassifyCodePoint(cp) == CharType.Normal)
					sb.Append(text[i]);
				if (surr) i++;
			}
			return sb.ToString();
		}

		private static string FormatPreview(List<byte> bytes)
		{
			if (bytes.Count == 0) return "(empty)";
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
			if (text.Length == 0) return false;
			int printable = text.Count(c => !char.IsControl(c));
			return (double)printable / text.Length > 0.5;
		}

		private static string? TryDecodeBase64(List<byte> bytes)
		{
			try
			{
				var b64 = Encoding.UTF8.GetString(bytes.ToArray()).Trim();
				if (b64.Length < 4) return null;

				// Validate base64 alphabet
				if (b64.Any(c => !char.IsLetterOrDigit(c) && c != '+' && c != '/' && c != '=' && !char.IsWhiteSpace(c)))
					return null;

				var decoded = Convert.FromBase64String(b64);
				var decodedText = Encoding.UTF8.GetString(decoded);

				if (IsMostlyPrintable(decodedText))
					return Truncate(decodedText, 160);

				// Binary base64 payload → show hex
				return Truncate("0x " + BitConverter.ToString(decoded).Replace("-", " "), 160);
			}
			catch
			{
				return null;
			}
		}

		private static string Truncate(string s, int max) =>
				s.Length <= max ? s : s[..max] + "…";
	}
}