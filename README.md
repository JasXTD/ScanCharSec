# ScanCharSecExploit

A WPF desktop application that detects and removes **hidden Unicode characters** embedded in source code files. These invisible characters — including variation selectors, bidi overrides (Trojan Source), zero-width chars, and invisible formatting — can be used to smuggle arbitrary data or manipulate code display in editors and code review tools.

## What It Does

Modern supply-chain attacks can hide malicious payloads inside source code using Unicode variation selectors (U+FE00–U+FE0F, U+E0100–U+E01EF). These characters are completely invisible in editors, terminals, and code review tools, but can encode arbitrary binary data byte-by-byte. Additionally, Trojan Source attacks (CVE-2021-42574) use bidi override characters to make code appear different from what it actually does. This tool scans your codebase to find and remove all of these threats.

## Screenshots
<img width="1920" height="1046" alt="image" src="https://github.com/user-attachments/assets/cc5ba04d-f39a-4dbf-8c47-229b6a724d8a" />

## Features

### Detection
- **Variation Selector Detection** — Identifies VS1–VS16 (U+FE00–U+FE0F) and supplemental VS (U+E0100–U+E01EF) characters used to encode hidden byte payloads
- **Trojan Source Detection (CVE-2021-42574)** — Detects bidi override characters (LRE, RLE, LRO, RLO, LRI, RLI, FSI, PDI) that can make code appear different from its actual logic
- **Zero-Width Character Detection** — Finds zero-width spaces (ZWSP), joiners (ZWJ, ZWNJ), word joiners, and stray BOMs
- **Invisible Formatting Detection** — Catches soft hyphens, combining grapheme joiners, Hangul fillers, and other invisible formatting characters
- **Suspicious Pattern Detection** — Regex-based detection of dangerous code patterns like `eval(Buffer.from(...))`, variation-selector decoder loops, and `new Function(...)` abuse in JS/TS files
- **GlassWorm IOC Detection** — Flags published GlassWorm indicators including the `lzcdrtfxyqiplpd` marker, known Solana wallet IOCs, home-directory `init.json` persistence references, Google Calendar C2 references, and Russian-locale evasion checks

### Analysis
- **Severity Classification** — Each finding is classified as Critical (bidi overrides, eval+decode combos), Warning (variation selectors, suspicious patterns), or Info (zero-width, invisible formatting)
- **Decoded Preview** — Shows what hidden VS bytes decode to: readable UTF-8 text when printable, or hex dump for binary data
- **Base64 Payload Detection** — Automatically detects when hidden bytes form valid base64 and decodes the inner payload
- **Suspicious Pattern Summary** — Names and describes each suspicious code pattern found, including GlassWorm-specific threat signals

### Remediation
- **Remove Selected** — Clean only the files you select in the results grid (supports multi-select with Ctrl+Click / Shift+Click). Only strips hidden characters from file content — files are never deleted
- **Remove All** — Clean all detected files at once. Only strips hidden characters — no files are deleted
- **Right-click Context Menu** — Copy decoded preview, copy file path, or trigger removal from the context menu

### UI
- **Severity-Colored Rows** — Results are color-coded by severity: red for Critical, orange for Warning, blue for Info
- **Resizable Log Panel** — Drag the splitter to resize the log panel
- **Non-blocking UI** — All scanning and removal runs on background threads with a progress bar and percentage updates
- **Live Logs** — Timestamped log output showing scan progress, per-file findings with severity, decoded payloads, and suspicious patterns
- **Taskbar Flash** — The window flashes in the taskbar when a scan completes

### Scanning
- **Fast Pre-Check** — Quickly skips files with no hidden characters or suspicious text needles before expensive full analysis, while still catching plain-text IOCs that do not rely on invisible Unicode
- **Recursive Source Code Scanning** — Scans entire directory trees focusing on source code files (100+ extensions: `.cs`, `.py`, `.js`, `.ts`, `.java`, `.cpp`, `.go`, `.rs`, `.html`, `.json`, `.yaml`, `.xml`, and more)
- **Parallel Processing** — Uses all CPU cores for scanning large codebases

## How It Works

The scanner operates in two passes per file:

1. **Hidden Character Detection** — Iterates every Unicode code-point in the file, classifying each as a variation selector, bidi override, zero-width character, invisible formatting, or normal. Variation selectors are decoded back to their hidden byte values (0–255) and reassembled into a payload preview.

2. **Suspicious Pattern Detection** — Runs regex-based pattern matching to find dangerous code constructs (e.g., `eval(Buffer.from(...))`, VS-decoder loops, `new Function(...)`) plus GlassWorm-specific indicators such as published wallet IOCs, persistence references, and locale-evasion logic.

Before either pass, a fast byte-level pre-check (`MayContainHiddenChars`) scans the raw file bytes for known UTF-8 sequences of hidden characters to skip clean files without the overhead of full UTF-16 decoding.

## Requirements

- Windows 10/11
- .NET 9.0

## Building

```bash
dotnet build
```

## Credits

Inspired by and based on the concept from [**charsec**](https://github.com/harttraveller/charsec) by [Hart Traveller](https://github.com/harttraveller) — a Python library for detecting and handling hidden Unicode character exploits. The detection logic was reimplemented in C# from scratch for this WPF application.
