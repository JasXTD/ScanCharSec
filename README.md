# ScanCharSecExploit

A WPF desktop application that detects and removes **hidden Unicode characters** embedded in source code files. These invisible variation selector characters (U+FE00–U+FE0F, U+E0100–U+E01EF) can be used to smuggle arbitrary data — including executable code — into seemingly normal text files.

## What It Does

Modern supply-chain attacks can hide malicious payloads inside source code using Unicode variation selectors. These characters are completely invisible in editors, terminals, and code review tools, but can encode arbitrary binary data byte-by-byte. This tool scans your codebase to find and remove them.

## Screenshots
<img width="1920" height="1046" alt="image" src="https://github.com/user-attachments/assets/cc5ba04d-f39a-4dbf-8c47-229b6a724d8a" />

## Features

- **Recursive Source Code Scanning** — Scans entire directory trees (e.g. `C:\Users\...\repos`) focusing only on source code files (100+ extensions: `.cs`, `.py`, `.js`, `.ts`, `.java`, `.cpp`, `.go`, `.rs`, `.html`, `.json`, `.yaml`, `.xml`, and more)
- **Hidden Data Detection** — Identifies files containing Unicode variation selector characters that could encode hidden payloads
- **Decoded Preview** — Shows what the hidden bytes decode to: readable UTF-8 text when printable, or hex dump (`0x AB CD ...`) for binary data
- **Remove Hidden Data** — Three removal options:
  - **Remove Selected** — Clean only the files you select in the results grid (supports multi-select with Ctrl+Click / Shift+Click)
  - **Remove All** — Clean all detected files at once
  - **Right-click Context Menu** — Both options available via right-click on the results grid
- **Non-blocking UI** — All scanning and removal runs on background threads; the UI stays responsive with a progress bar and percentage updates
- **Live Logs Panel** — Timestamped log output showing real-time scan progress, warnings for detected files, and removal confirmations
- **Taskbar Flash** — The window flashes in the taskbar when a scan completes, so you can work on other things while it runs

## How It Works

Unicode variation selectors (VS1–VS16: U+FE00–U+FE0F, VS17–VS256: U+E0100–U+E01EF) are zero-width characters normally used to select glyph variants. However, since there are 256 of them, each one can represent a byte value (0–255), allowing any arbitrary data to be encoded invisibly after a normal carrier character.

This tool scans each source file for these variation selectors. When found, it:
1. Reports the file path and count of hidden bytes
2. Attempts to decode the hidden bytes as UTF-8 text for a preview
3. Falls back to a hex dump if the data isn't printable text
4. Optionally strips all variation selectors from the file to clean it

## Requirements

- Windows 10/11
- .NET 9.0

## Building

```bash
dotnet build
```

## Credits

Inspired by and based on the concept from [**charsec**](https://github.com/harttraveller/charsec) by [Hart Traveller](https://github.com/harttraveller) — a Python library for detecting and handling hidden Unicode character exploits. The detection logic was reimplemented in C# from scratch for this WPF application.
