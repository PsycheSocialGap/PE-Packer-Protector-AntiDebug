# MalPacker

[![Build Status](https://img.shields.io/github/actions/workflow/status/maldev-research/MalPacker/build.yml?branch=main)](https://github.com/maldev-research/MalPacker/actions)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/maldev-research/MalPacker?style=social)](https://github.com/maldev-research/MalPacker)
[![.NET](https://img.shields.io/badge/.NET-9.0-purple)](https://dotnet.microsoft.com/)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-lightgrey)]()

> **PE Packer Protector | LZMA Compression + Section Encryption + Anti-Debug**

A comprehensive PE packer and protector implementing multi-layer compression, section-level AES encryption, header scrambling, and aggressive anti-analysis protections. Designed for malware research, binary protection studies, and understanding packer internals.

---

## Features

- **Compression Engine**
  - Brotli/LZMA-grade compression with size ratio tracking
  - Per-section compression with metadata preservation
  - Self-extracting payload generation

- **Section Encryption**
  - AES-256-CBC per-section encryption
  - Unique key per section for compartmentalization
  - Runtime decryption stub generation

- **Header Protection**
  - DOS stub randomization
  - Rich header scrambling
  - Debug directory nullification
  - Timestamp randomization

- **Anti-Debug Protections**
  - PEB.BeingDebugged check
  - NtGlobalFlag verification
  - Debug port detection (NtQueryInformationProcess)
  - Hardware breakpoint detection
  - Remote debugger detection

- **Anti-Dump**
  - PE header erasure at runtime
  - SizeOfImage corruption
  - Module list unlinking (PEB_LDR_DATA)

- **Anti-Tamper**
  - CRC32 section integrity verification
  - SHA-256 file hash checking
  - Embedded checksum stubs

- **Virtualization Detection**
  - VM process scanning (VMware, VBox, QEMU, Hyper-V)
  - VM driver file detection
  - Registry artifact checking
  - MAC address prefix analysis
  - System firmware vendor check

- **Timing Checks**
  - RDTSC-based timing detection
  - TickCount delta analysis
  - Performance counter anomaly detection
  - Stopwatch iteration counting

---

## Screenshots

![Packer Output](docs/screenshots/packer-output.png)
![Protection Layers](docs/screenshots/protection-diagram.png)

---

## Project Structure

```
src/MalPacker/
├── Core/                    # Packer engine, section manipulation, import rebuilding
├── Packing/                 # LZMA compression, section encryption, header scrambling
├── Protection/              # Anti-debug, anti-dump, anti-tamper, VM detection
├── PE/                      # PE reader/writer, section table, imports, relocations
├── Stub/                    # Unpacker stub, decompressor stub
├── Config/                  # Packer configuration
├── Models/                  # Data models (sections, imports)
└── Utils/                   # Alignment helpers, checksum calculation
```

---

## Build Instructions

### Prerequisites

- [.NET 9 SDK](https://dotnet.microsoft.com/download/dotnet/9.0)
- Windows 10/11 x64

### Build

```bash
dotnet restore
dotnet build -c Release
```

### Publish

```bash
dotnet publish -c Release -r win-x64 --self-contained -o publish/
```

---

## Usage

```bash
# Pack with all protections
MalPacker.exe target.exe --all --output protected.exe

# Compress only
MalPacker.exe target.exe --compress --output packed.exe

# Encrypt + Anti-debug
MalPacker.exe target.exe --encrypt --antidebug --output secured.exe

# Full protection suite
MalPacker.exe target.exe --compress --encrypt --antidebug --antidump --antitamper --scramble
```

### Options

| Flag | Description |
|------|-------------|
| `--output <path>` | Output file path |
| `--compress` | Enable Brotli/LZMA compression |
| `--encrypt` | Encrypt sections with AES-256 |
| `--antidebug` | Inject anti-debugging stubs |
| `--antidump` | Add anti-memory-dump protection |
| `--antitamper` | Add integrity verification |
| `--scramble` | Scramble PE headers |
| `--all` | Enable all protections |

---

## Disclaimer

This project is provided for **educational and authorized security research purposes only**. It is intended for:

- Understanding PE packer internals and binary protection mechanisms
- Malware analysis training and reverse engineering practice
- Security tool development and antivirus engine testing
- Academic research on software protection techniques

**Do NOT use this tool to protect malicious software or circumvent security controls on systems you do not own.** The authors assume no liability for misuse.

---

## License

MIT License - See [LICENSE](LICENSE) for details.
