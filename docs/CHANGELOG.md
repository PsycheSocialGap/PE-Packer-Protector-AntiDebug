# Changelog

## [2.0.0] - 2025-02-10

### Added
- Brotli compression engine (replaced raw LZMA)
- Self-extracting payload generation
- Resource packer with embedded key storage
- Module list unlinking for anti-dump
- Timing checks module (RDTSC, TickCount, QPC)
- Virtualization detection (VMware, VBox, QEMU, Hyper-V)
- PE relocation table parser and builder

### Changed
- Migrated to .NET 9
- Rewrote PE reader/writer for better section handling
- Improved header scrambler with Rich header support

## [1.0.0] - 2024-08-15

### Added
- Initial release
- LZMA section compression
- AES-256 section encryption
- Anti-debug (PEB, NtGlobalFlag, debug port, HWBP)
- Anti-dump (header erasure, SizeOfImage corruption)
- PE checksum calculation
- Header scrambling
