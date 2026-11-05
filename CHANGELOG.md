# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.1.1] - 2026-11-06

### Added

- `--port` validation.
- Per-log-source line-count summary on stderr at the end of a run, to compare
  against QRadar `eventcount`.

### Changed

- CI workflow token restricted to `contents: read`.

### Fixed

- `--speed` is validated; zero, negative, and non-numeric values are rejected.
- `--dry-run` prints the full line instead of truncating at 160 characters.
- `--stage 3` runs the C2 beacon on its own (it was previously rejected).
- The record counter is thread-safe.
- Clean exit on Ctrl+C.

## [0.1.0] - 2026-11-06

### Added

- Initial release: a stdlib-only, multi-stage intrusion simulator that sends a
  nine-stage attack chain as UDP syslog into a lab SIEM.
- QRadar-native DSM formats verified to parse on 7.6 CE: Cisco ASA, Palo Alto
  PAN-OS, Windows Security Event Log (Snare), and Linux OS.
- `--host`, `--port`, `--stage`, `--speed`, and `--dry-run` flags; host defaults
  to `127.0.0.1`.
- CI that dry-runs the full chain and each stage on Python 3.10 and 3.13.

[Unreleased]: https://github.com/sooua/rst-attack-sim/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/sooua/rst-attack-sim/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/sooua/rst-attack-sim/releases/tag/v0.1.0
