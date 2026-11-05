# Contributing

- **Stdlib only, Python 3.10+.** No third-party dependencies.
- **Dry-run before a PR:** `python attack_sim.py --dry-run` must finish
  cleanly. CI must pass.
- **Commit messages:** `<type>: <description>`, where type is one of `feat`,
  `fix`, `refactor`, `docs`, `test`, `chore`, `perf`, `ci`.
- **New log formats:** verify that every new format parses on the target SIEM,
  and state the SIEM and version in the PR (e.g. "QRadar 7.6 CE").
- **Authorized lab use only.** See the warning in the [README](README.md) and
  the [security policy](SECURITY.md).
