# rst-attack-sim

A stdlib-only, multi-stage **intrusion simulator** that plays a realistic attack
chain as **syslog** into a SIEM, so you can watch real detection rules fire and
exercise your triage / investigation workflows against data that looks like a
genuine breach — not `logger "test"`.

Today it targets **IBM QRadar** with DSM formats verified to parse on 7.6 CE.
The design separates *scenario* (what the attacker does) from *format* (how each
device logs it), so other SIEMs (Splunk, Elastic) and, later, monitoring
platforms (Prometheus, Zabbix) are additional emitters over the same scenarios —
see [Roadmap](#roadmap).

> [!WARNING]
> **Authorized lab use only.** This tool fabricates attack telemetry — brute
> force, C2 beacons, credential dumps, exfiltration, log wiping. Point it only
> at a SIEM you own and are authorized to test, on an isolated lab network.
> It sends UDP syslog to a host/port you specify and does nothing else; it does
> not touch, scan, or exploit any real system. Don't aim it at production.

一句话：把一条**真实感的攻击链**以 syslog 打进 SIEM，让检测规则真的触发、让你的研判/调查流程有真数据可练。仅限授权的实验环境。

## Requirements

- Python 3.10+ (standard library only — no `pip install`)
- A reachable SIEM syslog collector (UDP). For QRadar: a log source per host,
  see [QRadar setup](#qradar-setup).

## Quick start

```bash
python attack_sim.py --host 10.0.0.5              # whole chain into 10.0.0.5:514, ~15 min real time
python attack_sim.py --host 10.0.0.5 --speed 8    # same chain, 8x faster
python attack_sim.py --stage 1                    # just the perimeter scan
python attack_sim.py --stage 9 --speed 5          # the second, independent incident
python attack_sim.py --dry-run                    # print every line, send nothing
```

| flag | meaning |
|---|---|
| `--host` | syslog collector IP (default `127.0.0.1`) |
| `--port` | UDP port (default `514`) |
| `--stage N` | run one stage only (see table); omit for the full chain |
| `--speed X` | divide every inter-event pause by X |
| `--dry-run` | print lines to stdout, send nothing |

## The scenario

A targeted intrusion of a small enterprise, stage by stage. Timings and
thresholds are tuned so the stages that *should* raise an offense on QRadar CE
defaults actually do.

| stage | what happens | raises an offense on CE? |
|---|---|---|
| 1 recon | external nmap of the perimeter; the edge ASA denies ~480 connections | ✅ Excessive Firewall Denies / Host Port Scan |
| 2 initial access | `j.chen` opens an invoice `.docm` on WS-FIN-07; macro spawns encoded PowerShell | context only |
| 3 C2 beacon | WS-FIN-07 heartbeats to `185.220.101.4:443` every 60s (runs under later stages) | context only |
| 4 credentials | LSASS dump on the workstation, then a password spray against DC01 | ✅ Multiple Login Failures |
| 5 lateral | `svc_backup` PsExec onto FILE01/DC01; SSH brute then key login on srv-app01 | ✅ Login Failures Followed By Success |
| 6 persistence | sudo→root, new `sysadm` in the sudo group, cron backdoor, C2 IP logs straight in | context only |
| 7 exfil | robocopy over the Finance share, 2.3 GB to the C2, plus an SSH tunnel | context only |
| 8 anti-forensics | audit log cleared on DC01, audit policy gutted, `/var/log` wiped on srv-app01 | context only |
| 9 incident B | a **second, unrelated** actor `91.240.118.66`: DMZ scan, SSH brute of `oracle`, rogue-host RDP spray of DC01 | ✅ several distinct offenses |

The "context only" stages don't fire a rule by themselves — they are the
evidence an analyst (or an AI copilot) has to pull from the SIEM to reconstruct
the whole chain. That is deliberate: it's what makes triage and investigation a
real test rather than a rule-lit checkbox.

### Actors

```
45.142.212.100   external attacker (main chain)      185.220.101.4   C2
91.240.118.66    external attacker (incident B)
WS-FIN-07 10.10.20.57   patient zero (j.chen)        DC01 10.10.1.10   domain controller
FILE01 10.10.1.20   file server                      srv-app01 10.10.2.15   Linux app server
```

## DSM / log-source mapping (QRadar)

Every line uses a QRadar-native DSM format verified to parse on 7.6 CE:

| host | DSM (log source type) | format | events |
|---|---|---|---|
| fw-edge | Cisco ASA (auto-discovered) | `%ASA-4-106023 / 6-302013 / 6-302014` | Deny / Session Built / Teardown |
| fw-pan | Palo Alto PA Series (auto) | PAN-OS 10 TRAFFIC csv | Session Allowed |
| DC01, FILE01, WS-FIN-07 | Microsoft Windows Security Event Log | Snare tab format | 4624/4625/4672/4688/7045/4663/1102/4719 |
| srv-app01 | Linux OS (auto) | sshd / sudo / useradd / CRON | SSH failed/accepted, sudo, useradd, cron |

### QRadar setup

- **Auto-discovered sources** (Cisco ASA, Palo Alto, Linux OS) appear on their
  own after ~25 lines; the first batch lands in "SIM Generic" until then.
- **Windows sources must exist first** — Snare auto-discovery needs 25+ lines and
  the first batch is misrouted. Pre-create each with the API before sending:
  `POST /api/config/event_sources/log_source_management/log_sources` with
  `type_id 12`, `protocol_type_id 0`, `identifier = hostname`, then
  `POST /api/staged_config/deploy_status {"type":"INCREMENTAL"}`.
- Turn **event coalescing off** on the sim sources so `eventcount` equals the
  number of lines sent.
- The Linux OS DSM sometimes mis-detects as VMware; fix the `type_id` via the API
  before sending.

## Roadmap

The current script is one QRadar-specific scenario file. The extraction target:

- **scenarios** — MITRE-tagged attack techniques, platform-independent
- **emitters** — syslog (SIEM), Prometheus remote-write / textfile, Zabbix trapper
- **format packs** — one scenario rendered as Cisco ASA (QRadar), CIM (Splunk),
  ECS (Elastic), or synthetic metric anomalies (Prometheus/Zabbix)

Contributions welcome once the plugin boundaries land.

## License

MIT — see [LICENSE](LICENSE).
