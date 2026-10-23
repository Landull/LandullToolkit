#!/usr/bin/env python3
"""
sysaudit - one-shot system report: hardware, OS, security posture, software.

Collects the facts you'd want when handing over a PC, onboarding a
client machine or starting a support ticket: OS and build, CPU, RAM,
GPU, disks, network addresses, uptime, installed software, and a quick
security posture check (antivirus, firewall, disk encryption, SMBv1,
UAC, patch age, end-of-support OS, pending updates).

Output as a terminal report, JSON, or a standalone HTML page you can
send to a client. Works on Windows and Linux (macOS: basics only).

Standard library only. Python 3.8+.
"""

import argparse
import html
import json
import os
import platform
import re
import shutil
import socket
import string
import subprocess
import sys
from datetime import datetime, timezone

__version__ = "1.0.0"

PASS, WARN, FAIL, INFO = "PASS", "WARN", "FAIL", "INFO"
NOW = datetime.now(timezone.utc)

REAL_FS = {"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "ntfs", "ntfs3", "vfat",
           "exfat", "hfs", "apfs", "jfs", "reiserfs", "fuseblk"}

# Windows builds that are out of support for consumer (Home/Pro) editions
WINDOWS_EOL = {
    "10.0.10240": "2017", "10.0.10586": "2017", "10.0.14393": "2019", "10.0.15063": "2019",
    "10.0.16299": "2020", "10.0.17134": "2020", "10.0.17763": "2021", "10.0.18362": "2020",
    "10.0.18363": "2022", "10.0.19041": "2021", "10.0.19042": "2023", "10.0.19043": "2022",
    "10.0.19044": "2024", "10.0.19045": "Oct 2025", "10.0.22000": "Oct 2024",
    "10.0.22621": "Oct 2025",
}


def run(cmd, timeout=90):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                             encoding="utf-8", errors="replace")
    except (OSError, subprocess.TimeoutExpired):
        return None
    return out.stdout if out.returncode == 0 else None


def human_bytes(n):
    if n is None:
        return "?"
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if n < 1024 or unit == "PB":
            return f"{n:.0f} {unit}" if unit in ("B", "KB") else f"{n:.1f} {unit}"
        n /= 1024


def human_duration(seconds):
    days, rem = divmod(int(seconds), 86400)
    hours, rem = divmod(rem, 3600)
    return f"{days}d {hours}h {rem // 60}m"


def parse_iso(value):
    if not value:
        return None
    try:
        value = re.sub(r"(\.\d{6})\d+", r"\1", str(value))  # .NET gives 7 fractional digits
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


# ---- Disks (all platforms) ---------------------------------------------------

def volumes():
    paths = []
    if os.name == "nt":
        paths = [f"{d}:\\" for d in string.ascii_uppercase if os.path.exists(f"{d}:\\")]
    elif os.path.exists("/proc/mounts"):
        seen = set()
        with open("/proc/mounts") as fh:
            for line in fh:
                dev, mnt, fs = line.split()[:3]
                if fs in REAL_FS and dev not in seen and not mnt.startswith(("/snap", "/boot/efi")):
                    seen.add(dev)
                    paths.append(mnt.replace("\\040", " "))
    else:
        # macOS: real writable volumes only; skip mounted installer images (read-only .dmg)
        paths = ["/"]
        for line in (run(["mount"]) or "").splitlines():
            m = re.match(r"^\S+ on (/Volumes/.+?) \((.*)\)$", line)
            if m and "read-only" not in m.group(2) and "nobrowse" not in m.group(2):
                paths.append(m.group(1))
    out = []
    seen_sizes = set()
    for p in paths:
        try:
            u = shutil.disk_usage(p)
        except OSError:
            continue  # e.g. empty card reader
        if (u.total, u.free) in seen_sizes:
            continue  # same APFS container under another name (e.g. "Macintosh HD")
        seen_sizes.add((u.total, u.free))
        out.append({"mount": p, "total": u.total, "used": u.used, "free": u.free,
                    "percent_used": round(u.used / u.total * 100, 1) if u.total else 0})
    return out


def fqdn():
    """Fully qualified name, or None when it's only localhost or a reverse-DNS artifact."""
    name = socket.getfqdn()
    if "." not in name or name.endswith((".arpa", ".local", "localhost", ".localdomain")) or name == "localhost":
        return None
    return name


def ip_addresses():
    addrs = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            addrs.add(info[4][0])
    except socket.gaierror:
        pass
    try:  # primary outbound IP; UDP connect sends no packets
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            addrs.add(s.getsockname()[0])
    except OSError:
        pass
    return sorted(a for a in addrs if not a.startswith(("127.", "::1", "fe80")))


# ---- Windows -----------------------------------------------------------------

WIN_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}
$os = Get-CimInstance Win32_OperatingSystem
$o.os = [ordered]@{ Caption=$os.Caption; Version=$os.Version; Build=$os.BuildNumber;
  DisplayVersion=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').DisplayVersion;
  LastBoot=$os.LastBootUpTime.ToUniversalTime().ToString('o'); InstallDate=$os.InstallDate.ToUniversalTime().ToString('o');
  TotalRAM=[int64]$os.TotalVisibleMemorySize*1024; FreeRAM=[int64]$os.FreePhysicalMemory*1024 }
$cs = Get-CimInstance Win32_ComputerSystem
$o.system = [ordered]@{ Manufacturer=$cs.Manufacturer; Model=$cs.Model; Domain=$cs.Domain; PartOfDomain=$cs.PartOfDomain }
$b = Get-CimInstance Win32_BIOS
$o.bios = [ordered]@{ Version=$b.SMBIOSBIOSVersion; Serial=$b.SerialNumber }
$o.cpu = @(Get-CimInstance Win32_Processor | ForEach-Object { [ordered]@{ Name=$_.Name.Trim(); Cores=$_.NumberOfCores; Threads=$_.NumberOfLogicalProcessors } })
$o.gpu = @(Get-CimInstance Win32_VideoController | ForEach-Object { [ordered]@{ Name=$_.Name; Driver=$_.DriverVersion } })
$o.physical_disks = @(Get-PhysicalDisk | ForEach-Object { [ordered]@{ Model=$_.FriendlyName; Size=$_.Size; Media="$($_.MediaType)"; Health="$($_.HealthStatus)" } })
$mp = Get-MpComputerStatus
if ($mp) { $o.defender = [ordered]@{ Enabled=$mp.AntivirusEnabled; RealTime=$mp.RealTimeProtectionEnabled;
  SignaturesUpdated=$mp.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('o') } }
$o.av_products = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object { $_.displayName })
$o.firewall = @(Get-NetFirewallProfile | ForEach-Object { [ordered]@{ Name=$_.Name; Enabled=[bool]$_.Enabled } })
$o.bitlocker = @(Get-BitLockerVolume | ForEach-Object { [ordered]@{ Mount=$_.MountPoint; Protection="$($_.ProtectionStatus)"; Type="$($_.VolumeType)" } })
$o.smb1 = (Get-SmbServerConfiguration).EnableSMB1Protocol
$o.uac = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA
$o.secure_boot = Confirm-SecureBootUEFI
$hf = Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($hf) { $o.last_hotfix = [ordered]@{ Id=$hf.HotFixID; InstalledOn=$hf.InstalledOn.ToUniversalTime().ToString('o') } }
$o.reboot_pending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
  (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
$o | ConvertTo-Json -Depth 5
"""


def windows_software():
    import winreg
    keys = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    found = {}
    for hive, path in keys:
        try:
            root = winreg.OpenKey(hive, path)
        except OSError:
            continue
        for i in range(winreg.QueryInfoKey(root)[0]):
            try:
                sub = winreg.OpenKey(root, winreg.EnumKey(root, i))
            except OSError:
                continue

            def val(name):
                try:
                    return winreg.QueryValueEx(sub, name)[0]
                except OSError:
                    return None
            name = val("DisplayName")
            if not name or val("SystemComponent") == 1 or val("ParentKeyName"):
                continue
            key = (name.strip(), str(val("DisplayVersion") or ""))
            found[key] = {"name": key[0], "version": key[1], "publisher": val("Publisher") or "",
                          "installed": val("InstallDate") or ""}
    return sorted(found.values(), key=lambda s: s["name"].lower())


def collect_windows():
    ps = shutil.which("powershell") or shutil.which("pwsh")
    raw = run([ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", WIN_PS]) if ps else None
    w = json.loads(raw) if raw else {}
    os_info = w.get("os", {})
    boot = parse_iso(os_info.get("LastBoot"))
    info = {
        "os": f"{os_info.get('Caption', platform.platform())} {os_info.get('DisplayVersion') or ''}".strip(),
        "os_version": os_info.get("Version", platform.version()),
        "manufacturer": w.get("system", {}).get("Manufacturer"),
        "model": w.get("system", {}).get("Model"),
        "domain": w.get("system", {}).get("Domain"),
        "bios": w.get("bios", {}).get("Version"),
        "serial": w.get("bios", {}).get("Serial"),
        "cpu": [f"{c['Name']} ({c['Cores']}C/{c['Threads']}T)" for c in as_list(w.get("cpu"))],
        "gpu": [f"{g['Name']} (driver {g.get('Driver')})" for g in as_list(w.get("gpu"))],
        "ram_total": os_info.get("TotalRAM"),
        "ram_free": os_info.get("FreeRAM"),
        "physical_disks": [f"{d['Model']} {human_bytes(d.get('Size'))} {d.get('Media', '')} "
                           f"({d.get('Health', '?')})" for d in as_list(w.get("physical_disks"))],
        "boot_time": boot,
        "installed_on": parse_iso(os_info.get("InstallDate")),
    }
    try:
        software = windows_software()
    except Exception:
        software = []

    checks = []
    if not raw:
        checks.append((WARN, "Collection", "PowerShell queries failed; hardware and security details missing"))
    build = ".".join(str(os_info.get("Version", "")).split(".")[:3])
    eol = WINDOWS_EOL.get(build)
    if eol:
        checks.append((FAIL, "OS support", f"{info['os']} (build {build}) went out of support {eol}"))
    elif build:
        checks.append((PASS, "OS support", f"Build {build} is supported"))

    d = w.get("defender")
    av = [a for a in as_list(w.get("av_products")) if a]
    if d and d.get("RealTime"):
        checks.append((PASS, "Antivirus", "Microsoft Defender real-time protection on"))
        sig = parse_iso(d.get("SignaturesUpdated"))
        if sig and (NOW - sig).days > 7:
            checks.append((WARN, "AV signatures", f"Last updated {(NOW - sig).days} days ago"))
    elif av and any("defender" not in a.lower() for a in av):
        checks.append((PASS, "Antivirus", ", ".join(av)))
    elif raw:
        checks.append((FAIL, "Antivirus", "No active real-time antivirus found"))

    fw = as_list(w.get("firewall"))
    off = [p["Name"] for p in fw if not p.get("Enabled")]
    if fw:
        checks.append((FAIL, "Firewall", f"Disabled for {', '.join(off)} profile(s)") if off
                      else (PASS, "Firewall", "On for all profiles"))

    bl = as_list(w.get("bitlocker"))
    os_vol = next((v for v in bl if str(v.get("Type")).lower().startswith("operatingsystem")
                   or v.get("Mount") == "C:"), None)
    if os_vol:
        checks.append((PASS, "Disk encryption", "BitLocker on for the OS drive") if os_vol.get("Protection") == "On"
                      else (WARN, "Disk encryption", "BitLocker off on the OS drive"))
    elif raw:
        checks.append((INFO, "Disk encryption", "BitLocker status unavailable (run as Administrator, or Home edition)"))

    if w.get("smb1") is True:
        checks.append((FAIL, "SMBv1", "SMBv1 server is enabled (WannaCry-era protocol)"))
    elif w.get("smb1") is False:
        checks.append((PASS, "SMBv1", "Disabled"))
    if w.get("uac") == 0:
        checks.append((FAIL, "UAC", "User Account Control is turned off"))
    elif w.get("uac") == 1:
        checks.append((PASS, "UAC", "On"))
    if w.get("secure_boot") is True:
        checks.append((PASS, "Secure Boot", "On"))
    elif w.get("secure_boot") is False:
        checks.append((WARN, "Secure Boot", "Off"))

    hf = w.get("last_hotfix")
    if hf:
        when = parse_iso(hf.get("InstalledOn"))
        if when:
            age = (NOW - when).days
            checks.append((WARN if age > 45 else PASS, "Patching",
                           f"Last update {hf['Id']} installed {age} days ago"))
    if w.get("reboot_pending"):
        checks.append((WARN, "Reboot", "A reboot is pending to finish updates"))
    return info, checks, software


# ---- Linux -------------------------------------------------------------------

def read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read().strip()
    except OSError:
        return None


def collect_linux():
    rel = {}
    for line in (read("/etc/os-release") or "").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            rel[k] = v.strip('"')
    cpuinfo = read("/proc/cpuinfo") or ""
    model = re.search(r"model name\s*:\s*(.+)", cpuinfo)
    sockets_cores = {(m.group(1), m.group(2)) for m in
                     re.finditer(r"physical id\s*:\s*(\d+)[\s\S]*?core id\s*:\s*(\d+)", cpuinfo)}
    mem = {m.group(1): int(m.group(2)) * 1024 for m in
           re.finditer(r"^(\w+):\s+(\d+) kB", read("/proc/meminfo") or "", re.M)}
    uptime = float((read("/proc/uptime") or "0").split()[0])
    gpus = [l.split(": ", 1)[-1] for l in (run(["lspci"]) or "").splitlines()
            if re.search(r"VGA|3D controller|Display controller", l)]
    disks = []
    lsblk = run(["lsblk", "-dnbo", "NAME,SIZE,ROTA,MODEL,TYPE"]) or ""
    for line in lsblk.splitlines():
        parts = line.split(None, 4)
        if len(parts) >= 3 and "disk" in line and parts[1].isdigit() and int(parts[1]) > 0:
            model_name = parts[3] if len(parts) > 4 else parts[0]
            disks.append(f"{model_name.replace(' disk', '')} {human_bytes(int(parts[1]))} "
                         f"{'HDD' if parts[2] == '1' else 'SSD'}")
    threads = os.cpu_count()
    info = {
        "os": rel.get("PRETTY_NAME", platform.platform()),
        "os_version": platform.release(),
        "manufacturer": read("/sys/class/dmi/id/sys_vendor"),
        "model": read("/sys/class/dmi/id/product_name"),
        "domain": fqdn(),
        "bios": read("/sys/class/dmi/id/bios_version"),
        "serial": read("/sys/class/dmi/id/product_serial"),  # root only
        "cpu": [f"{model.group(1).strip() if model else platform.processor()} "
                f"({len(sockets_cores) or '?'}C/{threads}T)"],
        "gpu": gpus,
        "ram_total": mem.get("MemTotal"),
        "ram_free": mem.get("MemAvailable"),
        "physical_disks": disks,
        "boot_time": datetime.fromtimestamp(NOW.timestamp() - uptime, tz=timezone.utc),
        "installed_on": None,
    }

    checks = []
    eol = rel.get("VERSION_ID")
    if rel.get("ID") == "ubuntu" and eol and eol in ("14.04", "16.04", "18.04", "20.04", "23.04", "23.10", "24.10"):
        checks.append((FAIL if eol < "20.04" else WARN, "OS support",
                       f"Ubuntu {eol} is past standard support"))

    if shutil.which("apt"):
        out = run(["apt", "list", "--upgradable"], timeout=60) or ""
        pending = [l for l in out.splitlines() if "/" in l and "upgradable" in l]
        sec = [l for l in pending if "-security" in l]
        checks.append((WARN if pending else PASS, "Updates",
                       f"{len(pending)} package update(s) pending ({len(sec)} security)" if pending
                       else "No pending updates (as of last apt update)"))
    elif shutil.which("dnf"):
        out = subprocess.run(["dnf", "-q", "check-update"], capture_output=True, text=True).stdout
        n = len([l for l in out.splitlines() if l and not l.startswith(" ")])
        checks.append((WARN if n else PASS, "Updates", f"{n} package update(s) pending" if n else "Up to date"))
    if os.path.exists("/var/run/reboot-required"):
        checks.append((WARN, "Reboot", "A reboot is required to finish updates"))

    fw = None
    if shutil.which("ufw"):
        out = run(["ufw", "status"])
        fw = None if out is None else "Status: active" in out
    if fw is None and shutil.which("firewall-cmd"):
        fw = (run(["firewall-cmd", "--state"]) or "").strip() == "running"
    if fw is None and shutil.which("nft"):
        out = run(["nft", "list", "ruleset"])
        fw = None if out is None else bool(out.strip())
    if fw is True:
        checks.append((PASS, "Firewall", "Active"))
    elif fw is False:
        checks.append((WARN, "Firewall", "No active firewall"))
    else:
        checks.append((INFO, "Firewall", "Couldn't determine (run as root)"))

    if (run(["lsblk", "-no", "TYPE"]) or "").count("crypt"):
        checks.append((PASS, "Disk encryption", "LUKS encrypted volume present"))
    else:
        checks.append((INFO, "Disk encryption", "No LUKS volumes found"))

    software = []
    if shutil.which("dpkg-query"):
        out = run(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Maintainer}\n"]) or ""
        software = [dict(zip(("name", "version", "publisher"), l.split("\t"))) for l in out.splitlines() if l]
    elif shutil.which("rpm"):
        out = run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n"]) or ""
        software = [dict(zip(("name", "version", "publisher"), l.split("\t"))) for l in out.splitlines() if l]
    return info, checks, sorted(software, key=lambda s: s["name"].lower())


def collect_mac():
    sp = run(["sw_vers", "-productVersion"]) or ""
    info = {"os": f"macOS {sp.strip()}", "os_version": platform.release(),
            "manufacturer": "Apple", "model": (run(["sysctl", "-n", "hw.model"]) or "").strip(),
            "domain": fqdn(), "bios": None, "serial": None,
            "cpu": [(run(["sysctl", "-n", "machdep.cpu.brand_string"]) or platform.processor()).strip()],
            "gpu": [], "ram_total": int((run(["sysctl", "-n", "hw.memsize"]) or "0").strip() or 0),
            "ram_free": None, "physical_disks": [], "boot_time": None, "installed_on": None}
    checks = []
    fv = run(["fdesetup", "status"]) or ""
    if fv:
        checks.append((PASS, "Disk encryption", "FileVault on") if "On" in fv
                      else (WARN, "Disk encryption", "FileVault off"))
    fw = run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"]) or ""
    if fw:
        checks.append((PASS, "Firewall", "On") if re.search(r"enabled|State = [12]", fw)
                      else (WARN, "Firewall", "macOS firewall is off (System Settings > Network > Firewall)"))
    sip = run(["csrutil", "status"]) or ""
    if sip:
        checks.append((PASS, "SIP", "System Integrity Protection on") if "enabled" in sip
                      else (FAIL, "SIP", "System Integrity Protection is disabled"))
    gk = subprocess.run(["spctl", "--status"], capture_output=True, text=True).stdout \
        if shutil.which("spctl") else ""
    if gk:
        checks.append((PASS, "Gatekeeper", "On") if "enabled" in gk
                      else (WARN, "Gatekeeper", "Gatekeeper is off; unsigned apps run without warning"))
    apps = sorted(n[:-4] for n in os.listdir("/Applications") if n.endswith(".app")) \
        if os.path.isdir("/Applications") else []
    return info, checks, [{"name": a, "version": "", "publisher": ""} for a in apps]


# ---- Report ------------------------------------------------------------------

def collect():
    system = platform.system()
    if system == "Windows":
        info, checks, software = collect_windows()
    elif system == "Linux":
        info, checks, software = collect_linux()
    elif system == "Darwin":
        info, checks, software = collect_mac()
    else:
        raise RuntimeError(f"Unsupported OS: {system}")

    info["hostname"] = platform.node()
    info["arch"] = platform.machine()
    info["ip_addresses"] = ip_addresses()
    info["volumes"] = volumes()
    if info.get("boot_time"):
        up = (NOW - info["boot_time"]).total_seconds()
        info["uptime"] = human_duration(up)
        if up > 30 * 86400:
            checks.append((WARN, "Uptime", f"Up {info['uptime']}; updates may be waiting on a reboot"))
    for v in info["volumes"]:
        pct = v["percent_used"]
        if pct >= 90:
            checks.append((FAIL, f"Disk {v['mount']}", f"{pct}% full ({human_bytes(v['free'])} free)"))
        elif pct >= 80:
            checks.append((WARN, f"Disk {v['mount']}", f"{pct}% full ({human_bytes(v['free'])} free)"))
    if info.get("ram_total") and info["ram_total"] < 8 * 1024 ** 3 * 0.95:
        checks.append((INFO, "Memory", f"{human_bytes(info['ram_total'])} RAM; under 8 GB is tight for modern Windows"))

    return {
        "generated_at": NOW.isoformat(timespec="seconds"),
        "tool": f"sysaudit {__version__}",
        "system": info,
        "checks": [{"status": s, "check": c, "detail": d} for s, c, d in checks],
        "software": software,
    }


def summary_rows(info):
    rows = [
        ("Hostname", info.get("hostname")),
        ("OS", info.get("os")),
        ("Version", info.get("os_version")),
        ("Architecture", info.get("arch")),
        ("Make / model", " ".join(x for x in (info.get("manufacturer"), info.get("model")) if x)),
        ("Serial", info.get("serial")),
        ("BIOS", info.get("bios")),
        ("Domain", info.get("domain")),
        ("CPU", "; ".join(info.get("cpu") or [])),
        ("GPU", "; ".join(info.get("gpu") or [])),
        ("RAM", (f"{human_bytes(info.get('ram_total'))} total"
                 + (f", {human_bytes(info['ram_free'])} free" if info.get("ram_free") else ""))
            if info.get("ram_total") else None),
        ("Physical disks", "; ".join(info.get("physical_disks") or [])),
        ("IP addresses", ", ".join(info.get("ip_addresses") or [])),
        ("Uptime", info.get("uptime")),
        ("OS installed", info["installed_on"].date().isoformat() if info.get("installed_on") else None),
    ]
    return [(k, v) for k, v in rows if v]


def color(status, enabled):
    if not enabled:
        return status
    return f"\033[{ {PASS: '32', WARN: '33', FAIL: '31', INFO: '36'}[status] }m{status}\033[0m"


def print_report(report, show_software, use_color):
    info = report["system"]
    print("SYSTEM")
    for k, v in summary_rows(info):
        print(f"  {k:<15} {v}")
    print("\nVOLUMES")
    for v in info["volumes"]:
        bar = "#" * int(v["percent_used"] / 5)
        print(f"  {v['mount']:<15} {human_bytes(v['used']):>9} / {human_bytes(v['total']):<9} "
              f"[{bar:<20}] {v['percent_used']}%")
    print("\nSECURITY & HEALTH")
    order = {FAIL: 0, WARN: 1, INFO: 2, PASS: 3}
    for c in sorted(report["checks"], key=lambda c: order[c["status"]]):
        print(f"  [{color(c['status'], use_color)}] {c['check']:<16} {c['detail']}")
    print(f"\nSOFTWARE  ({len(report['software'])} installed)")
    if show_software:
        for s in report["software"]:
            print(f"  {s['name'][:50]:<50} {s.get('version', '')[:20]}")
    elif report["software"]:
        print("  (use --software to list, or -f json / -f html for the full inventory)")


def html_report(report):
    info = report["system"]
    e = html.escape
    badge = {PASS: "#1a7f37", WARN: "#9a6700", FAIL: "#cf222e", INFO: "#0969da"}
    rows = "".join(f"<tr><th>{e(k)}</th><td>{e(str(v))}</td></tr>" for k, v in summary_rows(info))
    vols = "".join(
        f"<tr><td>{e(v['mount'])}</td><td>{human_bytes(v['used'])} / {human_bytes(v['total'])}</td>"
        f"<td><div class=bar><span style='width:{v['percent_used']}%;background:"
        f"{badge[FAIL] if v['percent_used'] >= 90 else badge[WARN] if v['percent_used'] >= 80 else badge[PASS]}'>"
        f"</span></div></td><td>{v['percent_used']}%</td></tr>" for v in info["volumes"])
    order = {FAIL: 0, WARN: 1, INFO: 2, PASS: 3}
    checks = "".join(
        f"<tr><td><b style='color:{badge[c['status']]}'>{c['status']}</b></td><td>{e(c['check'])}</td>"
        f"<td>{e(c['detail'])}</td></tr>" for c in sorted(report["checks"], key=lambda c: order[c["status"]]))
    sw = "".join(f"<tr><td>{e(s['name'])}</td><td>{e(s.get('version', ''))}</td><td>{e(s.get('publisher', ''))}</td></tr>"
                 for s in report["software"])
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>System report: {e(info.get('hostname', ''))}</title>
<style>
body{{font:14px/1.5 system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#1f2328}}
h1{{margin-bottom:0}} .sub{{color:#656d76;margin-top:.25rem}} h2{{margin-top:2rem;border-bottom:1px solid #d0d7de}}
table{{border-collapse:collapse;width:100%}} th,td{{text-align:left;padding:.35rem .6rem;border-bottom:1px solid #eaeef2;vertical-align:top}}
th{{width:170px;color:#656d76;font-weight:500}} .bar{{background:#eaeef2;height:10px;border-radius:5px;width:220px}}
.bar span{{display:block;height:10px;border-radius:5px}} details summary{{cursor:pointer;margin:.5rem 0}}
@media print{{details{{display:block}}}}
</style></head><body>
<h1>{e(info.get('hostname', 'System report'))}</h1>
<p class="sub">Generated {e(report['generated_at'])} by {e(report['tool'])}</p>
<h2>System</h2><table>{rows}</table>
<h2>Storage</h2><table>{vols}</table>
<h2>Security &amp; health</h2><table>{checks}</table>
<h2>Installed software ({len(report['software'])})</h2>
<details><summary>Show list</summary><table><tr><th>Name</th><th>Version</th><th>Publisher</th></tr>{sw}</table></details>
</body></html>"""


def to_json(report):
    def conv(o):
        if isinstance(o, datetime):
            return o.isoformat()
        raise TypeError(type(o))
    return json.dumps(report, indent=2, default=conv)


def parse_args(argv):
    p = argparse.ArgumentParser(prog="sysaudit",
                                description="One-shot system report: hardware, OS, security posture, software.")
    p.add_argument("-s", "--software", action="store_true", help="list installed software in the terminal report")
    p.add_argument("-f", "--format", choices=("table", "json", "html"), default="table", help="output format")
    p.add_argument("-o", "--output", metavar="FILE", help="write JSON or HTML to a file")
    p.add_argument("--no-color", action="store_true", help="plain output without colors")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        report = collect()
    except RuntimeError as err:
        print(f"[!] {err}", file=sys.stderr)
        return 2

    if args.format == "table" and not args.output:
        print_report(report, args.software, sys.stdout.isatty() and not args.no_color)
    else:
        fmt = args.format
        if fmt == "table":
            fmt = "html" if args.output and args.output.lower().endswith((".html", ".htm")) else "json"
        data = html_report(report) if fmt == "html" else to_json(report)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(data + "\n")
            print(f"[*] Wrote {args.output}", file=sys.stderr)
        else:
            print(data)
    return 1 if any(c["status"] == FAIL for c in report["checks"]) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted", file=sys.stderr)
        sys.exit(130)
    except BrokenPipeError:  # e.g. piped into `head`
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
