#!/usr/bin/env python3
"""
logscan - summarize failed logins and spot brute-force attempts.

Parses Linux auth logs (auth.log / secure, including rotated .gz files)
and Windows Security event 4625 (live, or from a wevtutil XML export)
and summarizes failed logins by source IP, username and hour. Flags IPs
that look like brute force or password spraying, and successful logins
from IPs that failed first.

Standard library only. Python 3.8+.
"""

import argparse
import csv
import glob
import gzip
import ipaddress
import json
import os
import platform
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

__version__ = "1.0.0"

DEFAULT_LINUX_LOGS = ("/var/log/auth.log", "/var/log/secure")

# sshd / PAM / su / sudo failure and success lines
FAIL_PATTERNS = [
    re.compile(r"Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(?P<user>\S*) "
               r"from (?P<ip>[0-9a-fA-F:.]+)"),
    re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[0-9a-fA-F:.]+)"),
    re.compile(r"authentication failure;.*?rhost=(?P<ip>[0-9a-fA-F:.]+)(?:\s+user=(?P<user>\S+))?"),
    re.compile(r"Connection closed by (?:authenticating|invalid) user (?P<user>\S*) (?P<ip>[0-9a-fA-F:.]+)"),
]
SUCCESS_PATTERN = re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
SYSLOG_TS = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<time>\d\d:\d\d:\d\d)")
ISO_TS = re.compile(r"^(?P<iso>\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?)")

# 4625 sub-status codes worth naming
STATUS = {
    "0xc000006a": "bad password", "0xc0000064": "no such user", "0xc0000234": "account locked",
    "0xc0000072": "account disabled", "0xc000006f": "outside logon hours", "0xc0000070": "workstation restriction",
    "0xc0000071": "password expired", "0xc0000193": "account expired", "0xc0000224": "must change password",
    "0xc000015b": "logon type not granted",
}
LOGON_TYPES = {"2": "interactive", "3": "network", "4": "batch", "5": "service", "7": "unlock",
               "8": "network cleartext", "9": "new credentials", "10": "RDP", "11": "cached"}


def open_any(path):
    return gzip.open(path, "rt", errors="replace") if path.endswith(".gz") else open(path, errors="replace")


def parse_ts(line, year):
    m = ISO_TS.match(line)
    if m:
        try:
            iso = re.sub(r"([+-]\d\d)(\d\d)$", r"\1:\2", m.group("iso").replace("Z", "+00:00"))
            iso = re.sub(r"(\.\d{6})\d+", r"\1", iso)
            dt = datetime.fromisoformat(iso)
            return dt if dt.tzinfo else dt.astimezone()
        except ValueError:
            return None
    m = SYSLOG_TS.match(line)
    if m:
        try:
            dt = datetime.strptime(f"{year} {m.group('mon')} {m.group('day')} {m.group('time')}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return None
        return dt.astimezone()
    return None


def journal_lines():
    """sshd entries from the systemd journal, for distros without auth.log."""
    try:
        r = subprocess.run(["journalctl", "-u", "ssh", "-u", "sshd", "--no-pager", "-o", "short-iso"],
                           capture_output=True, text=True, errors="replace", timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout.splitlines() if r.returncode == 0 and r.stdout.strip() else None


def mac_lines(hours):
    """sshd entries from the macOS unified log (Remote Login)."""
    try:
        r = subprocess.run(["log", "show", "--style", "syslog", "--last", f"{int(hours)}h",
                            "--predicate", 'process == "sshd" OR process == "sshd-session"'],
                           capture_output=True, text=True, errors="replace", timeout=170)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return [l for l in r.stdout.splitlines() if "sshd" in l] if r.returncode == 0 else None


def linux_events(paths, extra_lines=None):
    """Yield (kind, datetime, ip, user, detail) from auth logs."""
    now = datetime.now().astimezone()
    sources = [(p, None) for p in paths] + ([("journal", extra_lines)] if extra_lines else [])
    for path, preloaded in sources:
        if preloaded is not None:
            yield from parse_lines(preloaded, now.year, now)
            continue
        try:
            year = datetime.fromtimestamp(os.path.getmtime(path)).year
            fh = open_any(path)
        except OSError as err:
            print(f"[!] {path}: {err.strerror}", file=sys.stderr)
            continue
        with fh:
            yield from parse_lines(fh, year, now)


def parse_lines(lines, year, now):
    for line in lines:
        ts = parse_ts(line, year)
        if ts and ts > now + timedelta(days=1):  # syslog lines from last December
            ts = ts.replace(year=ts.year - 1)
        m = SUCCESS_PATTERN.search(line)
        if m:
            yield "success", ts, m.group("ip"), m.group("user"), "ssh"
            continue
        for pat in FAIL_PATTERNS:
            m = pat.search(line)
            if m:
                user = m.groupdict().get("user") or ""
                detail = "invalid user" if "nvalid user" in line else "auth failure"
                yield "fail", ts, m.group("ip"), user, detail
                break


def parse_event_xml(xml_text):
    """Yield events from wevtutil XML (one or many <Event> elements)."""
    text = xml_text.strip()
    if not text.startswith("<Events"):
        text = f"<Events>{text}</Events>"
    text = re.sub(r'xmlns="[^"]+"', "", text, count=0)
    root = ET.fromstring(text)
    for ev in root.iter("Event"):
        eid = (ev.findtext("System/EventID") or "").strip()
        created = ev.find("System/TimeCreated")
        ts = None
        if created is not None and created.get("SystemTime"):
            raw = re.sub(r"(\.\d{6})\d+", r"\1", created.get("SystemTime"))
            try:
                ts = datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone()
            except ValueError:
                pass
        data = {d.get("Name"): (d.text or "") for d in ev.iter("Data")}
        ip = data.get("IpAddress", "-")
        user = data.get("TargetUserName", "")
        domain = data.get("TargetDomainName", "")
        if domain and domain not in ("-", ".") and user:
            user = f"{domain}\\{user}"
        ltype = LOGON_TYPES.get(data.get("LogonType", ""), data.get("LogonType", ""))
        if eid == "4625":
            sub = (data.get("SubStatus") or "").lower()
            reason = STATUS.get(sub) or STATUS.get((data.get("Status") or "").lower()) or sub
            yield "fail", ts, ip if ip not in ("-", "") else "local", user, f"{reason}, {ltype}".strip(", ")
        elif eid == "4624" and ip not in ("-", "", "127.0.0.1", "::1"):
            yield "success", ts, ip, user, ltype


def windows_events(hours, include_success):
    ids = "EventID=4625" + (" or EventID=4624" if include_success else "")
    query = f"*[System[({ids}) and TimeCreated[timediff(@SystemTime) <= {int(hours * 3600 * 1000)}]]]"
    r = subprocess.run(["wevtutil", "qe", "Security", f"/q:{query}", "/f:xml", "/rd:true"],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode != 0:
        msg = r.stderr.strip() or r.stdout.strip()
        if "access" in msg.lower() or r.returncode == 5:
            raise RuntimeError("Reading the Security log needs an Administrator prompt.")
        raise RuntimeError(msg or "wevtutil failed")
    if not r.stdout.strip():
        return iter(())
    return parse_event_xml(r.stdout)


def is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return True


def analyze(events, since, threshold, spray_users):
    fails = []
    successes = []
    for kind, ts, ip, user, detail in events:
        if since and ts and ts < since:
            continue
        (fails if kind == "fail" else successes).append({"time": ts, "ip": ip, "user": user, "detail": detail})

    by_ip = defaultdict(list)
    for f in fails:
        by_ip[f["ip"]].append(f)
    ips = []
    for ip, rows in by_ip.items():
        users = Counter(r["user"] for r in rows)
        times = [r["time"] for r in rows if r["time"]]
        flags = []
        if len(rows) >= threshold:
            flags.append("brute force")
        if len(users) >= spray_users:
            flags.append("password spray")
        ok = [s for s in successes if s["ip"] == ip]
        if ok:
            flags.append(f"LOGGED IN as {', '.join(sorted({s['user'] for s in ok}))}")
        ips.append({
            "ip": ip, "failures": len(rows), "users": len(users),
            "top_users": [u for u, _ in users.most_common(5)],
            "first": min(times).isoformat(timespec="seconds") if times else None,
            "last": max(times).isoformat(timespec="seconds") if times else None,
            "external": not is_private(ip) if ip != "local" else False,
            "flags": flags,
        })
    ips.sort(key=lambda r: -r["failures"])
    hours = Counter(f["time"].strftime("%H") for f in fails if f["time"])
    users = Counter(f["user"] for f in fails)
    return {
        "total_failures": len(fails),
        "total_successes": len(successes),
        "first": min((f["time"] for f in fails if f["time"]), default=None),
        "last": max((f["time"] for f in fails if f["time"]), default=None),
        "ips": ips,
        "users": users.most_common(),
        "hours": {f"{h:02d}": hours.get(f"{h:02d}", 0) for h in range(24)},
    }


def print_report(rep, top, source):
    print(f"Source: {source}")
    if not rep["total_failures"]:
        print("\n  No failed logins found.")
        return
    span = ""
    if rep["first"]:
        span = f"  ({rep['first']:%Y-%m-%d %H:%M} to {rep['last']:%Y-%m-%d %H:%M})"
    print(f"Failed logins: {rep['total_failures']} from {len(rep['ips'])} source(s){span}\n")

    print(f"  {'SOURCE':<40} {'FAILS':>6} {'USERS':>6}  {'LAST SEEN':<16}  FLAGS")
    for r in rep["ips"][:top]:
        last = r["last"][:16].replace("T", " ") if r["last"] else "-"
        tag = " ext" if r["external"] else ""
        print(f"  {r['ip'] + tag:<40} {r['failures']:>6} {r['users']:>6}  {last:<16}  {', '.join(r['flags'])}")
    if len(rep["ips"]) > top:
        print(f"  ... {len(rep['ips']) - top} more (use --top)")

    print(f"\n  {'TARGETED USER':<30} FAILS")
    for user, n in rep["users"][:top]:
        print(f"  {user or '(blank)':<30} {n}")

    peak = max(rep["hours"].values()) or 1
    print("\n  FAILURES BY HOUR")
    for h, n in rep["hours"].items():
        if n:
            print(f"  {h}:00 {'#' * max(1, round(n / peak * 40)):<40} {n}")

    alerts = [r for r in rep["ips"] if r["flags"]]
    if alerts:
        print()
        for r in alerts:
            sev = "[!!]" if any(f.startswith("LOGGED IN") for f in r["flags"]) else "[!] "
            print(f"  {sev} {r['ip']}: {', '.join(r['flags'])} ({r['failures']} failures, {r['users']} user(s))")


def parse_args(argv):
    p = argparse.ArgumentParser(prog="logscan",
                                description="Summarize failed logins from Linux auth logs or Windows event 4625.")
    p.add_argument("files", nargs="*", help="auth log(s) (.gz ok) or wevtutil XML export(s); "
                                            "default: this machine's logs")
    p.add_argument("--hours", type=float, default=None,
                   help="only look at the last N hours (Windows live default: 168)")
    p.add_argument("-n", "--threshold", type=int, default=10, help="failures from one IP to flag brute force (default 10)")
    p.add_argument("-u", "--spray-users", type=int, default=5,
                   help="distinct usernames from one IP to flag password spraying (default 5)")
    p.add_argument("--top", type=int, default=15, help="rows to show per table (default 15)")
    p.add_argument("-f", "--format", choices=("table", "csv", "json"), default="table", help="output format")
    p.add_argument("-o", "--output", metavar="FILE", help="write results to a file")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    since = datetime.now().astimezone() - timedelta(hours=args.hours) if args.hours else None

    try:
        if args.files:
            xml_files = [f for f in args.files if f.lower().endswith(".xml")]
            log_files = [f for f in args.files if f not in xml_files]
            events = list(linux_events(log_files))
            for f in xml_files:
                with open(f, encoding="utf-8-sig", errors="replace") as fh:
                    events += list(parse_event_xml(fh.read()))
            source = ", ".join(args.files)
        elif platform.system() == "Darwin":
            hours = args.hours or 168
            lines = mac_lines(hours)
            if lines is None:
                raise RuntimeError("Couldn't read the unified log (`log show`).")
            events = list(linux_events([], lines))
            source = f"macOS unified log (sshd), last {hours:g} hours"
            if not lines:
                source += "; Remote Login may be off"
        elif platform.system() == "Windows":
            hours = args.hours or 168
            events = list(windows_events(hours, include_success=True))
            source = f"Windows Security log, last {hours:g} hours"
        else:
            paths = []
            for base in DEFAULT_LINUX_LOGS:
                paths += sorted(glob.glob(base + "*"), reverse=True)
            journal = None if paths else journal_lines()
            if not paths and not journal:
                raise RuntimeError("No auth log or sshd journal found (try running with sudo).")
            events = list(linux_events(paths, journal))
            source = ", ".join(paths) if paths else "systemd journal (ssh/sshd)"
    except (RuntimeError, ET.ParseError, OSError) as err:
        print(f"[!] {err}", file=sys.stderr)
        return 2

    rep = analyze(events, since, args.threshold, args.spray_users)

    if args.format == "table" and not args.output:
        print_report(rep, args.top, source)
    elif args.format == "csv":
        fh = open(args.output, "w", newline="", encoding="utf-8") if args.output else sys.stdout
        w = csv.writer(fh)
        w.writerow(["ip", "failures", "users", "top_users", "first", "last", "external", "flags"])
        for r in rep["ips"]:
            w.writerow([r["ip"], r["failures"], r["users"], " ".join(r["top_users"]), r["first"], r["last"],
                        r["external"], "; ".join(r["flags"])])
        if args.output:
            fh.close()
    else:
        out = dict(rep, source=source,
                   first=rep["first"].isoformat() if rep["first"] else None,
                   last=rep["last"].isoformat() if rep["last"] else None)
        data = json.dumps(out, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(data + "\n")
        else:
            print(data)
    if args.output:
        print(f"[*] Wrote {args.output}", file=sys.stderr)
    return 1 if any(r["flags"] for r in rep["ips"]) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted", file=sys.stderr)
        sys.exit(130)
    except BrokenPipeError:  # e.g. piped into `head`
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
