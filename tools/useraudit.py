#!/usr/bin/env python3
"""
useraudit - audit local user accounts for risky settings.

Lists every local account and flags the things an auditor looks for:
too many administrators, enabled Guest or built-in Administrator,
passwords that never expire or aren't required, accounts that haven't
logged in for months, extra root (UID 0) accounts, empty passwords and
service accounts with login shells.

Works on Windows (PowerShell LocalAccounts), Linux (/etc/passwd,
/etc/shadow, /etc/group) and macOS (dscl). Run as Administrator / root
for complete results.

Standard library only. Python 3.8+.
"""

import argparse
import csv
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone

__version__ = "1.0.0"

PASS, WARN, FAIL, INFO = "PASS", "WARN", "FAIL", "INFO"
NOW = datetime.now(timezone.utc)
NOLOGIN_SHELLS = ("nologin", "false", "sync", "shutdown", "halt")


def run(cmd, timeout=60):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                             encoding="utf-8", errors="replace")
    except (OSError, subprocess.TimeoutExpired):
        return None
    return out.stdout if out.returncode == 0 else None


def is_elevated():
    if os.name == "nt":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def account(name, **kw):
    base = {"name": name, "enabled": True, "admin": False, "last_logon": None,
            "password_last_set": None, "password_never_expires": None,
            "password_required": True, "uid": None, "shell": None, "builtin": None}
    base.update(kw)
    return base


# ---- Windows -----------------------------------------------------------------

def ps_date(value):
    """PowerShell 5 serializes dates as /Date(ms)/; 7 uses ISO strings."""
    if not value:
        return None
    if isinstance(value, dict):
        value = value.get("value") or value.get("DateTime")
    m = re.search(r"/Date\((-?\d+)", str(value))
    if m:
        return datetime.fromtimestamp(int(m.group(1)) / 1000, tz=timezone.utc)
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def windows_accounts():
    ps = shutil.which("powershell") or shutil.which("pwsh")
    if not ps:
        raise RuntimeError("PowerShell not found")
    users_cmd = ("Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordLastSet,"
                 "PasswordExpires,PasswordRequired,@{n='SID';e={$_.SID.Value}} | ConvertTo-Json -Depth 3")
    # S-1-5-32-544 is the Administrators group in every language
    admins_cmd = ("Get-LocalGroupMember -SID S-1-5-32-544 | "
                  "Select-Object Name,ObjectClass,PrincipalSource,@{n='SID';e={$_.SID.Value}} | ConvertTo-Json")
    raw = run([ps, "-NoProfile", "-NonInteractive", "-Command", users_cmd])
    if raw is None:
        raise RuntimeError("Get-LocalUser failed (needs Windows 10 / Server 2016 or later)")
    users = json.loads(raw or "[]")
    users = users if isinstance(users, list) else [users]
    admin_raw = run([ps, "-NoProfile", "-NonInteractive", "-Command", admins_cmd]) or "[]"
    members = json.loads(admin_raw or "[]")
    members = members if isinstance(members, list) else [members]
    admin_sids = {m.get("SID") for m in members}

    accounts = []
    for u in users:
        sid = u.get("SID") or ""
        rid = sid.rsplit("-", 1)[-1]
        builtin = {"500": "administrator", "501": "guest", "503": "defaultaccount",
                   "504": "wdagutilityaccount"}.get(rid)
        accounts.append(account(
            u["Name"],
            enabled=bool(u.get("Enabled")),
            admin=sid in admin_sids,
            last_logon=ps_date(u.get("LastLogon")),
            password_last_set=ps_date(u.get("PasswordLastSet")),
            password_never_expires=u.get("PasswordExpires") in (None, ""),
            password_required=bool(u.get("PasswordRequired", True)),
            uid=sid,
            builtin=builtin,
        ))
    # Domain users/groups that are local admins
    local_names = {a["uid"] for a in accounts}
    other_admins = [m["Name"] for m in members if m.get("SID") not in local_names]
    return accounts, other_admins


# ---- Linux -------------------------------------------------------------------

def read_lines(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return [l.rstrip("\n") for l in fh if l.strip() and not l.startswith("#")]
    except OSError:
        return None


def linux_lastlog():
    """{user: datetime or None} from lastlog, or None when lastlog isn't available."""
    out = run(["lastlog"])
    result = {}
    if not out:
        return None
    for line in out.splitlines()[1:]:
        user = line.split()[0] if line.split() else ""
        if "**Never logged in**" in line:
            result[user] = None
            continue
        m = re.search(r"(\w{3} \w{3} +\d+ [\d:]+ [+-]\d{4} \d{4})", line)
        if m:
            try:
                result[user] = datetime.strptime(m.group(1), "%a %b %d %H:%M:%S %z %Y")
            except ValueError:
                pass
    return result


def linux_accounts():
    passwd = read_lines("/etc/passwd") or []
    shadow = {l.split(":")[0]: l.split(":") for l in (read_lines("/etc/shadow") or [])}
    groups = {}
    gid_names = {}
    for line in read_lines("/etc/group") or []:
        parts = line.split(":")
        if len(parts) >= 4:
            groups[parts[0]] = [m for m in parts[3].split(",") if m]
            gid_names[parts[2]] = parts[0]
    admin_groups = [g for g in ("sudo", "wheel", "admin") if g in groups]
    admin_members = {m for g in admin_groups for m in groups[g]}
    admin_gids = {gid for gid, name in gid_names.items() if name in admin_groups}
    lastlog = linux_lastlog()

    accounts = []
    for line in passwd:
        parts = line.split(":")
        if len(parts) < 7:
            continue
        name, _x, uid, gid, _gecos, _home, shell = parts[:7]
        uid = int(uid) if uid.isdigit() else -1
        sh = shadow.get(name)
        enabled, pw_required, never_expires, last_set = True, True, None, None
        if sh and len(sh) >= 5:
            pw = sh[1]
            if pw == "":
                pw_required = False
            elif pw.startswith("!") or pw.startswith("*"):
                pw_required = True  # password login locked; key-based login may still work
            if sh[2].isdigit():
                last_set = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(days=int(sh[2]))
            never_expires = sh[4] in ("", "99999") or (sh[4].isdigit() and int(sh[4]) >= 10000)
            if len(sh) >= 8 and sh[7].isdigit():
                expired = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(days=int(sh[7]))
                if expired < NOW:
                    enabled = False
        if uid != 0 and shell.rsplit("/", 1)[-1] in NOLOGIN_SHELLS:
            enabled = False  # can't log in interactively
        accounts.append(account(
            name, enabled=enabled,
            admin=(uid == 0 or name in admin_members or gid in admin_gids),
            last_logon=lastlog.get(name) if lastlog else None,
            password_last_set=last_set,
            password_never_expires=never_expires if sh else None,
            password_required=pw_required,
            uid=uid, shell=shell,
            builtin="root" if name == "root" else None,
        ))
    return accounts, [], bool(shadow), lastlog is not None


# ---- macOS -------------------------------------------------------------------

def mac_accounts():
    out = run(["dscl", ".", "list", "/Users", "UniqueID"]) or ""
    admins_out = run(["dscl", ".", "read", "/Groups/admin", "GroupMembership"]) or ""
    admins = set(admins_out.replace("GroupMembership:", "").split())
    accounts = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) != 2 or parts[0].startswith("_"):
            continue
        name, uid = parts[0], int(parts[1]) if parts[1].lstrip("-").isdigit() else -1
        info = run(["dscl", ".", "read", f"/Users/{name}", "UserShell", "AuthenticationAuthority"]) or ""
        shell = re.search(r"UserShell:\s*(\S+)", info)
        shell = shell.group(1) if shell else ""
        # Accounts without an AuthenticationAuthority can't log in with a password
        # (root is disabled this way on a stock Mac)
        can_auth = "AuthenticationAuthority:" in info
        enabled = shell.rsplit("/", 1)[-1] not in NOLOGIN_SHELLS and (can_auth or uid >= 500)
        accounts.append(account(name, admin=name in admins or uid == 0, uid=uid, shell=shell,
                                enabled=enabled, builtin="root" if name == "root" else None))
    return accounts, []


# ---- Analysis ----------------------------------------------------------------

def is_login_account(a, os_name):
    """Real people's accounts: everything on Windows/macOS; root + UID 1000-59999 with a shell on Linux."""
    if os_name != "Linux":
        return True
    if a["uid"] == 0:
        return True
    has_shell = bool(a["shell"]) and a["shell"].rsplit("/", 1)[-1] not in NOLOGIN_SHELLS
    return isinstance(a["uid"], int) and 1000 <= a["uid"] < 60000 and has_shell


def analyze(accounts, other_admins, os_name, stale_days, max_admins, has_logons=True):
    findings = []

    def add(status, account_name, detail):
        findings.append({"status": status, "account": account_name, "detail": detail})

    enabled_admins = [a for a in accounts if a["admin"] and a["enabled"] and a["builtin"] != "root"]
    total_admins = len(enabled_admins) + len(other_admins)
    if total_admins > max_admins:
        names = [a["name"] for a in enabled_admins] + other_admins
        add(WARN, "-", f"{total_admins} enabled administrators (more than {max_admins}): {', '.join(names)}")
    for name in other_admins:
        add(INFO, name, "Non-local (domain/Microsoft/Entra) member of Administrators")

    for a in accounts:
        n = a["name"]
        is_human = is_login_account(a, os_name)

        if a["builtin"] == "guest" and a["enabled"]:
            add(FAIL, n, "Guest account is enabled")
        if a["builtin"] == "administrator" and a["enabled"]:
            add(WARN, n, "Built-in Administrator is enabled; disable it and use named admin accounts")
        if os_name == "Linux" and a["uid"] == 0 and n != "root":
            add(FAIL, n, "Has UID 0; a second root account")
        if not a["password_required"] and a["enabled"]:
            add(FAIL, n, "No password required (empty password)")
        if os_name == "Linux" and not is_human and a["enabled"] and a["shell"] \
                and a["shell"].rsplit("/", 1)[-1] not in NOLOGIN_SHELLS and n != "root":
            add(WARN, n, f"System account (UID {a['uid']}) has a login shell: {a['shell']}")

        if not a["enabled"]:
            # On Linux a locked password is normal (root on Ubuntu, key-only users)
            if os_name == "Windows" and a["builtin"] not in ("guest", "defaultaccount", "wdagutilityaccount"):
                add(INFO, n, "Disabled account still present")
            continue
        if not is_human or a["builtin"] in ("defaultaccount", "wdagutilityaccount"):
            continue

        if a["password_never_expires"]:
            # Linux defaults every account to 99999 days, so only Windows gets a warning
            add(WARN if a["admin"] and os_name == "Windows" else INFO, n,
                "Password never expires" + (" on an admin account" if a["admin"] else ""))
        if not has_logons:
            pass  # no logon history on this platform; don't guess
        elif a["last_logon"] is None:
            if os_name == "Windows" or a["uid"] != 0:
                add(WARN, n, "Enabled but has never logged in")
        else:
            idle = (NOW - a["last_logon"]).days
            if idle > stale_days:
                add(WARN, n, f"No logon for {idle} days (last {a['last_logon'].date()})")
        if a["password_last_set"] and a["admin"]:
            age = (NOW - a["password_last_set"]).days
            if age > 365:
                add(INFO, n, f"Admin password last changed {age} days ago")
    return findings


def collect(stale_days, max_admins):
    system = platform.system()
    notes = []
    has_logons = True
    if system == "Windows":
        accounts, others = windows_accounts()
    elif system == "Linux":
        accounts, others, has_shadow, has_logons = linux_accounts()
        if not has_shadow:
            notes.append("Couldn't read /etc/shadow; run as root for password checks")
        if not has_logons:
            notes.append("lastlog isn't available, so stale-account checks are skipped")
    elif system == "Darwin":
        accounts, others = mac_accounts()
        has_logons = False
        notes.append("macOS mode checks admins, disabled accounts and shells (no logon history)")
    else:
        raise RuntimeError(f"Unsupported OS: {system}")
    if not is_elevated() and system == "Windows":
        notes.append("Not running as Administrator; some fields may be missing")
    return {
        "host": platform.node(),
        "os": system,
        "scanned_at": NOW.isoformat(timespec="seconds"),
        "notes": notes,
        "accounts": accounts,
        "findings": analyze(accounts, others, system, stale_days, max_admins, has_logons),
    }


def fmt_date(dt):
    return dt.strftime("%Y-%m-%d") if dt else "never"


def color(status, enabled):
    if not enabled:
        return status
    return f"\033[{ {PASS: '32', WARN: '33', FAIL: '31', INFO: '36'}[status] }m{status}\033[0m"


def print_report(report, show_all, use_color):
    print(f"{report['host']} ({report['os']})")
    for n in report["notes"]:
        print(f"[!] {n}")
    rows = report["accounts"]
    if report["os"] == "Linux" and not show_all:
        rows = [a for a in rows if is_login_account(a, "Linux") or a["admin"]]
    print(f"\n  {'ACCOUNT':<22} {'ENABLED':<8} {'ADMIN':<6} {'LAST LOGON':<11} {'PW SET':<11} PW EXPIRES")
    for a in sorted(rows, key=lambda a: (not a["admin"], not a["enabled"], a["name"].lower())):
        expires = "-" if a["password_never_expires"] is None else ("never" if a["password_never_expires"] else "yes")
        print(f"  {a['name']:<22} {('yes' if a['enabled'] else 'no'):<8} {('yes' if a['admin'] else ''):<6} "
              f"{fmt_date(a['last_logon']):<11} {fmt_date(a['password_last_set']):<11} {expires}")
    hidden = len(report["accounts"]) - len(rows)
    if hidden:
        print(f"  ({hidden} system accounts hidden; use --all)")

    print()
    order = {FAIL: 0, WARN: 1, INFO: 2}
    findings = sorted(report["findings"], key=lambda f: order[f["status"]])
    if not findings:
        print(f"  [{color(PASS, use_color)}] No issues found")
    for f in findings:
        who = "" if f["account"] == "-" else f"{f['account']}: "
        print(f"  [{color(f['status'], use_color)}] {who}{f['detail']}")
    counts = {s: sum(1 for f in findings if f["status"] == s) for s in (FAIL, WARN, INFO)}
    print(f"\n[*] {len(report['accounts'])} accounts, {counts[FAIL]} fail, {counts[WARN]} warn, {counts[INFO]} info")


def serializable(report):
    def conv(v):
        return v.isoformat() if isinstance(v, datetime) else v
    out = dict(report)
    out["accounts"] = [{k: conv(v) for k, v in a.items()} for a in report["accounts"]]
    return out


def parse_args(argv):
    p = argparse.ArgumentParser(prog="useraudit", description="Audit local user accounts for risky settings.")
    p.add_argument("-d", "--stale-days", type=int, default=90,
                   help="flag accounts with no logon in this many days (default 90)")
    p.add_argument("-m", "--max-admins", type=int, default=2,
                   help="warn when there are more enabled admins than this (default 2)")
    p.add_argument("-a", "--all", action="store_true", help="also list Linux system accounts")
    p.add_argument("-f", "--format", choices=("table", "csv", "json"), default="table", help="output format")
    p.add_argument("-o", "--output", metavar="FILE", help="write results to a file")
    p.add_argument("--no-color", action="store_true", help="plain output without colors")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        report = collect(args.stale_days, args.max_admins)
    except (RuntimeError, ValueError) as err:
        print(f"[!] {err}", file=sys.stderr)
        return 2

    use_color = sys.stdout.isatty() and not args.no_color
    if args.format == "table" and not args.output:
        print_report(report, args.all, use_color)
    elif args.format == "csv":
        fh = open(args.output, "w", newline="", encoding="utf-8") if args.output else sys.stdout
        w = csv.DictWriter(fh, fieldnames=["status", "account", "detail"])
        w.writeheader()
        w.writerows(report["findings"])
        if args.output:
            fh.close()
            print(f"[*] Wrote {args.output}", file=sys.stderr)
    else:
        data = json.dumps(serializable(report), indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(data + "\n")
            print(f"[*] Wrote {args.output}", file=sys.stderr)
        else:
            print(data)

    return 1 if any(f["status"] in (FAIL, WARN) for f in report["findings"]) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted", file=sys.stderr)
        sys.exit(130)
    except BrokenPipeError:  # e.g. piped into `head`
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
