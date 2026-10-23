#!/usr/bin/env python3
"""
netscan - discover devices on your local network and spot new ones.

Sweeps a subnet with ping plus a quick TCP probe (for devices that
ignore ping), then reads the system ARP table for MAC addresses, looks
up hostnames and hardware vendors, and flags randomized (private) MACs.
Save a baseline and diff later scans against it to catch new devices,
devices that disappeared, and IPs whose MAC address changed (a sign of
DHCP churn or ARP spoofing).

Only scan networks you own or are authorized to test.

Standard library only. Python 3.8+.
"""

import argparse
import csv
import ipaddress
import json
import os
import platform
import re
import socket
import ssl
import subprocess
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

__version__ = "1.0.0"

PROBE_PORTS = (80, 443, 445, 22, 139, 3389, 8080, 62078)  # 62078: iPhone lockdown
IS_WIN = os.name == "nt"
OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"
OUI_CACHE = os.path.join(os.path.expanduser("~"), ".netscan_oui.csv")


def ssl_context(verify=True):
    """Default TLS context. python.org builds for macOS ship without CA certificates,
    so when none are loaded there, borrow the system roots from the macOS keychain."""
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if sys.platform == "darwin" and not ctx.cert_store_stats().get("x509_ca"):
        try:
            pem = subprocess.run(
                ["security", "find-certificate", "-a", "-p",
                 "/System/Library/Keychains/SystemRootCertificates.keychain"],
                capture_output=True, text=True, timeout=30).stdout
            if pem:
                ctx.load_verify_locations(cadata=pem)
        except (OSError, subprocess.SubprocessError, ssl.SSLError, ValueError):
            pass
    return ctx


def local_network():
    """Guess the local /24 from the primary outbound interface."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("192.0.2.1", 9))  # no packets sent for UDP connect
        ip = s.getsockname()[0]
    return ipaddress.ip_network(f"{ip}/24", strict=False)


def ping(ip, timeout_ms):
    if IS_WIN:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    elif platform.system() == "Darwin":
        cmd = ["ping", "-c", "1", "-W", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, round(timeout_ms / 1000))), ip]
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                           timeout=timeout_ms / 1000 + 2,
                           creationflags=0x08000000 if IS_WIN else 0)  # CREATE_NO_WINDOW
    except (OSError, subprocess.TimeoutExpired):
        return False
    # Windows returns 0 for "Destination host unreachable" replies from the gateway
    return r.returncode == 0 and ("TTL=" in r.stdout.upper() or not IS_WIN)


def tcp_probe(ip, timeout):
    for port in PROBE_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except ConnectionRefusedError:
            return True  # an RST means something is there
        except OSError:
            continue
    return False


def alive(ip, timeout_ms, tcp):
    if ping(ip, timeout_ms):
        return "icmp"
    if tcp and tcp_probe(ip, timeout_ms / 1000):
        return "tcp"
    return None


def arp_table():
    """{ip: mac} from the OS neighbor cache."""
    table = {}
    if os.path.exists("/proc/net/arp"):
        with open("/proc/net/arp") as fh:
            for line in fh.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                    table[parts[0]] = parts[3].lower()
        return table
    try:
        out = subprocess.run(["arp", "-a"] if IS_WIN else ["arp", "-an"], capture_output=True, text=True,
                             creationflags=0x08000000 if IS_WIN else 0).stdout
    except OSError:
        return table
    for line in out.splitlines():
        ip = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        mac = re.search(r"([0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}", line)
        if ip and mac:
            norm = ":".join(f"{int(x, 16):02x}" for x in re.split("[:-]", mac.group(0)))
            if norm not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                table[ip.group(1)] = norm
    return table


def load_oui(path):
    """Load an IEEE oui.csv or Wireshark 'manuf' file into {prefix: vendor}."""
    vendors = {}
    if not path or not os.path.exists(path):
        return vendors
    with open(path, encoding="utf-8", errors="replace") as fh:
        first = fh.readline()
        fh.seek(0)
        if first.startswith("Registry,Assignment"):
            for row in csv.DictReader(fh):
                vendors[row["Assignment"].lower()] = row["Organization Name"].strip()
        else:
            for line in fh:
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.rstrip("\n").split("\t")
                prefix = parts[0].split("/")[0].replace(":", "").replace("-", "").lower()
                if len(prefix) == 6 and len(parts) > 1:
                    vendors[prefix] = parts[-1].strip()
    return vendors


def update_oui(path):
    print(f"[*] Downloading IEEE OUI list to {path} ...", file=sys.stderr)
    req = urllib.request.Request(OUI_URL, headers={"User-Agent": f"netscan/{__version__}"})
    with urllib.request.urlopen(req, timeout=60, context=ssl_context()) as resp, open(path, "wb") as fh:
        fh.write(resp.read())


def vendor_for(mac, vendors):
    if not mac:
        return ""
    first_octet = int(mac[:2], 16)
    if first_octet & 0x02:
        return "(randomized / private MAC)"
    return vendors.get(mac.replace(":", "")[:6], "")


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def scan(network, threads, timeout_ms, tcp, resolve, vendors):
    hosts = [str(h) for h in network.hosts()] if network.num_addresses > 2 else [str(network.network_address)]
    with ThreadPoolExecutor(max_workers=threads) as pool:
        states = dict(zip(hosts, pool.map(lambda ip: alive(ip, timeout_ms, tcp), hosts)))
    arp = arp_table()
    my_ips = set()
    try:
        my_ips = {info[4][0] for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)}
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            my_ips.add(s.getsockname()[0])
    except OSError:
        pass

    # ARP entries for the range count as up even if they ignored our probes
    found = {ip for ip, st in states.items() if st}
    found |= {ip for ip in arp if ipaddress.ip_address(ip) in network}
    found = sorted(found, key=lambda ip: ipaddress.ip_address(ip))

    with ThreadPoolExecutor(max_workers=threads) as pool:
        names = dict(zip(found, pool.map(reverse_dns, found))) if resolve else {}

    devices = []
    for ip in found:
        mac = arp.get(ip, "")
        devices.append({
            "ip": ip,
            "mac": mac,
            "vendor": "(this machine)" if ip in my_ips else vendor_for(mac, vendors),
            "hostname": names.get(ip, ""),
            "seen_by": states.get(ip) or "arp",
        })
    return devices


def diff(devices, baseline):
    old = {d["ip"]: d for d in baseline.get("devices", [])}
    old_macs = {d["mac"]: d for d in baseline.get("devices", []) if d.get("mac")}
    new = {d["ip"]: d for d in devices}
    changes = []
    for ip, d in new.items():
        if ip not in old:
            moved = old_macs.get(d["mac"]) if d["mac"] else None
            if moved:
                changes.append(("MOVED", d, f"was {moved['ip']}"))
            else:
                changes.append(("NEW", d, ""))
        elif d["mac"] and old[ip].get("mac") and d["mac"] != old[ip]["mac"]:
            changes.append(("MAC CHANGED", d, f"was {old[ip]['mac']}"))
    for ip, d in old.items():
        if ip not in new and not (d.get("mac") and any(x["mac"] == d["mac"] for x in devices)):
            changes.append(("GONE", d, ""))
    return changes


def print_table(devices):
    print(f"  {'IP':<16} {'MAC':<18} {'VENDOR':<32} HOSTNAME")
    for d in devices:
        print(f"  {d['ip']:<16} {d['mac'] or '-':<18} {d['vendor'][:32]:<32} {d['hostname']}")


def parse_args(argv):
    p = argparse.ArgumentParser(prog="netscan",
                                description="Discover devices on your local network and diff against a baseline.")
    p.add_argument("network", nargs="?", help="CIDR to scan, e.g. 192.168.1.0/24 (default: your local /24)")
    p.add_argument("-j", "--threads", type=int, default=64, help="parallel workers (default 64)")
    p.add_argument("-t", "--timeout", type=int, default=700, help="per-host timeout in ms (default 700)")
    p.add_argument("--no-tcp", action="store_true", help="ping only, skip the TCP probe")
    p.add_argument("--no-dns", action="store_true", help="skip reverse DNS lookups")
    p.add_argument("--oui", metavar="FILE", default=OUI_CACHE,
                   help="IEEE oui.csv or Wireshark manuf file for vendor names (default ~/.netscan_oui.csv)")
    p.add_argument("--update-oui", action="store_true", help="download the IEEE vendor list first")
    p.add_argument("-s", "--save", metavar="FILE", help="save this scan as a baseline (JSON)")
    p.add_argument("-d", "--diff", metavar="FILE", help="compare against a saved baseline")
    p.add_argument("-f", "--format", choices=("table", "csv", "json"), default="table", help="output format")
    p.add_argument("-o", "--output", metavar="FILE", help="write results to a file")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        network = ipaddress.ip_network(args.network, strict=False) if args.network else local_network()
    except (ValueError, OSError) as err:
        print(f"[!] Bad network: {err}", file=sys.stderr)
        return 2
    if network.version != 4:
        print("[!] Only IPv4 ranges are supported.", file=sys.stderr)
        return 2
    if network.num_addresses > 4096:
        print(f"[!] {network} has {network.num_addresses} addresses; use /20 or smaller.", file=sys.stderr)
        return 2

    if args.update_oui:
        try:
            update_oui(args.oui)
        except OSError as err:
            print(f"[!] OUI download failed: {err}", file=sys.stderr)
    vendors = load_oui(args.oui)

    print(f"[*] Scanning {network} ({network.num_addresses - 2 if network.prefixlen < 31 else network.num_addresses} hosts)...",
          file=sys.stderr)
    started = datetime.now(timezone.utc)
    devices = scan(network, args.threads, args.timeout, not args.no_tcp, not args.no_dns, vendors)
    elapsed = (datetime.now(timezone.utc) - started).total_seconds()
    result = {"network": str(network), "scanned_at": started.isoformat(timespec="seconds"), "devices": devices}

    changes = None
    if args.diff:
        try:
            with open(args.diff, encoding="utf-8") as fh:
                changes = diff(devices, json.load(fh))
        except (OSError, ValueError) as err:
            print(f"[!] Can't read baseline: {err}", file=sys.stderr)
            return 2
        result["changes"] = [{"change": c, **d, "note": n} for c, d, n in changes]

    if args.format == "table" and not args.output:
        print_table(devices)
        print(f"\n[*] {len(devices)} device(s) up in {elapsed:.1f}s"
              + ("" if vendors else "  (run with --update-oui once for vendor names)"))
        if changes is not None:
            print(f"\nCHANGES since {args.diff}")
            if not changes:
                print("  none")
            for c, d, note in changes:
                print(f"  {c:<12} {d['ip']:<16} {d.get('mac') or '-':<18} {d.get('vendor', '')[:28]:<28} {note}")
    elif args.format == "csv":
        fh = open(args.output, "w", newline="", encoding="utf-8") if args.output else sys.stdout
        w = csv.DictWriter(fh, fieldnames=["ip", "mac", "vendor", "hostname", "seen_by"])
        w.writeheader()
        w.writerows(devices)
        if args.output:
            fh.close()
    else:
        data = json.dumps(result, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(data + "\n")
        else:
            print(data)

    if args.save:
        with open(args.save, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        print(f"[*] Baseline saved to {args.save}", file=sys.stderr)
    return 1 if changes else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted", file=sys.stderr)
        sys.exit(130)
    except BrokenPipeError:  # e.g. piped into `head`
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
