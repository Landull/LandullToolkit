#!/usr/bin/env python3
"""
secretscan - find leaked API keys, passwords and tokens in files.

Walks a folder or repo looking for credentials that shouldn't be there:
cloud keys (AWS, Google, Azure), platform tokens (GitHub, GitLab, Slack,
Stripe, OpenAI, Anthropic, npm and more), private keys, JWTs, database
URLs with embedded passwords, and high-entropy "password = ..." style
assignments. Also flags sensitive files by name (.env, id_rsa, *.pfx,
KeePass databases). Secrets are masked in output unless --show is used.

Add 'secretscan:ignore' to a line to silence a known false positive.

Standard library only. Python 3.8+.
"""

import argparse
import csv
import fnmatch
import json
import math
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone

__version__ = "1.0.0"

HIGH, MEDIUM, LOW = "HIGH", "MEDIUM", "LOW"

RULES = [
    ("AWS access key ID", HIGH, r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
    ("AWS secret access key", HIGH, r"(?i)aws_?secret_?access_?key\W{0,4}[=:]\s*[\"']?([A-Za-z0-9/+=]{40})\b"),
    ("GitHub token", HIGH, r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b"),
    ("GitHub fine-grained token", HIGH, r"\b(github_pat_[A-Za-z0-9_]{60,255})\b"),
    ("GitLab token", HIGH, r"\b(glpat-[A-Za-z0-9_-]{20,})\b"),
    ("Slack token", HIGH, r"\b(xox[abposr]-[A-Za-z0-9-]{10,})\b"),
    ("Slack webhook", HIGH, r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)"),
    ("Discord webhook", HIGH, r"(https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+)"),
    ("Google API key", HIGH, r"\b(AIza[0-9A-Za-z_-]{35})\b"),
    ("Stripe live key", HIGH, r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,})\b"),
    ("OpenAI API key", HIGH, r"\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,})\b"),
    ("OpenAI project key", HIGH, r"\b(sk-proj-[A-Za-z0-9_-]{80,})\b"),
    ("Anthropic API key", HIGH, r"\b(sk-ant-[a-z0-9]{2,8}-[A-Za-z0-9_-]{80,})\b"),
    ("SendGrid API key", HIGH, r"\b(SG\.[\w-]{22}\.[\w-]{43})\b"),
    ("npm token", HIGH, r"\b(npm_[A-Za-z0-9]{36})\b"),
    ("PyPI token", HIGH, r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})\b"),
    ("Azure storage key", HIGH, r"AccountKey=([A-Za-z0-9+/]{86}==)"),
    ("Twilio API key", MEDIUM, r"\b(SK[0-9a-f]{32})\b"),
    ("Telegram bot token", HIGH, r"\b(\d{8,10}:AA[0-9A-Za-z_-]{33})\b"),
    ("Private key", HIGH, r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)"),
    ("Password in URL", HIGH,
     r"\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?|mssql|ftp|smtp)://[^:\s/@]+:[^@\s/]{3,}@[^\s\"'<>]+)"),
    ("JSON Web Token", MEDIUM, r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"),
    ("Hardcoded secret", MEDIUM,
     r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)"
     r"[\"']?\s*(?:=|:|=>)\s*[\"']([^\"'\s]{8,})[\"']"),
]
COMPILED = [(n, s, re.compile(p)) for n, s, p in RULES]

PLACEHOLDERS = re.compile(r"(?i)(example|sample|dummy|placeholder|changeme|change_me|your[_-]|xxxx|\*\*\*|"
                          r"redacted|<[^>]+>|\$\{|\{\{|%\(|process\.env|os\.environ|getenv|test123|password123|"
                          r"\bfake\b|not_?a_?real)")

SENSITIVE_FILES = [
    (".env", HIGH), (".env.*", HIGH), ("*.pem", MEDIUM), ("*.key", MEDIUM), ("id_rsa", HIGH),
    ("id_dsa", HIGH), ("id_ecdsa", HIGH), ("id_ed25519", HIGH), ("*.pfx", HIGH), ("*.p12", HIGH),
    ("*.kdbx", MEDIUM), ("*.ppk", HIGH), (".npmrc", MEDIUM), (".pypirc", MEDIUM), (".netrc", HIGH),
    ("credentials", MEDIUM), ("credentials.json", MEDIUM), ("*.tfstate", MEDIUM), (".htpasswd", HIGH),
    ("wp-config.php", MEDIUM), ("*.ovpn", MEDIUM), ("secrets.y*ml", MEDIUM),
]
SAFE_FILES = (".env.example", ".env.sample", ".env.template", ".env.dist")

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "env", ".tox", "dist", "build",
             ".mypy_cache", ".pytest_cache", ".idea", ".next", "vendor", "site-packages", ".terraform"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".pdf", ".zip", ".gz", ".7z", ".tar",
            ".mp3", ".mp4", ".mov", ".woff", ".woff2", ".ttf", ".eot", ".exe", ".dll", ".so", ".class",
            ".jar", ".pyc", ".lock", ".min.js", ".map"}


def entropy(s):
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def mask(secret):
    if len(secret) <= 8:
        return "*" * len(secret)
    keep = 4 if len(secret) < 30 else 6
    return secret[:keep] + "*" * min(len(secret) - keep - 2, 20) + secret[-2:]


def is_binary(path):
    try:
        with open(path, "rb") as fh:
            return b"\x00" in fh.read(8192)
    except OSError:
        return True


def iter_files(root, max_size, excludes):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS
                         and not any(fnmatch.fnmatch(d, e) for e in excludes))
        for name in sorted(files):
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root)
            if any(fnmatch.fnmatch(rel, e) or fnmatch.fnmatch(name, e) for e in excludes):
                continue
            yield path


def scan_file(path, max_size):
    findings = []
    name = os.path.basename(path)
    if name not in SAFE_FILES:
        for pattern, sev in SENSITIVE_FILES:
            if fnmatch.fnmatch(name, pattern):
                findings.append({"rule": "Sensitive file", "severity": sev, "line": 0, "secret": name})
                break

    lower = name.lower()
    if any(lower.endswith(ext) for ext in SKIP_EXT):
        return findings
    try:
        if os.path.getsize(path) > max_size or is_binary(path):
            return findings
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return findings

    for lineno, line in enumerate(lines, 1):
        if "secretscan:ignore" in line or len(line) > 5000:
            continue
        for rule, sev, rx in COMPILED:
            for m in rx.finditer(line):
                secret = m.group(1)
                if rule == "Hardcoded secret":
                    if PLACEHOLDERS.search(secret) or entropy(secret) < 3.0 or secret.isalpha() and len(secret) < 12:
                        continue
                elif rule == "Password in URL":
                    pw = secret.split("://", 1)[1].split("@", 1)[0].split(":", 1)[1]
                    if PLACEHOLDERS.search(pw) or pw.lower() in ("password", "pass", "pwd"):
                        continue
                elif rule == "Private key":
                    # A real key has a base64 body or PEM headers on the next line;
                    # a lone BEGIN line is usually docs or code mentioning the format
                    nxt = lines[lineno].strip() if lineno < len(lines) else ""
                    if not re.match(r"^([A-Za-z0-9+/=]{16,}|Proc-Type:|Comment:|-----END)", nxt):
                        continue
                elif (PLACEHOLDERS.search(secret) or re.search(r"(.)\1{7,}", secret)):
                    continue  # sk_live_xxxxxxxx..., AKIAEXAMPLE... and other docs placeholders
                findings.append({"rule": rule, "severity": sev, "line": lineno, "secret": secret,
                                 "context": line.strip()[:200]})
    # The generic rule often re-finds a specific key; keep the specific match
    specific = {(f["line"], f["secret"]) for f in findings if f["rule"] != "Hardcoded secret"}
    return [f for f in findings if f["rule"] != "Hardcoded secret"
            or not any(f["line"] == l and (s in f["secret"] or f["secret"] in s) for l, s in specific)]


def parse_args(argv):
    p = argparse.ArgumentParser(prog="secretscan", description="Find leaked API keys, passwords and tokens in files.")
    p.add_argument("path", nargs="?", default=".", help="folder or file to scan (default: current folder)")
    p.add_argument("-x", "--exclude", action="append", default=[], metavar="GLOB",
                   help="skip paths matching this pattern (repeatable), e.g. -x 'tests/*'")
    p.add_argument("-m", "--min-severity", choices=(LOW, MEDIUM, HIGH), type=str.upper, default=LOW,
                   help="only report this severity and above")
    p.add_argument("--max-size", type=int, default=2, help="skip files larger than N MB (default 2)")
    p.add_argument("--show", action="store_true", help="print secrets unmasked (careful with screen shares)")
    p.add_argument("-f", "--format", choices=("table", "csv", "json"), default="table", help="output format")
    p.add_argument("-o", "--output", metavar="FILE", help="write results to a file")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if not os.path.exists(args.path):
        print(f"[!] Not found: {args.path}", file=sys.stderr)
        return 2
    rank = {LOW: 0, MEDIUM: 1, HIGH: 2}
    max_size = args.max_size * 1024 * 1024
    excludes = list(args.exclude)
    if args.output:
        excludes.append(os.path.basename(args.output))  # don't scan our own report

    results, scanned = [], 0
    for path in iter_files(args.path, max_size, excludes):
        scanned += 1
        for f in scan_file(path, max_size):
            if rank[f["severity"]] < rank[args.min_severity]:
                continue
            rel = path if os.path.isfile(args.path) else os.path.relpath(path, args.path)
            f["file"] = rel
            shown = f["secret"] if args.show or f["rule"] in ("Sensitive file", "Private key") else mask(f["secret"])
            if not args.show and "context" in f:
                f["context"] = f["context"].replace(f["secret"], shown)
            f["secret"] = shown
            results.append(f)

    results.sort(key=lambda r: (-rank[r["severity"]], r["file"], r["line"]))
    if args.format == "table" and not args.output:
        for r in results:
            where = f"{r['file']}:{r['line']}" if r["line"] else r["file"]
            print(f"[{r['severity']:<6}] {r['rule']:<24} {where}")
            if r["rule"] != "Sensitive file":
                print(f"         {r['secret']}")
        counts = Counter(r["severity"] for r in results)
        print(f"\n[*] {len(results)} finding(s) in {scanned} file(s): "
              f"{counts[HIGH]} high, {counts[MEDIUM]} medium, {counts[LOW]} low", file=sys.stderr)
        if results and not args.show:
            print("[*] Secrets are masked. Rotate anything real; deleting it from the file isn't enough "
                  "if it was ever committed.", file=sys.stderr)
    elif args.format == "csv":
        fh = open(args.output, "w", newline="", encoding="utf-8") if args.output else sys.stdout
        w = csv.DictWriter(fh, fieldnames=["severity", "rule", "file", "line", "secret"], extrasaction="ignore")
        w.writeheader()
        w.writerows(results)
        if args.output:
            fh.close()
    else:
        data = json.dumps({"path": os.path.abspath(args.path),
                           "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                           "files_scanned": scanned, "findings": results}, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(data + "\n")
        else:
            print(data)
    if args.output:
        print(f"[*] Wrote {args.output}", file=sys.stderr)
    return 1 if results else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted", file=sys.stderr)
        sys.exit(130)
    except BrokenPipeError:  # e.g. piped into `head`
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
