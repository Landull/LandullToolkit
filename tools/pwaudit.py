#!/usr/bin/env python3
"""
pwaudit - score password strength and check it against known breaches.

Estimates how hard a password is to guess (length, character variety,
common words, keyboard walks, sequences, dates) and checks it against
Have I Been Pwned's breach corpus using k-anonymity: only the first five
characters of the password's SHA-1 hash ever leave your machine.

Standard library only. Python 3.8+.
"""

import argparse
import getpass
import hashlib
import json
import math
import os
import re
import ssl
import subprocess
import sys
import urllib.error
import urllib.request

__version__ = "1.0.0"

HIBP_URL = "https://api.pwnedpasswords.com/range/"
GUESSES_PER_SEC = 1e10  # offline attack, fast hash, one modern GPU rig

COMMON = {
    "password", "passw0rd", "letmein", "welcome", "admin", "administrator", "qwerty",
    "dragon", "monkey", "football", "baseball", "master", "shadow", "sunshine",
    "princess", "iloveyou", "trustno1", "superman", "batman", "login", "starwars",
    "hello", "freedom", "whatever", "michael", "charlie", "secret", "summer", "winter",
    "spring", "autumn", "changeme", "default", "guest", "root", "test", "access",
    "computer", "internet", "mustang", "pokemon", "minecraft", "fortnite", "hunter",
    "ranger", "jordan", "soccer", "hockey", "killer", "pepper", "cheese", "cookie",
    "family", "flower", "ginger", "purple", "orange", "yellow", "silver", "golden",
}
KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "qazwsxedc", "!@#$%^&*()")
LEET = str.maketrans("4@38!1|0$5+7", "aaebiiiosstt")


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


def pool_size(pw):
    pool = 0
    if re.search(r"[a-z]", pw):
        pool += 26
    if re.search(r"[A-Z]", pw):
        pool += 26
    if re.search(r"[0-9]", pw):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", pw):
        pool += 33
    if any(ord(c) > 127 for c in pw):
        pool += 100
    return max(pool, 1)


def find_patterns(pw):
    """Return list of (pattern description, characters it covers)."""
    found = []
    low = pw.lower()
    plain = low.translate(LEET)

    for word in sorted(COMMON, key=len, reverse=True):
        if word in low or word in plain:
            found.append((f"common word '{word}'", len(word)))
            break

    for row in KEYBOARD_ROWS:
        for n in range(len(row), 3, -1):
            hit = next((row[i:i + n] for i in range(len(row) - n + 1)
                        if row[i:i + n] in low or row[i:i + n][::-1] in low), None)
            if hit:
                found.append((f"keyboard walk '{hit}'", len(hit)))
                break

    run = 1
    best = 1
    for a, b in zip(low, low[1:]):
        run = run + 1 if ord(b) - ord(a) in (1, -1) and a.isalnum() and b.isalnum() else 1
        best = max(best, run)
    if best >= 4:
        found.append((f"sequence of {best} characters", best))

    for rep in re.finditer(r"(.)\1{2,}", pw):
        found.append((f"repeated character '{rep.group(1)}' x{len(rep.group(0))}", len(rep.group(0))))

    chunk = re.search(r"(.{2,})\1+", pw)
    if chunk and len(chunk.group(0)) >= 4 and len(set(chunk.group(1))) > 1:
        found.append((f"repeated chunk '{chunk.group(1)}'", len(chunk.group(0)) - len(chunk.group(1))))

    year = re.search(r"(19[5-9]\d|20[0-4]\d)", pw)
    if year:
        found.append((f"year '{year.group(1)}'", 4))

    if re.fullmatch(r"[A-Z]?[a-z]+\d{1,4}[!@#$%?.]?", pw):
        found.append(("predictable shape (Word + digits + symbol)", 0))
    return found


def analyze(pw):
    length = len(pw)
    pool = pool_size(pw)
    raw_bits = length * math.log2(pool)
    patterns = find_patterns(pw)
    # Characters covered by a guessable pattern only add ~1 bit each
    covered = min(length, sum(n for _, n in patterns))
    bits = (length - covered) * math.log2(pool) + covered * 1.0
    if any("shape" in p for p, _ in patterns):
        bits *= 0.7
    bits = max(0.0, min(bits, raw_bits))

    if bits < 28:
        score, label = 0, "very weak"
    elif bits < 40:
        score, label = 1, "weak"
    elif bits < 60:
        score, label = 2, "fair"
    elif bits < 80:
        score, label = 3, "strong"
    else:
        score, label = 4, "very strong"

    tips = []
    if length < 12:
        tips.append("use 12+ characters (a 4-5 word passphrase is easiest)")
    if pool < 62 and length < 16:
        tips.append("mix upper, lower, digits and symbols, or go longer")
    if patterns:
        tips.append("avoid common words, keyboard walks, sequences and years")

    return {
        "length": length,
        "charset_size": pool,
        "entropy_bits": round(bits, 1),
        "score": score,
        "rating": label,
        "crack_time": human_time(2 ** bits / 2 / GUESSES_PER_SEC),
        "patterns": [p for p, _ in patterns],
        "tips": tips,
    }


def human_time(seconds):
    if seconds < 1:
        return "instant"
    for unit, size in (("centuries", 3.15e9), ("years", 3.15e7), ("days", 86400),
                       ("hours", 3600), ("minutes", 60), ("seconds", 1)):
        if seconds >= size:
            value = seconds / size
            if unit == "centuries" and value > 1e6:
                return "millions of years+"
            return f"{value:,.0f} {unit}"
    return "instant"


def pwned_count(pw, timeout=10):
    """Times this password appears in HIBP, via k-anonymity range lookup."""
    sha1 = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    req = urllib.request.Request(HIBP_URL + prefix, headers={
        "User-Agent": f"pwaudit/{__version__}",
        "Add-Padding": "true",  # hides how many real suffixes the range has
    })
    with urllib.request.urlopen(req, timeout=timeout, context=ssl_context()) as resp:
        body = resp.read().decode("ascii", "replace")
    for line in body.splitlines():
        hash_suffix, _, count = line.partition(":")
        if hash_suffix.strip() == suffix:
            return int(count.strip() or 0)
    return 0


def mask(pw):
    """Never echo any part of the password, only its length."""
    return "*" * min(len(pw), 24)


def audit(pw, offline=False):
    rec = analyze(pw)
    if offline:
        rec["breached"] = None
    else:
        try:
            rec["breach_count"] = pwned_count(pw)
            rec["breached"] = rec["breach_count"] > 0
        except (urllib.error.URLError, OSError) as err:
            rec["breached"] = None
            rec["breach_error"] = str(getattr(err, "reason", err))
    if rec.get("breached"):
        rec["score"] = 0
        rec["rating"] = "breached"
    return rec


def print_report(label, rec, use_color):
    def c(text, code):
        return f"\033[{code}m{text}\033[0m" if use_color else text
    colors = {0: "31", 1: "31", 2: "33", 3: "32", 4: "32"}
    print(f"{label}")
    print(f"  Rating      {c(rec['rating'].upper(), colors[rec['score']])}  ({rec['score']}/4)")
    print(f"  Length      {rec['length']}  (character set of {rec['charset_size']})")
    print(f"  Entropy     ~{rec['entropy_bits']} bits")
    print(f"  Crack time  {rec['crack_time']}  (offline, 10 billion guesses/sec)")
    if rec.get("breached"):
        print(f"  Breaches    {c('FOUND', '31')} in {rec['breach_count']:,} breach records; never use it")
    elif rec.get("breached") is False:
        print(f"  Breaches    {c('not found', '32')} in Have I Been Pwned")
    elif "breach_error" in rec:
        print(f"  Breaches    couldn't check ({rec['breach_error']})")
    else:
        print("  Breaches    skipped (--offline)")
    for p in rec["patterns"]:
        print(f"  [!] {p}")
    for t in rec["tips"]:
        print(f"  [+] {t}")


def parse_args(argv):
    p = argparse.ArgumentParser(
        prog="pwaudit",
        description="Score password strength and check Have I Been Pwned (k-anonymity).")
    p.add_argument("--stdin", action="store_true",
                   help="read passwords from stdin, one per line, instead of prompting")
    p.add_argument("--offline", action="store_true", help="don't query Have I Been Pwned")
    p.add_argument("-f", "--format", choices=("table", "json"), default="table", help="output format")
    p.add_argument("-o", "--output", metavar="FILE", help="write JSON results to a file")
    p.add_argument("--no-color", action="store_true", help="plain output without colors")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.stdin:
        passwords = [l.rstrip("\r\n") for l in sys.stdin if l.rstrip("\r\n")]
    else:
        try:
            pw = getpass.getpass("Password (hidden): ")
        except (KeyboardInterrupt, EOFError):
            print()
            return 2
        passwords = [pw] if pw else []
    if not passwords:
        print("[!] No password given.", file=sys.stderr)
        return 2

    use_color = sys.stdout.isatty() and not args.no_color
    results = []
    for i, pw in enumerate(passwords, 1):
        rec = audit(pw, args.offline)
        rec = {"id": i, "masked": mask(pw), **rec}
        results.append(rec)
        if args.format == "table":
            if i > 1:
                print()
            label = f"#{i} {rec['masked']}" if len(passwords) > 1 else rec["masked"]
            print_report(label, rec, use_color)

    if args.format == "json" or args.output:
        data = json.dumps(results if len(results) > 1 else results[0], indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(data + "\n")
            print(f"[*] Wrote {args.output}", file=sys.stderr)
        else:
            print(data)

    return 1 if any(r["breached"] or r["score"] < 2 for r in results) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted", file=sys.stderr)
        sys.exit(130)
    except BrokenPipeError:  # e.g. piped into `head`
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
