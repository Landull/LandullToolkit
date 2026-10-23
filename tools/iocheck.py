#!/usr/bin/env python3
"""
iocheck - indicator of compromise (IOC) extractor.

Pulls URLs, domains, IPv4/IPv6 addresses, email addresses, file hashes,
CVE IDs, Bitcoin/Ethereum wallet addresses and Windows registry keys out of
logs, text files, emails (.eml/.mbox), PDFs, Office documents, ZIP/TAR/GZIP
archives and raw binaries. Defanged indicators (hxxp, [.], (dot), [@]) are
refanged automatically, and found hashes can be written straight into a
hashcheck known-hash list.

Standard library only. Python 3.8+.

https://github.com/Landull/iocheck
"""

import argparse
import csv
import datetime as dt
import email
import email.policy
import hashlib
import html
import io
import ipaddress
import json
import os
import re
import sys
import tarfile
import zipfile
import zlib
from urllib.parse import urlsplit

__version__ = "1.0.0"

CHUNK = 16 * 1024 * 1024           # read size when streaming big binaries
CARRY_MAX = 64 * 1024              # longest string carried between chunks
MAX_CONTAINER = 512 * 1024 * 1024  # biggest PDF/ZIP/EML loaded into memory
MAX_MEMBER = 64 * 1024 * 1024      # biggest archive member / PDF stream inflated
MAX_DEPTH = 4                      # nested containers (zip in eml in zip ...)
MIN_STRING = 5                     # shortest printable run pulled from binaries

TYPES = [
    ("url", "URLs"),
    ("domain", "Domains"),
    ("ipv4", "IPv4 addresses"),
    ("ipv6", "IPv6 addresses"),
    ("email", "Email addresses"),
    ("md5", "MD5 hashes"),
    ("sha1", "SHA-1 hashes"),
    ("sha256", "SHA-256 hashes"),
    ("sha512", "SHA-512 hashes"),
    ("cve", "CVE IDs"),
    ("btc", "Bitcoin addresses"),
    ("eth", "Ethereum addresses"),
    ("registry", "Registry keys"),
]
TYPE_ORDER = {t: i for i, (t, _) in enumerate(TYPES)}
HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}

# --------------------------------------------------------------------------
# Top-level domains
# --------------------------------------------------------------------------

CCTLDS = set("""
ac ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj
bm bn bo br bs bt bw by bz ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx
cy cz de dj dk dm do dz ec ee eg er es et eu fi fj fk fm fo fr ga gb gd ge gf
gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in io
iq ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls
lt lu lv ly ma mc md me mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz
na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps pt pw
py qa re ro rs ru rw sa sb sc sd se sg sh si sk sl sm sn so sr ss st su sv sx
sy sz tc td tf tg th tj tk tl tm tn to tr tt tv tw tz ua ug uk us uy uz va vc
ve vg vi vn vu wf ws ye yt za zm zw
""".split())

GTLDS = set("""
com net org edu gov mil int info biz name pro mobi asia tel travel jobs cat
coop aero museum xxx app dev page new how foo zip mov phd esq nexus rsvp meme
prof bot xyz top online site shop store tech club live space website fun icu
vip work link click cloud buzz rest bar cyou monster quest sbs cfd lol fyi
wiki blog news email digital agency today life world network services
solutions support tools zone center company group media studio design art
global city london nyc tokyo berlin paris download stream review party
science men win bid loan date faculty racing accountant trade webcam cricket
kim country mom best guru ninja rocks social host hosting domains systems
software tips ltd inc llc gmbh google microsoft apple amazon azure bing
windows office xbox skype goog youtube play gle security bank insurance
finance financial money cash exchange
onion local internal corp lan
""".split())

TLDS = CCTLDS | GTLDS

# TLDs that are also common file extensions. Outside a URL or an email
# address, "setup.py" or "notes.md" is far more likely a file than a domain.
AMBIGUOUS_TLDS = {
    "py", "sh", "md", "pl", "rs", "so", "ps", "cc", "ai", "tf", "mk", "ml",
    "pm", "mo", "am", "ac", "mm", "sc", "sv", "as", "gs", "cr",
    "zip", "mov", "app", "name",
}

# "self.name", "logger.info", "console.log" and friends in source code.
CODE_LABELS = {
    "self", "this", "args", "kwargs", "cls", "super", "os", "sys", "re", "np",
    "pd", "plt", "logger", "logging", "log", "obj", "window", "document",
    "console", "math", "json", "err", "ex", "e", "event", "req", "res",
}

# Namespace and schema hosts that flood Office/PDF/XMP output. Skipped
# unless --all is given.
NOISE_DOMAINS = {
    "w3.org", "openxmlformats.org", "purl.org", "ns.adobe.com",
    "schemas.microsoft.com", "xmlsoap.org", "oasis-open.org",
    "openoffice.org", "iptc.org", "ns.useplus.org", "schemas.android.com",
    "cipa.jp", "aiim.org", "npes.org", "ns.google.com", "xmlns.com",
}
NOISE_URL_PREFIXES = ("http://www.apple.com/dtds/",)

# --------------------------------------------------------------------------
# Patterns
# --------------------------------------------------------------------------

LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"

URL_RE = re.compile(
    r"(?<![\w.+-])[a-z][a-z0-9+.-]{1,15}://[^\s<>\"'`{}|\\^\[\]]+", re.I)
DOMAIN_RE = re.compile(
    r"(?<![\w@.-])((?:" + LABEL + r"\.)+[a-z][a-z0-9-]{0,62})"
    r"(?![\w-]|\.[a-z0-9]|@)", re.I)
EMAIL_RE = re.compile(
    r"(?<![\w.%+-])([a-z0-9][a-z0-9._%+-]{0,63})@"
    r"((?:" + LABEL + r"\.)+[a-z][a-z0-9-]{0,62})(?![\w-]|\.[a-z0-9])", re.I)
IPV4_RE = re.compile(
    r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\d|\.\d)")
IPV6_RE = re.compile(
    r"(?<![0-9A-Za-z_:.])((?:[0-9A-Fa-f]{0,4}:){2,7}"
    r"(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f]{0,4}))(?![0-9A-Za-z_:])")
HASH_RE = re.compile(
    r"(?<![0-9A-Za-z_])([0-9A-Fa-f]{128}|[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|"
    r"[0-9A-Fa-f]{32})(?![0-9A-Za-z_])")
CVE_RE = re.compile(r"\bCVE-(?:19|20)\d\d-\d{4,7}\b", re.I)
BTC_LEGACY_RE = re.compile(
    r"(?<![0-9A-Za-z])[13][1-9A-HJ-NP-Za-km-z]{25,34}(?![0-9A-Za-z])")
BTC_BECH32_RE = re.compile(
    r"(?<![0-9A-Za-z])bc1[02-9ac-hj-np-z]{11,71}(?![0-9A-Za-z])", re.I)
ETH_RE = re.compile(r"(?<![0-9A-Za-z])0x[0-9A-Fa-f]{40}(?![0-9A-Za-z])")
REG_SEG = r"[\w.{}()$#@~&+=-]+"
REGISTRY_RE = re.compile(
    r"(?<![\w])(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|"
    r"HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC):?"
    r"(?:\\" + REG_SEG + r"(?: " + REG_SEG + r")*(?=\\))*\\" + REG_SEG, re.I)

# Defanged forms: hxxp://evil[.]com, user[@]evil(dot)com, 1.2.3[.]4
REFANG_RULES = [
    (re.compile(r"\bh(?:xx|\*\*|XX)p(s?)(?=\[?:)", re.I), r"http\1"),
    (re.compile(r"\bfxp(?=\[?:)", re.I), "ftp"),
    (re.compile(r"\[\s*:\s*\]\s*//|\[://\]"), "://"),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\\\."), "."),
    (re.compile(r"\s?[\[({]\s*dot\s*[\])}]\s?", re.I), "."),
    (re.compile(r"\s?[\[({]\s*(?:@|at)\s*[\])}]\s?", re.I), "@"),
]
REFANG_HINT = re.compile(r"[\[({\\]|h[x*]{2}p|fxp", re.I)

PRINTABLE_ASCII = re.compile(rb"[\x20-\x7e\t]{%d,}" % MIN_STRING)
PRINTABLE_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_STRING)
STRING_BYTES = set(range(0x20, 0x7f)) | {0x09, 0x00}

EML_HEAD_RE = re.compile(
    rb"^(?:Return-Path|Received|Delivered-To|From|To|Subject|Date|Message-ID|"
    rb"MIME-Version|X-[\w-]+|ARC-[\w-]+|DKIM-Signature|Authentication-Results|"
    rb"Reply-To|Content-Type)[ \t]*:", re.I)
PDF_STREAM_RE = re.compile(rb"(?<!end)stream\r?\n")
BLOCK_TAG_RE = re.compile(
    r"</(?:w:p|a:p|text:p|text:h|p|div|li|tr|td|h\d)>|<br\s*/?>|<w:br/>", re.I)
TAG_RE = re.compile(r"<[^>]{0,2000}>")

# --------------------------------------------------------------------------
# Validation helpers
# --------------------------------------------------------------------------

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def refang(text):
    if not REFANG_HINT.search(text):
        return text
    for pattern, repl in REFANG_RULES:
        text = pattern.sub(repl, text)
    return text


def valid_domain(name, allow_ambiguous=False):
    if len(name) > 253:
        return False
    labels = name.split(".")
    if len(labels) < 2 or any(not l or len(l) > 63 for l in labels):
        return False
    tld = labels[-1]
    if tld not in TLDS:
        return False
    if not allow_ambiguous:
        if tld in AMBIGUOUS_TLDS:
            return False
        if labels[0] in CODE_LABELS and len(labels) == 2:
            return False
        # reverse-DNS identifiers: com.apple.security, org.mozilla.firefox
        if labels[0] in ("com", "org", "net", "io", "edu", "gov") and len(labels) >= 3:
            return False
    return True


PRIVATE_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")]
CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")
DOC_NETS = [ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]


def plausible_binary_domain(found):
    """Random bytes regularly spell things like 'qt.to' or '4x.il'. Inside raw
    binary strings, only keep lowercase names with a real-looking first label."""
    if found != found.lower():
        return False
    labels = found.split(".")
    sld = labels[-2]
    if len(sld) < 3 or not re.search(r"[a-z]{2}", sld):
        return False
    return len(labels) >= 3 or len(sld) >= 4 or labels[-1] in GTLDS


def ip_note(ip):
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_unspecified:
        return "unspecified"
    if any(ip in n for n in PRIVATE_NETS if n.version == ip.version):
        return "private"
    if ip.version == 4 and ip in CGNAT_NET:
        return "cgnat"
    if any(ip in n for n in DOC_NETS if n.version == ip.version):
        return "documentation"
    if not ip.is_global:
        return "reserved"
    return ""


def btc_legacy_ok(addr):
    n = 0
    for c in addr:
        n = n * 58 + B58.index(c)
    try:
        raw = n.to_bytes(25, "big")
    except OverflowError:
        return False
    if raw[0] not in (0x00, 0x05):
        return False
    check = hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4]
    return check == raw[-4:]


def bech32_ok(addr):
    addr = addr.lower()
    hrp, _, data = addr.rpartition("1")
    if hrp != "bc" or len(data) < 6:
        return False
    values = [BECH32.find(c) for c in data]
    if -1 in values:
        return False
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= gen[i]
    return chk in (1, 0x2BC830A3)   # bech32 (segwit v0) or bech32m (taproot)


def clean_url(url):
    for stop in ("&quot;", "&gt;", "&lt;", "&#", "&apos;"):
        i = url.find(stop)
        if i > 0:
            url = url[:i]
    while True:
        before = url
        url = url.rstrip(".,;:!?'\"*")
        if url.endswith(")") and url.count("(") < url.count(")"):
            url = url[:-1]
        if url == before:
            return url


# --------------------------------------------------------------------------
# Collector
# --------------------------------------------------------------------------

class Collector:
    def __init__(self, types=None, ignore=(), keep_noise=False, public_only=False):
        self.types = set(types) if types else set(TYPE_ORDER)
        self.ignore = {i.lower() for i in ignore}
        self.keep_noise = keep_noise
        self.public_only = public_only
        self.items = {}
        self.warnings = []

    def warn(self, msg):
        self.warnings.append(msg)

    def _host_ignored(self, host):
        sets = [self.ignore] if self.keep_noise else [self.ignore, NOISE_DOMAINS]
        for s in sets:
            parts = host.split(".")
            for i in range(len(parts) - 1):
                if ".".join(parts[i:]) in s:
                    return True
        return False

    def add(self, typ, value, src, loc, note=""):
        if typ not in self.types:
            return
        if value.lower() in self.ignore:
            return
        if typ == "domain" and self._host_ignored(value):
            return
        if typ == "email" and self._host_ignored(value.split("@", 1)[1]):
            return
        if typ == "url":
            host = urlsplit(value).hostname or ""
            if self._host_ignored(host):
                return
            if not self.keep_noise and value.lower().startswith(NOISE_URL_PREFIXES):
                return
        if self.public_only and typ in ("ipv4", "ipv6") and note:
            return
        key = (typ, value)
        rec = self.items.get(key)
        if rec is None:
            rec = self.items[key] = {
                "type": typ, "value": value, "count": 0, "note": note,
                "first_seen": f"{src} ({loc})" if loc else src, "sources": [],
            }
        rec["count"] += 1
        if src not in rec["sources"]:
            rec["sources"].append(src)

    def records(self):
        return sorted(self.items.values(), key=lambda r: TYPE_ORDER[r["type"]])


# --------------------------------------------------------------------------
# Scanning text
# --------------------------------------------------------------------------

def scan_text(text, src, loc, col, strict=False):
    """strict: text came from raw binary strings, so bare domains need to
    look more like real hostnames before they count."""
    if not text or len(text) < 4:
        return
    text = refang(text)
    t = col.types

    if "url" in t or "domain" in t:
        for m in URL_RE.finditer(text):
            url = clean_url(m.group())
            scheme, _, rest = url.partition("://")
            netloc = re.split(r"[/?#]", rest, maxsplit=1)[0]
            url = scheme.lower() + "://" + netloc.lower() + rest[len(netloc):]
            try:
                host = urlsplit(url).hostname
            except ValueError:
                continue
            if not host:
                continue
            try:
                ipaddress.ip_address(host)
                is_ip = True
            except ValueError:
                is_ip = False
                if not valid_domain(host, allow_ambiguous=True):
                    continue
            col.add("url", url, src, loc)
            if not is_ip:
                col.add("domain", host, src, loc)

    if "domain" in t:
        for m in DOMAIN_RE.finditer(text):
            if text[max(0, m.start() - 3):m.start()] == "://":
                continue    # already counted with its URL
            if text[m.end():m.end() + 1] == "(":
                continue    # method call in source code: match.group(0)
            found = m.group(1)
            name = found.lower()
            if strict and not plausible_binary_domain(found):
                continue
            if valid_domain(name):
                col.add("domain", name, src, loc)

    if "email" in t and "@" in text:
        for m in EMAIL_RE.finditer(text):
            domain = m.group(2).lower()
            if valid_domain(domain, allow_ambiguous=True):
                col.add("email", f"{m.group(1).lower()}@{domain}", src, loc)

    if "ipv4" in t and "." in text:
        for m in IPV4_RE.finditer(text):
            ip = ipaddress.IPv4Address(m.group())
            col.add("ipv4", str(ip), src, loc, ip_note(ip))

    if "ipv6" in t and ("::" in text or text.count(":") >= 7):
        for m in IPV6_RE.finditer(text):
            cand = m.group(1)
            if cand == "::" or (sum(c in "0123456789abcdefABCDEF" for c in cand) < 4
                                and cand != "::1"):
                continue
            try:
                ip = ipaddress.IPv6Address(cand)
            except ValueError:
                continue
            col.add("ipv6", ip.compressed, src, loc, ip_note(ip))

    if t & {"md5", "sha1", "sha256", "sha512"}:
        for m in HASH_RE.finditer(text):
            h = m.group(1).lower()
            if len(set(h)) < 6 or h.isdigit():
                continue
            if not col.keep_noise:
                s, e = m.start(1), m.end(1)
                if text[s - 1:s] == "<" and text[e:e + 1] == ">":
                    continue    # PDF document ID
                if re.search(r"(?:did|iid|docid|uuid|guid):\s*$",
                             text[max(0, s - 12):s], re.I):
                    continue    # XMP document/instance ID
            col.add(HASH_TYPES[len(h)], h, src, loc)

    if "cve" in t:
        for m in CVE_RE.finditer(text):
            col.add("cve", m.group().upper(), src, loc)

    if "btc" in t:
        for m in BTC_LEGACY_RE.finditer(text):
            if btc_legacy_ok(m.group()):
                col.add("btc", m.group(), src, loc)
        for m in BTC_BECH32_RE.finditer(text):
            v = m.group()
            if (v.islower() or v.isupper()) and bech32_ok(v):
                col.add("btc", v.lower(), src, loc)

    if "eth" in t and "0x" in text:
        for m in ETH_RE.finditer(text):
            col.add("eth", m.group(), src, loc)

    if "registry" in t and "\\" in text:
        for m in REGISTRY_RE.finditer(text):
            col.add("registry", m.group().rstrip("."), src, loc)


def decode_text(data):
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("cp1252", errors="replace")


def unescape_line(line):
    """Decode HTML entities (&amp; &#104;) so they don't split indicators."""
    return html.unescape(line) if "&" in line else line


def sub(loc, part):
    return f"{loc} > {part}" if loc else part


def scan_text_block(text, src, loc, col):
    """Scan decoded text line by line, plus HTML-unescaped and tag-stripped
    variants so entities and Word's split text runs don't hide indicators."""
    for n, line in enumerate(text.splitlines(), 1):
        scan_text(unescape_line(line), src, sub(loc, f"line {n}"), col)
    stripped = text.lstrip()
    if stripped.startswith("<") and ">" in stripped[:4096]:
        plain = TAG_RE.sub("", BLOCK_TAG_RE.sub("\n", text))
        plain = html.unescape(plain)
        for n, line in enumerate(plain.splitlines(), 1):
            if line.strip():
                scan_text(line, src, sub(loc, f"text {n}"), col)


def scan_strings(data, src, loc, col, base=0):
    for m in PRINTABLE_ASCII.finditer(data):
        scan_text(m.group().decode("ascii"), src,
                  sub(loc, f"offset 0x{base + m.start():x}"), col, strict=True)
    for m in PRINTABLE_UTF16.finditer(data):
        scan_text(m.group().decode("utf-16-le"), src,
                  sub(loc, f"offset 0x{base + m.start():x} utf16"), col, strict=True)


# --------------------------------------------------------------------------
# Containers
# --------------------------------------------------------------------------

def looks_text(head):
    if not head:
        return True
    if b"\x00" in head:
        return False
    ctrl = sum(1 for b in head if b < 9 or (13 < b < 32 and b != 27))
    return ctrl / len(head) < 0.02


def sniff(head, name=""):
    ext = os.path.splitext(name.lower())[1]
    if head.startswith(b"%PDF-"):
        return "pdf"
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "zip"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head[257:262] == b"ustar":
        return "tar"
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf16"
    if looks_text(head):
        if head.startswith(b"From ") and (
                ext in (".mbox", ".mbx")
                or re.search(rb"\n(?:Received|Return-Path|Message-ID|From):", head)):
            return "mbox"
        if ext == ".eml" or EML_HEAD_RE.match(head):
            return "eml"
        return "text"
    return "binary"


def extract_bytes(data, src, loc, col, depth=0, name=""):
    kind = sniff(data[:8192], name or loc or src)
    if depth > MAX_DEPTH and kind not in ("text", "utf16", "binary"):
        col.warn(f"{src}: {loc}: nested too deep, scanned as raw strings")
        kind = "binary"
    try:
        if kind == "pdf":
            extract_pdf(data, src, loc, col, depth)
        elif kind == "zip":
            extract_zip(data, src, loc, col, depth)
        elif kind == "tar":
            extract_tar(data, src, loc, col, depth)
        elif kind == "gzip":
            out = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(data, MAX_CONTAINER)
            inner = name[:-3] if name.lower().endswith(".gz") else ""
            extract_bytes(out, src, sub(loc, "gunzip"), col, depth + 1, inner)
        elif kind == "eml":
            extract_eml(data, src, loc, col, depth)
        elif kind == "mbox":
            parts = re.split(rb"(?m)^From [^\r\n]*\r?\n", data)
            for i, msg in enumerate((p for p in parts if p.strip()), 1):
                extract_eml(msg, src, sub(loc, f"message {i}"), col, depth)
        elif kind == "utf16":
            scan_text_block(data.decode("utf-16", errors="replace"), src, loc, col)
        elif kind == "text":
            scan_text_block(decode_text(data), src, loc, col)
        else:
            scan_strings(data, src, loc, col)
    except Exception as exc:  # malformed container: fall back to raw strings
        col.warn(f"{src}: {loc or kind}: {type(exc).__name__}: {exc}; "
                 f"scanned as raw strings")
        scan_strings(data, src, loc, col)


def extract_pdf(data, src, loc, col, depth):
    scan_strings(data, src, loc, col)          # uncompressed objects, /URI links
    n = 0
    for m in PDF_STREAM_RE.finditer(data):
        start = m.end()
        end = data.find(b"endstream", start)
        if end < 0:
            break
        n += 1
        try:
            out = zlib.decompressobj().decompress(data[start:end], MAX_MEMBER)
        except zlib.error:
            continue
        if out:
            extract_bytes(out, src, sub(loc, f"stream {n}"), col, depth + 1)


def extract_zip(data, src, loc, col, depth):
    zf = zipfile.ZipFile(io.BytesIO(data))
    names = [i.filename for i in zf.infolist()]
    scan_text("\n".join(names), src, sub(loc, "entry names"), col)
    for info in zf.infolist():
        if info.is_dir():
            continue
        if info.flag_bits & 0x1:
            col.warn(f"{src}: {sub(loc, info.filename)}: encrypted, skipped")
            continue
        try:
            with zf.open(info) as fh:
                blob = fh.read(MAX_MEMBER)
        except Exception as exc:
            col.warn(f"{src}: {sub(loc, info.filename)}: {exc}")
            continue
        if info.file_size > MAX_MEMBER:
            col.warn(f"{src}: {sub(loc, info.filename)}: only first "
                     f"{MAX_MEMBER // 1048576} MiB scanned")
        extract_bytes(blob, src, sub(loc, info.filename), col, depth + 1, info.filename)


def extract_tar(data, src, loc, col, depth):
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        for member in tf:
            if not member.isfile():
                continue
            fh = tf.extractfile(member)
            if fh is None:
                continue
            blob = fh.read(MAX_MEMBER)
            extract_bytes(blob, src, sub(loc, member.name), col, depth + 1, member.name)


def extract_eml(data, src, loc, col, depth):
    msg = email.message_from_bytes(data, policy=email.policy.default)
    for key, value in msg.raw_items():
        value = re.sub(r"\r?\n[ \t]+", " ", str(value))
        scan_text(value, src, sub(loc, f"header {key}"), col)
    n = 0
    for part in msg.walk():
        if part.is_multipart():
            continue
        n += 1
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        ctype = part.get_content_type()
        filename = part.get_filename()
        if filename or not ctype.startswith("text/"):
            label = f"attachment {filename}" if filename else f"part {n} ({ctype})"
            extract_bytes(payload, src, sub(loc, label), col, depth + 1, filename or "")
        else:
            charset = part.get_content_charset() or "utf-8"
            try:
                text = payload.decode(charset, errors="replace")
            except LookupError:
                text = decode_text(payload)
            scan_text_block(text, src, sub(loc, f"body {ctype}"), col)


# --------------------------------------------------------------------------
# Files on disk
# --------------------------------------------------------------------------

def scan_binary_stream(fh, src, col):
    """Pull strings out of an arbitrarily large file in chunks, carrying any
    string that straddles a chunk boundary into the next read."""
    carry = b""
    base = 0          # file offset of carry[0]
    while True:
        chunk = fh.read(CHUNK)
        data = carry + chunk
        if not chunk:
            if data:
                scan_strings(data, src, "", col, base)
            return
        cut = len(data)
        limit = max(0, len(data) - CARRY_MAX)
        while cut > limit and data[cut - 1] in STRING_BYTES:
            cut -= 1
        scan_strings(data[:cut], src, "", col, base)
        carry = data[cut:]
        base += cut


def scan_path(path, col):
    with open(path, "rb") as fh:
        head = fh.read(8192)
        kind = sniff(head, path)
        size = os.fstat(fh.fileno()).st_size
        fh.seek(0)
        if kind == "text":
            for n, raw in enumerate(fh, 1):
                line = decode_text(raw.rstrip(b"\r\n"))
                scan_text(unescape_line(line), path, f"line {n}", col)
        elif kind != "binary" and size <= MAX_CONTAINER:
            extract_bytes(fh.read(), path, "", col, 0, path)
        else:
            if kind != "binary":
                col.warn(f"{path}: larger than {MAX_CONTAINER // 1048576} MiB, "
                         f"scanned as raw strings")
            scan_binary_stream(fh, path, col)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def iter_files(target, recursive=True):
    if os.path.isfile(target):
        yield target
        return
    if recursive:
        for root, dirs, files in os.walk(target):
            dirs.sort()
            for name in sorted(files):
                yield os.path.join(root, name)
    else:
        for name in sorted(os.listdir(target)):
            path = os.path.join(target, name)
            if os.path.isfile(path):
                yield path


def load_list(path):
    out = set()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                out.add(refang(line.split(",")[0].strip()).lower())
    return out


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def defang(typ, value):
    if typ == "url":
        scheme, _, rest = value.partition("://")
        netloc = re.split(r"[/?#]", rest, maxsplit=1)[0]
        scheme = re.sub(r"^http", "hxxp", scheme)
        return f"{scheme}[://]{netloc.replace('.', '[.]')}{rest[len(netloc):]}"
    if typ in ("domain", "ipv4"):
        return value.replace(".", "[.]")
    if typ == "email":
        user, _, host = value.partition("@")
        return f"{user}[@]{host.replace('.', '[.]')}"
    if typ == "ipv6":
        return value.replace(":", "[:]")
    return value


def shown(rec, do_defang):
    return defang(rec["type"], rec["value"]) if do_defang else rec["value"]


def render_table(records, files, do_defang):
    out = [f"iocheck {__version__} | {len(files)} file(s) scanned | "
           f"{len(records)} indicator(s)"]
    if 0 < len(files) <= 20:
        for f in files:
            out.append(f"  {f['path']}  sha256 {f['sha256']}")
    labels = dict(TYPES)
    for typ, _ in TYPES:
        group = [r for r in records if r["type"] == typ]
        if not group:
            continue
        out.append(f"\n{labels[typ]} ({len(group)})")
        values = [shown(r, do_defang) + (f"  [{r['note']}]" if r["note"] else "")
                  for r in group]
        width = min(max(len(v) for v in values), 72)
        for r, v in zip(group, values):
            more = len(r["sources"]) - 1
            seen = r["first_seen"] + (f"  (+{more} more file{'s' if more > 1 else ''})"
                                      if more else "")
            out.append(f"  {v:<{width}}  {r['count']:>4}x  {seen}")
    if not records:
        out.append("\nNo indicators found.")
    return "\n".join(out) + "\n"


def render(records, files, warnings, fmt, do_defang):
    if fmt == "table":
        return render_table(records, files, do_defang)
    if fmt == "list":
        return "".join(shown(r, do_defang) + "\n" for r in records)
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["type", "value", "count", "note", "first_seen", "sources"])
        for r in records:
            w.writerow([r["type"], shown(r, do_defang), r["count"], r["note"],
                        r["first_seen"], "; ".join(r["sources"])])
        return buf.getvalue()
    doc = {
        "tool": "iocheck",
        "version": __version__,
        "generated": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "files": files,
        "indicators": [dict(r, value=shown(r, do_defang)) for r in records],
        "warnings": warnings,
    }
    return json.dumps(doc, indent=2) + "\n"


def write_hash_list(records, path):
    hashes = [r for r in records if r["type"] in ("md5", "sha1", "sha256")]
    stamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"# iocheck {__version__} - hashes extracted {stamp}\n")
        fh.write("# usage: python hashcheck.py <folder> -k this-file --matches-only\n")
        for r in hashes:
            label = re.sub(r"[,\r\n]", ";", f"iocheck: {r['first_seen']}")
            fh.write(f"{r['value']},{label}\n")
    return len(hashes)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="iocheck",
        description="Extract indicators of compromise (URLs, domains, IPs, emails, "
                    "hashes, CVEs, wallets, registry keys) from files and folders.",
    )
    p.add_argument("targets", nargs="+", metavar="target",
                   help="file or folder to scan ('-' reads from stdin)")
    p.add_argument("-t", "--type", action="append", choices=[t for t, _ in TYPES],
                   help="only extract this type (repeatable)")
    p.add_argument("-x", "--exclude", metavar="FILE",
                   help="allowlist of values or domains to ignore, one per line")
    p.add_argument("--public-only", action="store_true",
                   help="drop private, loopback and reserved IP addresses")
    p.add_argument("--all", action="store_true",
                   help="keep schema/namespace noise (w3.org, openxmlformats.org, "
                        "PDF and XMP document IDs)")
    p.add_argument("--defang", action="store_true",
                   help="defang output (hxxp, [.]) so it's safe to paste into reports")
    p.add_argument("--hashes-out", metavar="FILE",
                   help="also write found hashes as a hashcheck known-hash list (-k)")
    p.add_argument("-n", "--no-recurse", action="store_true",
                   help="don't descend into subfolders")
    p.add_argument("-f", "--format", choices=("table", "list", "csv", "json"),
                   default="table", help="output format (default: table)")
    p.add_argument("-o", "--output", metavar="FILE", help="write output to a file")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    ignore = set()
    if args.exclude:
        try:
            ignore = load_list(args.exclude)
        except OSError as exc:
            print(f"[!] Can't read allowlist: {exc}", file=sys.stderr)
            return 2

    col = Collector(args.type, ignore, keep_noise=args.all, public_only=args.public_only)
    files = []

    for target in args.targets:
        if target == "-":
            data = sys.stdin.buffer.read()
            extract_bytes(data, "<stdin>", "", col)
            files.append({"path": "<stdin>", "size": len(data),
                          "sha256": hashlib.sha256(data).hexdigest()})
            continue
        if not os.path.exists(target):
            print(f"[!] Not found: {target}", file=sys.stderr)
            return 2
        for path in iter_files(target, not args.no_recurse):
            try:
                scan_path(path, col)
                files.append({"path": path, "size": os.path.getsize(path),
                              "sha256": sha256_file(path)})
            except OSError as exc:
                col.warn(f"{path}: {exc.strerror or exc}")

    records = col.records()
    text = render(records, files, col.warnings, args.format, args.defang)
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        print(f"[*] {len(records)} indicator(s) written to {args.output}", file=sys.stderr)
    else:
        try:
            sys.stdout.write(text)
            sys.stdout.flush()
        except BrokenPipeError:
            sys.stderr.close()

    if args.hashes_out:
        n = write_hash_list(records, args.hashes_out)
        print(f"[*] {n} hash(es) written to {args.hashes_out} "
              f"(use with hashcheck -k)", file=sys.stderr)

    if args.format != "json":
        for w in col.warnings:
            print(f"[!] {w}", file=sys.stderr)

    return 1 if records else 0


if __name__ == "__main__":
    sys.exit(main())
