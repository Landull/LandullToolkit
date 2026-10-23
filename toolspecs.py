"""
Tool definitions for the Landull Toolkit GUI.

Every one of the 18 command-line tools is described here as a list of form
fields. The GUI builds its input forms from these, and build_argv() turns the
filled-in form back into the exact command-line arguments the tool expects.
This file has no GUI code so it can be tested on its own.
"""

import re
import shlex

KITS = [
    ("forensickit", "Forensic", "Investigate files, browsers and timelines after an incident.", "#d9a441"),
    ("auditkit", "Audit", "Check how well a site, domain, password or computer is configured.", "#6fa8dc"),
    ("scankit", "Scan", "Discover devices, ports, subdomains, Wi-Fi, logins and leaked secrets.", "#7cc47f"),
]


# ---------------------------------------------------------------- field helpers
def F(key, kind, label, flag=None, **kw):
    d = {"key": key, "kind": kind, "label": label, "flag": flag}
    d.update(kw)
    return d


def fmt(choices, default=None):
    return F("format", "choice", "Output format", "-f", choices=choices, default=default or choices[0],
             help="How results are laid out. 'table' is easiest to read; csv/json are for spreadsheets or other tools.",
             group="output")


def out(label="Also save results to a file", help="Pick where to save a copy of the results.", **kw):
    return F("output", "path", label, "-o", mode="save", group="output", help=help, **kw)


def chk(key, flag, label, help="", adv=False):
    return F(key, "check", label, flag, help=help, adv=adv)


def num(key, flag, label, default, help="", adv=True, decimals=False):
    return F(key, "number", label, flag, placeholder=str(default), help=help, adv=adv, decimals=decimals)


NO_RECURSE = lambda: chk("no_recurse", "-n", "Don't look inside subfolders", "Only check the top level of the folder.", adv=True)


# ---------------------------------------------------------------- the 18 tools
TOOLS = [
    # ============================================================ forensickit
    {
        "name": "hashcheck", "kit": "forensickit",
        "tagline": "Fingerprint files with MD5 / SHA-1 / SHA-256",
        "desc": "Computes cryptographic hashes for a file or every file in a folder. Use it to prove evidence "
                "hasn't changed, check a download against a published hash, or sweep a folder for known-bad files.",
        "fields": [
            F("target", "path", "File or folder to hash", None, mode="any", required=True,
              help="Drag a file or folder here, paste a path, or use the buttons."),
            F("verify", "text", "Expected hash (optional)", "-v", placeholder="paste a hash to verify a single file",
              help="Checks one file against a hash you already have and tells you if it matches."),
            F("known", "path", "Known-hash list (optional)", "-k", mode="file",
              help="A text file of hashes (one per line). Any file that matches is flagged. iocheck can create one."),
            chk("matches_only", "--matches-only", "Only show files that match the known-hash list"),
            F("algo", "multi", "Algorithms", "-a", choices=["md5", "sha1", "sha256"], adv=True,
              help="Leave all unticked to compute all three."),
            NO_RECURSE(),
            fmt(["table", "csv", "json"]), out(),
        ],
    },
    {
        "name": "metacheck", "kit": "forensickit",
        "tagline": "Pull hidden metadata from photos, PDFs and Office files",
        "desc": "Extracts metadata such as camera model, GPS location, author names, editing software, "
                "PDF revision history and Office macros, and flags anything forensically interesting.",
        "fields": [
            F("paths", "paths", "Files or folders to examine", None, mode="any", required=True,
              help="Images (JPEG, PNG, HEIC, RAW...), PDFs and Office documents."),
            chk("findings_only", "--findings-only", "Only show files with findings"),
            F("kml", "path", "Save GPS locations as a map file (.kml)", "--kml", mode="save", save_filter="KML (*.kml)",
              help="Every GPS location found is written to a file you can open in Google Earth."),
            F("thumbs", "path", "Save embedded thumbnails to folder", "--thumbs", mode="dir", adv=True,
              help="Photos often carry a small preview image that can differ from the real photo."),
            chk("all_tags", "--all-tags", "Include unnamed EXIF tags", adv=True),
            chk("no_hash", "--no-hash", "Skip SHA-256 hashing (faster)", adv=True),
            NO_RECURSE(),
            fmt(["text", "csv", "json"]), out(),
        ],
    },
    {
        "name": "iocheck", "kit": "forensickit",
        "tagline": "Extract indicators of compromise from anything",
        "desc": "Finds URLs, domains, IP addresses, emails, hashes, CVE IDs, crypto wallets and registry keys in "
                "logs, emails, PDFs, Office docs, archives and binaries. Defanged indicators like hxxp://evil[.]com "
                "are recognized automatically.",
        "fields": [
            F("target", "paths", "Files or folders to scan", None, mode="any", required=True),
            F("type", "multi", "Only extract these types", "-t",
              choices=["url", "domain", "ipv4", "ipv6", "email", "md5", "sha1", "sha256", "sha512", "cve", "btc",
                       "eth", "registry"],
              help="Leave all unticked to extract everything."),
            chk("public_only", "--public-only", "Drop private / local IP addresses",
                "Useful when building a blocklist."),
            chk("defang", "--defang", "Defang output (safe to paste into reports)", "Turns http into hxxp and . into [.]"),
            F("hashes_out", "path", "Save found hashes as a hashcheck list", "--hashes-out", mode="save",
              save_filter="Text (*.txt)", adv=True,
              help="Writes every hash found in a format hashcheck can sweep a machine with."),
            F("exclude", "path", "Allowlist file (values to ignore)", "-x", mode="file", adv=True),
            chk("all", "--all", "Keep schema/namespace noise", "Normally w3.org, openxmlformats.org etc. are hidden.", adv=True),
            NO_RECURSE(),
            fmt(["table", "list", "csv", "json"]), out(),
        ],
    },
    {
        "name": "histcheck", "kit": "forensickit",
        "tagline": "Browser history as one timeline",
        "desc": "Reads visits, downloads and searches from Chrome, Edge, Brave, Opera, Vivaldi, Arc, Firefox and "
                "Safari, and flags risky downloads. Databases are copied first, so the originals are never touched.",
        "fields": [
            chk("live", "--live", "Read this computer's browsers (my own history)",
                "Finds every browser profile for the current user. On a Mac, the app may need Full Disk Access to read Safari."),
            F("target", "paths", "...or history files / evidence folders", None, mode="any",
              help="A History / places.sqlite / History.db file, a profile folder, or a whole evidence folder."),
            F("type", "multi", "Record types", "-t", choices=["visit", "download", "search"],
              help="Leave unticked for all three."),
            F("since", "text", "From date", "--since", placeholder="YYYY-MM-DD or YYYY-MM-DD HH:MM"),
            F("until", "text", "To date", "--until", placeholder="YYYY-MM-DD or YYYY-MM-DD HH:MM"),
            F("grep", "texts", "Only records containing", "-g", placeholder="text, other text", split="comma",
              help="Separate several search terms with commas."),
            F("domain", "texts", "Only these domains", "-d", placeholder="example.com, other.org", split="ws"),
            chk("flagged", "--flagged", "Only flagged records (!)"),
            chk("local", "--local", "Show times in my time zone (instead of UTC)", adv=True),
            chk("summary", "--summary", "Summary only (per-source counts and top sites)", adv=True),
            chk("full", "--full", "Don't shorten long URLs/titles", adv=True),
            NO_RECURSE(),
            fmt(["table", "csv", "json"]), out(),
        ],
        "require_one_of": [("live", "target"), "Tick 'Read this computer's browsers' or add a history file/folder."],
    },
    {
        "name": "timecheck", "kit": "forensickit",
        "tagline": "Merge everything into one sorted timeline",
        "desc": "Builds a single UTC timeline from file-system times, bodyfiles, histcheck/metacheck output, CSV "
                "exports and logs, and flags timestomping, deleted entries, executables in user folders and "
                "suspicious log lines.",
        "fields": [
            F("target", "paths", "Folders or files to include", None, mode="any", required=True,
              help="A folder (its file times are used), or files: bodyfile, histcheck/metacheck CSV/JSON, CSV export or log."),
            F("since", "text", "From date", "--since", placeholder="YYYY-MM-DD or YYYY-MM-DD HH:MM"),
            F("until", "text", "To date", "--until", placeholder="YYYY-MM-DD or YYYY-MM-DD HH:MM"),
            F("around", "text", "Focus around a moment", "--around", placeholder="YYYY-MM-DD HH:MM",
              help="Show only events near this time; the moment is marked in the table."),
            F("window", "text", "...within", "--window", placeholder="15m  (e.g. 90s, 15m, 2h, 1d)"),
            F("source", "multi", "Only these sources", "-s", choices=["fs", "bodyfile", "browser", "metadata", "log", "csv"]),
            F("grep", "texts", "Only events containing", "-g", placeholder="text, other text", split="comma"),
            chk("flagged", "--flagged", "Only flagged events (!)"),
            F("macb", "text", "MACB letters", "--macb", placeholder="e.g. b or mb", adv=True,
              help="File events only if they include one of these: m=modified a=accessed c=changed b=born."),
            F("exclude", "texts", "Skip paths matching", "-x", placeholder="*.tmp, node_modules", split="comma", adv=True),
            F("time_col", "texts", "CSV time column(s)", "--time-col", placeholder="column name", split="comma", adv=True),
            F("tz", "text", "Time zone for times without one", "--tz", placeholder="UTC, local, or -05:00", adv=True),
            num("year", "--year", "Year for syslog lines", "this year",
                help="Syslog lines don't include a year, so say which one they're from."),
            chk("local", "--local", "Show times in my time zone (instead of UTC)", adv=True),
            chk("summary", "--summary", "Summary only (per-source counts, busiest hours)", adv=True),
            chk("full", "--full", "Don't shorten long lines", adv=True),
            NO_RECURSE(),
            fmt(["table", "csv", "json"]), out(),
        ],
    },
    {
        "name": "sigcheck", "kit": "forensickit",
        "tagline": "Catch files pretending to be something else",
        "desc": "Reads each file's magic bytes to find its real type, then flags extension mismatches, data hidden "
                "after the end of a file, Office macros, active PDF content, disguised executables and "
                "right-to-left filename tricks.",
        "fields": [
            F("target", "paths", "Files or folders to check", None, mode="any",
              help="By default only problem files are listed."),
            chk("all", "-a", "Show every file, not just problems"),
            chk("flagged", "--flagged", "Only files with findings (!)"),
            F("status", "multi", "Only these statuses", "--status", choices=["match", "mismatch", "unknown", "empty", "error"]),
            chk("hash", "--hash", "Add SHA-256 of each file"),
            chk("summary", "--summary", "Add content-type and mismatch counts", adv=True),
            F("exclude", "texts", "Skip paths matching", "-x", placeholder="*.log, .git", split="comma", adv=True),
            num("max_scan", "--max-scan", "Largest file to scan in full (MB)", 256),
            chk("types", "--types", "Just list the file types sigcheck recognizes", adv=True),
            NO_RECURSE(),
            fmt(["table", "csv", "json"]), out(),
        ],
        "require_one_of": [("target", "types"), "Add a file or folder to check."],
    },

    # ============================================================ auditkit
    {
        "name": "headeraudit", "kit": "auditkit",
        "tagline": "Grade a website's security headers",
        "desc": "Fetches a site and grades its HTTP security headers (CSP, HSTS, X-Frame-Options...) and cookie "
                "flags, with a plain-English explanation of anything missing.",
        "fields": [
            F("urls", "texts", "Websites", None, placeholder="example.com, https://shop.example.com", split="ws",
              help="One or more sites, separated by commas or spaces."),
            F("input", "path", "...or a file of URLs (one per line)", "-i", mode="file", adv=True),
            chk("verbose", "-v", "Show the raw header values"),
            chk("no_follow", "--no-follow", "Don't follow redirects", adv=True),
            chk("insecure", "-k", "Don't verify the TLS certificate", adv=True),
            num("timeout", "-t", "Timeout (seconds)", 10),
            fmt(["table", "json"]), out("Also save results as JSON"),
        ],
        "require_one_of": [("urls", "input"), "Enter at least one website."],
        "fixed": ["--no-color"],
    },
    {
        "name": "mailaudit", "kit": "auditkit",
        "tagline": "Check a domain's SPF, DKIM and DMARC",
        "desc": "Looks up a domain's email-authentication records and explains whether someone could spoof email "
                "from it.",
        "fields": [
            F("domains", "texts", "Domains", None, placeholder="example.com, other.org", split="ws"),
            F("selector", "texts", "Extra DKIM selectors", "-s", placeholder="e.g. google, selector1", split="ws",
              help="Common selectors are tried automatically; add your provider's if you know it."),
            chk("no_dkim", "--no-dkim", "Skip DKIM checks"),
            chk("verbose", "-v", "Show the raw DNS records"),
            F("input", "path", "...or a file of domains (one per line)", "-i", mode="file", adv=True),
            fmt(["table", "json"]), out("Also save results as JSON"),
        ],
        "require_one_of": [("domains", "input"), "Enter at least one domain."],
        "fixed": ["--no-color"],
    },
    {
        "name": "certaudit", "kit": "auditkit",
        "tagline": "TLS certificate expiry and protocol check",
        "desc": "Connects to each host and checks the certificate chain, hostname, expiry date, key strength and "
                "whether old TLS 1.0/1.1 are still enabled.",
        "fields": [
            F("targets", "texts", "Hosts", None, placeholder="example.com, mail.example.com:993", split="ws",
              help="host, host:port or a full URL."),
            num("warn_days", "-w", "Warn when expiry is within (days)", 30, adv=False),
            chk("no_legacy", "--no-legacy", "Skip TLS 1.0/1.1 tests (faster)"),
            chk("summary", "-s", "One line per host", adv=True),
            chk("detail", "-d", "Full detail even for many hosts", adv=True),
            F("input", "path", "...or a file of hosts (one per line)", "-i", mode="file", adv=True),
            num("port", "-p", "Default port", 443),
            num("timeout", "-t", "Timeout (seconds)", 8),
            num("threads", "-j", "Parallel workers", 10),
            fmt(["table", "csv", "json"]), out(),
        ],
        "require_one_of": [("targets", "input"), "Enter at least one host."],
        "fixed": ["--no-color"],
    },
    {
        "name": "pwaudit", "kit": "auditkit",
        "tagline": "Password strength + Have I Been Pwned check",
        "desc": "Scores a password's strength and checks whether it appears in known data breaches. Only the first "
                "5 characters of the password's SHA-1 hash ever leave your computer (k-anonymity), and the "
                "password itself is never shown or saved.",
        "fields": [
            F("password", "password", "Password to check", None, required=True, stdin=True),
            chk("offline", "--offline", "Offline only (don't check Have I Been Pwned)"),
            fmt(["table", "json"]), out("Also save results as JSON"),
        ],
        "fixed": ["--stdin", "--no-color"],
    },
    {
        "name": "useraudit", "kit": "auditkit",
        "tagline": "Audit this computer's user accounts",
        "desc": "Lists local accounts on this computer and flags risky ones: too many admins, accounts with no "
                "password, stale accounts that haven't logged in for months, and more.",
        "fields": [
            num("stale_days", "-d", "Flag accounts unused for (days)", 90, adv=False),
            num("max_admins", "-m", "Warn above this many admins", 2, adv=False),
            chk("all", "-a", "Also list Linux system accounts", adv=True),
            fmt(["table", "csv", "json"]), out(),
        ],
        "fixed": ["--no-color"],
    },
    {
        "name": "sysaudit", "kit": "auditkit",
        "tagline": "One-click report on this computer",
        "desc": "Builds a report of this computer's hardware, OS, security settings (firewall, disk encryption, "
                "updates, antivirus) and installed software. Choose 'html' and a save location for a shareable report.",
        "fields": [
            chk("software", "-s", "List installed software"),
            fmt(["table", "json", "html"]), out("Save report to a file", "Needed for the html format."),
        ],
        "fixed": ["--no-color"],
    },

    # ============================================================ scankit
    {
        "name": "netscan", "kit": "scankit",
        "tagline": "Find every device on your network",
        "desc": "Discovers devices on your local network with their IP, MAC address, vendor and hostname. Save a "
                "baseline, then compare later to spot new or unknown devices.",
        "fields": [
            F("network", "text", "Network range (optional)", None, placeholder="leave blank for your local /24, or 192.168.1.0/24"),
            F("save", "path", "Save this scan as a baseline", "-s", mode="save", save_filter="JSON (*.json)"),
            F("diff", "path", "Compare against a saved baseline", "-d", mode="file"),
            chk("no_dns", "--no-dns", "Skip hostname lookups (faster)", adv=True),
            chk("no_tcp", "--no-tcp", "Ping only, skip the TCP probe", adv=True),
            chk("update_oui", "--update-oui", "Download the latest vendor list first", adv=True),
            F("oui", "path", "Vendor list file", "--oui", mode="file", adv=True),
            num("threads", "-j", "Parallel workers", 64),
            num("timeout", "-t", "Per-host timeout (ms)", 700),
            fmt(["table", "csv", "json"]), out(),
        ],
        "warning": "Only scan networks you own or have permission to test.",
    },
    {
        "name": "portscan", "kit": "scankit",
        "tagline": "See which ports are open, and what's on them",
        "desc": "A fast TCP connect scanner that lists open ports and grabs service banners so you can see what "
                "software is listening.",
        "fields": [
            F("targets", "texts", "Targets", None, placeholder="192.168.1.10, example.com, 10.0.0.0/24", split="ws",
              required=True, help="Hosts, IPs or ranges (up to a /22)."),
            F("ports", "text", "Ports", "-p", placeholder="top  (or all, or 22,80,443,8000-8100)",
              help="Blank = ~90 most common ports."),
            chk("no_banner", "--no-banner", "Don't grab service banners (faster)", adv=True),
            num("threads", "-j", "Parallel workers", 200),
            num("timeout", "-t", "Connect timeout (seconds)", 0.8, decimals=True),
            fmt(["table", "csv", "json"]), out(),
        ],
        "warning": "Only scan systems you own or have permission to test.",
    },
    {
        "name": "subscan", "kit": "scankit",
        "tagline": "Find a domain's subdomains",
        "desc": "Finds subdomains from public certificate-transparency logs (crt.sh, CertSpotter) without sending "
                "a single packet to the target. Optionally checks which ones are live.",
        "fields": [
            F("domain", "text", "Domain", None, placeholder="example.com", required=True),
            chk("resolve", "-r", "Resolve each name and show live IPs"),
            chk("live_only", "-l", "Hide names that don't resolve (with the option above)"),
            F("source", "choice", "Source", "-s", choices=["all", "crtsh", "certspotter"], default="all", adv=True),
            num("threads", "-j", "Parallel workers", 20),
            num("timeout", "-t", "Request timeout (seconds)", 30),
            fmt(["table", "txt", "csv", "json"]), out(),
        ],
    },
    {
        "name": "wifiscan", "kit": "scankit",
        "tagline": "Nearby Wi-Fi networks and weak security",
        "desc": "Lists Wi-Fi networks around you with signal, channel and security type, and flags open or "
                "weakly protected (WEP/WPA1/TKIP) networks.",
        "fields": [
            chk("issues", "-a", "Only show networks with problems"),
            fmt(["table", "csv", "json"]), out(),
        ],
        "fixed": ["--no-color"],
    },
    {
        "name": "logscan", "kit": "scankit",
        "tagline": "Spot brute-force and password-spray attempts",
        "desc": "Summarizes failed logins from Linux/macOS auth logs or Windows event 4625 exports, and flags IPs "
                "that look like brute force or password spraying.",
        "fields": [
            F("files", "paths", "Log files (optional)", None, mode="file",
              help="auth.log (.gz ok) or a wevtutil XML export. Leave empty to read this computer's logs."),
            num("hours", "--hours", "Only the last N hours", "all", adv=False),
            num("threshold", "-n", "Failures from one IP to flag brute force", 10),
            num("spray_users", "-u", "Distinct usernames from one IP to flag spraying", 5),
            num("top", "--top", "Rows per table", 15),
            fmt(["table", "csv", "json"]), out(),
        ],
    },
    {
        "name": "secretscan", "kit": "scankit",
        "tagline": "Find leaked API keys, passwords and tokens",
        "desc": "Scans code and config files for leaked secrets: cloud keys, API tokens, private keys, database "
                "URLs and hard-coded passwords. Secrets are masked in the output unless you choose otherwise.",
        "fields": [
            F("path", "path", "Folder or file to scan", None, mode="any", required=True),
            F("min_severity", "choice", "Minimum severity", "-m", choices=["", "LOW", "MEDIUM", "HIGH"], default=""),
            F("exclude", "texts", "Skip paths matching", "-x", placeholder="tests/*, *.min.js", split="comma"),
            chk("show", "--show", "Show secrets unmasked (careful when sharing your screen)", adv=True),
            num("max_size", "--max-size", "Skip files larger than (MB)", 2),
            fmt(["table", "csv", "json"]), out(),
        ],
    },
]

TOOL_BY_NAME = {t["name"]: t for t in TOOLS}


# ---------------------------------------------------------------- argv building
def split_values(text, mode="ws"):
    if isinstance(text, (list, tuple)):
        return [str(v) for v in text if str(v).strip()]
    text = (text or "").strip()
    if not text:
        return []
    if mode == "comma":
        parts = re.split(r"[,\n]", text)
    else:
        parts = re.split(r"[,\s]+", text)
    return [p.strip() for p in parts if p.strip()]


def is_empty(field, value):
    kind = field["kind"]
    if kind == "check":
        return not value
    if kind in ("paths", "multi"):
        return not value
    if kind == "texts":
        return not split_values(value, field.get("split", "ws"))
    return value is None or str(value).strip() == ""


def validate(spec, values):
    """Return a list of human-readable problems (empty = OK)."""
    problems = []
    for f in spec["fields"]:
        if f.get("required") and is_empty(f, values.get(f["key"])):
            problems.append(f"{f['label']} is required.")
        if f["kind"] == "number":
            v = str(values.get(f["key"]) or "").strip()
            if v:
                try:
                    float(v) if f.get("decimals") else int(v)
                except ValueError:
                    problems.append(f"{f['label']} must be a {'number' if f.get('decimals') else 'whole number'}.")
    roo = spec.get("require_one_of")
    if roo:
        keys, msg = roo
        fields = {f["key"]: f for f in spec["fields"]}
        if all(is_empty(fields[k], values.get(k)) for k in keys):
            problems.append(msg)
    return problems


def build_argv(spec, values):
    """Turn form values into the tool's argument list (without the program name).
    Returns (argv, stdin_text)."""
    opts, positional, stdin_text = [], [], None
    fields = spec["fields"]
    for f in fields:
        v = values.get(f["key"])
        if is_empty(f, v):
            continue
        kind, flag = f["kind"], f["flag"]
        if kind == "password":
            stdin_text = str(v) + "\n"
            continue
        if kind == "check":
            opts.append(flag)
            continue
        if kind == "choice":
            if str(v) == str(f.get("default", "")) and f["key"] != "format":
                continue
            if f["key"] == "format" and v == f["choices"][0]:
                continue                       # tool's own default
            opts += [flag, str(v)]
            continue
        if kind in ("paths", "multi", "texts"):
            vals = list(v) if kind != "texts" else split_values(v, f.get("split", "ws"))
            if flag is None:
                positional += [str(x) for x in vals]
            else:
                for x in vals:
                    opts += [flag, str(x)]
            continue
        # path, text, number
        sval = str(v).strip()
        if flag is None:
            positional.append(sval)
        else:
            opts += [flag, sval]
    opts += spec.get("fixed", [])
    # "--" protects positional values that start with "-"
    if any(p.startswith("-") for p in positional):
        return opts + ["--"] + positional, stdin_text
    return opts + positional, stdin_text


def command_preview(spec, argv):
    return " ".join(["python3", spec["name"] + ".py"] + [shlex.quote(a) for a in argv])
