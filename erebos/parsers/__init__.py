"""Parsers module exports."""

from typing import Optional

from erebos.parsers.base import Parser
from erebos.parsers.katana import KatanaParser
from erebos.parsers.nikto import NiktoParser
from erebos.parsers.nuclei import NucleiParser
from erebos.parsers.nmap import NmapParser
from erebos.parsers.ffuf import FfufParser
from erebos.parsers.gobuster import GobusterParser
from erebos.parsers.sqlmap import SqlmapParser
from erebos.parsers.dirb import DirbParser
from erebos.parsers.amass import AmassParser
from erebos.parsers.subfinder import SubfinderParser
from erebos.parsers.masscan import MasscanParser
from erebos.parsers.httpx import HttpxParser
from erebos.parsers.dnsx import DnsxParser
from erebos.parsers.assetfinder import AssetfinderParser
from erebos.parsers.naabu import NaabuParser
from erebos.parsers.gau import GauParser
from erebos.parsers.waybackurls import WaybackurlsParser
from erebos.parsers.alterx import AlterxParser
from erebos.parsers.arjun import ArjunParser
from erebos.parsers.dirsearch import DirsearchParser
from erebos.parsers.dalfox import DalfoxParser
from erebos.parsers.wpscan import WpscanParser
from erebos.parsers.kxss import KxssParser
from erebos.parsers.bxss import BxssParser

__all__ = [
    "Parser",
    "NucleiParser",
    "NiktoParser",
    "KatanaParser",
    "NmapParser",
    "FfufParser",
    "GobusterParser",
    "SqlmapParser",
    "DirbParser",
    "AmassParser",
    "SubfinderParser",
    "MasscanParser",
    "HttpxParser",
    "DnsxParser",
    "AssetfinderParser",
    "NaabuParser",
    "GauParser",
    "WaybackurlsParser",
    "AlterxParser",
    "ArjunParser",
    "DirsearchParser",
    "DalfoxParser",
    "WpscanParser",
    "KxssParser",
    "BxssParser",
]


def get_parser_for_tool(tool: str) -> Optional[Parser]:
    """Get a parser instance for a specific tool."""
    parsers = {
        "nuclei": NucleiParser(),
        "nikto": NiktoParser(),
        "katana": KatanaParser(),
        "nmap": NmapParser(),
        "ffuf": FfufParser(),
        "gobuster": GobusterParser(),
        "sqlmap": SqlmapParser(),
        "dirb": DirbParser(),
        "amass": AmassParser(),
        "subfinder": SubfinderParser(),
        "masscan": MasscanParser(),
        "httpx": HttpxParser(),
        "dnsx": DnsxParser(),
        "assetfinder": AssetfinderParser(),
        "naabu": NaabuParser(),
        "gau": GauParser(),
        "waybackurls": WaybackurlsParser(),
        "alterx": AlterxParser(),
        "arjun": ArjunParser(),
        "dirsearch": DirsearchParser(),
        "dalfox": DalfoxParser(),
        "wpscan": WpscanParser(),
        "kxss": KxssParser(),
        "bxss": BxssParser(),
    }
    return parsers.get(tool.lower())


def auto_detect_parser(output: str) -> Optional[Parser]:
    """Auto-detect the appropriate parser for tool output.

    Order matters: parsers with specific formats must come before
    parsers with broad formats (e.g., Amass/Masscan before Katana which
    matches any JSON array starting with '[').
    """
    parsers = [
        NucleiParser(),
        NiktoParser(),
        WpscanParser(),
        DalfoxParser(),
        ArjunParser(),
        HttpxParser(),
        NaabuParser(),
        AmassParser(),
        MasscanParser(),
        NmapParser(),
        FfufParser(),
        DirsearchParser(),
        GobusterParser(),
        SqlmapParser(),
        DirbParser(),
        DnsxParser(),
        KxssParser(),
        BxssParser(),
        SubfinderParser(),
        AssetfinderParser(),
        AlterxParser(),
        GauParser(),
        WaybackurlsParser(),
        KatanaParser(),
    ]
    for parser in parsers:
        if parser.can_parse(output):
            return parser
    return None
