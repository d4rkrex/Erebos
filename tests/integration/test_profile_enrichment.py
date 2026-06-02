"""Optional real-target TargetProfile integration tests."""

import requests
import pytest

from erebos.core.target_profile import TargetProfiler, TargetType
from erebos.enrichment.http_probe import HttpProbeService
from erebos.parsers.nmap import NmapScanResult, PortInfo


def _reachable(url: str) -> bool:
    try:
        response = requests.get(url, timeout=5)
        return response.ok
    except requests.RequestException:
        return False


@pytest.mark.skipif(
    not _reachable("https://wordpress.org"),
    reason="wordpress.org is unreachable from this environment",
)
def test_real_target_wordpress_profile_detection():
    profiler = TargetProfiler()
    probe = HttpProbeService(timeout=5.0).probe("wordpress.org", 443)
    profile = profiler.create_profile(
        "https://wordpress.org",
        NmapScanResult(ports=[PortInfo(port="443", protocol="tcp", state="open", service="https")]),
        {("wordpress.org", 443): probe},
    )

    assert profile is not None
    assert profile.target_type == TargetType.WEB_APPLICATION
    assert any("wordpress" in tech.name.lower() for tech in profile.technologies)


@pytest.mark.skipif(
    not _reachable("http://scanme.nmap.org"),
    reason="scanme.nmap.org is unreachable from this environment",
)
def test_real_target_scanme_profile_detection():
    profiler = TargetProfiler()
    probe = HttpProbeService(timeout=5.0).probe("scanme.nmap.org", 80)
    profile = profiler.create_profile(
        "http://scanme.nmap.org",
        NmapScanResult(
            ports=[
                PortInfo(port="80", protocol="tcp", state="open", service="http"),
                PortInfo(port="22", protocol="tcp", state="open", service="ssh"),
            ]
        ),
        {("scanme.nmap.org", 80): probe},
    )

    assert profile is not None
    assert profile.target_type in {TargetType.WEB_APPLICATION, TargetType.NETWORK_HOST}
    assert any(service.port == 22 for service in profile.services)
