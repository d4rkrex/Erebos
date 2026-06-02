"""Performance checks for TargetProfile operations."""

import time

from erebos.core.target_profile import TargetProfiler
from erebos.enrichment.http_probe import HttpProbeResult
from erebos.parsers.nmap import NmapScanResult, PortInfo


def test_benchmark_basic_target_profile_under_100ms():
    profiler = TargetProfiler()

    start = time.perf_counter()
    profile = profiler.create_profile("example.com", NmapScanResult(), {})
    duration = time.perf_counter() - start

    assert profile is not None
    assert duration < 0.1, f"Basic profiling took {duration * 1000:.2f}ms"


def test_benchmark_http_target_profile_under_500ms():
    profiler = TargetProfiler()
    http_results = {
        ("example.com", 443): HttpProbeResult(
            is_http=True,
            is_https=True,
            headers={"server": "nginx/1.18.0", "content-security-policy": "default-src 'self'"},
            content_type="text/html",
            body="<html><script>__NEXT_DATA__</script></html>",
        )
    }
    nmap_result = NmapScanResult(
        ports=[PortInfo(port="443", protocol="tcp", state="open", service="https", product="nginx")]
    )

    start = time.perf_counter()
    profile = profiler.create_profile("https://example.com", nmap_result, http_results)
    duration = time.perf_counter() - start

    assert profile is not None
    assert duration < 0.5, f"HTTP profiling took {duration * 1000:.2f}ms"
