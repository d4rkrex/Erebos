"""Unit tests for enrichment services."""

import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from erebos.enrichment.cve_service import CveRecord, CveService
from erebos.enrichment.exploit_db import ExploitDbService
from erebos.enrichment.http_probe import HttpProbeResult, HttpProbeService


class TestCveService:
    """Tests for CveService."""

    def setup_method(self):
        """Set up test fixtures."""
        self.service = CveService()

    def test_lookup_cpe_cache_hit(self):
        """Cached CPE queries return without HTTP request."""
        cached_records = [
            CveRecord(cve_id="CVE-2021-44228", description="Log4Shell", cvss_v3_score=10.0)
        ]
        self.service._cache["cpe:2.3:a:apache:http_server:2.4.41"] = cached_records

        result = self.service.lookup_cpe("cpe:2.3:a:apache:http_server:2.4.41")

        assert result == cached_records

    def test_lookup_cpe_empty_result(self):
        """Unknown CPE returns empty list."""
        with patch.object(self.service._session, "get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"vulnerabilities": []}
            mock_get.return_value = mock_response

            result = self.service.lookup_cpe("cpe:2.3:a:nonexistent:product:99.99")

            assert result == []

    def test_lookup_cpe_retry_on_429(self):
        """HTTP 429 triggers retry with 7s delay."""
        with patch.object(self.service._session, "get") as mock_get:
            mock_429 = MagicMock()
            mock_429.status_code = 429
            mock_200 = MagicMock()
            mock_200.status_code = 200
            mock_200.json.return_value = {"vulnerabilities": []}
            mock_get.side_effect = [mock_429, mock_200]

            with patch("time.sleep") as mock_sleep:
                result = self.service.lookup_cpe("cpe:2.3:a:test:product:1.0")

                mock_sleep.assert_called_once_with(7)
                assert result == []

    def test_lookup_product_version(self):
        """lookup_product_version constructs partial CPE and queries."""
        with patch.object(self.service._session, "get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"vulnerabilities": []}
            mock_get.return_value = mock_response

            self.service.lookup_product_version("apache", "2.4.41")

            mock_get.assert_called_once()
            _, kwargs = mock_get.call_args
            assert kwargs["params"]["keywordSearch"] == "cpe:2.3:a:apache:2.4.41"

    def test_parse_response_with_cvss(self):
        """_parse_response extracts CVSS v3 score and severity."""
        api_data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-44228",
                        "descriptions": [{"lang": "en", "value": "Log4Shell RCE"}],
                        "published": "2021-12-10T00:00:00.000",
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 10.0,
                                        "baseSeverity": "CRITICAL",
                                    }
                                }
                            ]
                        },
                    }
                }
            ]
        }

        records = self.service._parse_response(api_data)

        assert len(records) == 1
        assert records[0].cve_id == "CVE-2021-44228"
        assert records[0].cvss_v3_score == 10.0
        assert records[0].cvss_v3_severity == "CRITICAL"


class TestExploitDbService:
    """Tests for ExploitDbService."""

    def test_tool_not_available(self):
        """Returns empty list when searchsploit not in PATH."""
        with patch("shutil.which", return_value=None):
            service = ExploitDbService()
            assert service.is_available() is False
            result = service.get_exploits_for_cve("CVE-2021-44228")
            assert result == []

    def test_correlate_from_nmap_empty_when_unavailable(self):
        """correlate_from_nmap returns [] when tool unavailable."""
        with patch("shutil.which", return_value=None):
            service = ExploitDbService()
            result = service.correlate_from_nmap("/tmp/nmap.xml")
            assert result == []

    def test_parse_searchsploit_json_valid(self):
        """_parse_searchsploit_json extracts ExploitRef objects."""
        with patch("shutil.which", return_value="/usr/bin/searchsploit"):
            service = ExploitDbService()
            json_output = json.dumps(
                {
                    "RESULTS_EXPLOIT": [
                        {
                            "EDB-ID": "50957",
                            "CVE": "CVE-2021-44228",
                            "Description": "Log4Shell RCE",
                            "File": "/exploits/50957.py",
                            "Author": "p海上",
                            "Platform": "Multiple",
                        }
                    ]
                }
            )

            results = service._parse_searchsploit_json(json_output)

            assert len(results) == 1
            assert results[0].edb_id == "50957"
            assert results[0].cve == "CVE-2021-44228"
            assert results[0].description == "Log4Shell RCE"
            assert results[0].file_path == "/exploits/50957.py"

    def test_parse_searchsploit_json_empty(self):
        """Empty JSON output returns empty list."""
        with patch("shutil.which", return_value="/usr/bin/searchsploit"):
            service = ExploitDbService()
            results = service._parse_searchsploit_json("")
            assert results == []

            results = service._parse_searchsploit_json("not json")
            assert results == []


class TestHttpProbeService:
    """Tests for HttpProbeService."""

    def setup_method(self):
        """Set up test fixtures."""
        self.service = HttpProbeService(max_concurrent=5, timeout=2.0)

    def test_probe_http_on_port(self):
        """probe() detects HTTP on a standard port."""
        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"Server": "Apache/2.4.41"}
            mock_response.text = "<html>Welcome</html>"
            mock_get.return_value = mock_response

            result = self.service.probe("192.168.1.1", 80)

            assert result.is_http is True
            assert result.status_code == 200
            assert result.server_banner == "Apache/2.4.41"

    def test_probe_https_on_port(self):
        """probe() detects HTTPS on a port."""
        with patch("requests.get") as mock_get:
            # First call (HTTPS) succeeds
            mock_https = MagicMock()
            mock_https.status_code = 200
            mock_https.headers = {"Server": "nginx/1.18.0"}
            mock_https.text = "OK"
            mock_get.return_value = mock_https

            result = self.service.probe("192.168.1.1", 443)

            assert result.is_http is True
            assert result.is_https is True
            assert result.server_banner == "nginx/1.18.0"

    def test_probe_non_http_port(self):
        """probe() returns is_http=False for non-HTTP services (SSH)."""
        with patch("requests.get") as mock_get:
            mock_get.side_effect = requests.exceptions.ConnectionError("Connection refused")

            result = self.service.probe("192.168.1.1", 22)

            assert result.is_http is False
            assert result.reason == "connection_refused"

    def test_probe_timeout(self):
        """probe() handles timeout gracefully."""
        with patch("requests.get") as mock_get:
            mock_get.side_effect = requests.exceptions.Timeout("timed out")

            result = self.service.probe("192.168.1.1", 8080)

            assert result.is_http is False
            assert result.reason == "timeout"

    def test_probe_redirect(self):
        """probe() captures redirect URL on 301/302."""
        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 302
            mock_response.headers = {"Location": "https://192.168.1.1:8443/", "Server": "Apache"}
            mock_get.return_value = mock_response

            result = self.service.probe("192.168.1.1", 8443)

            assert result.is_http is True
            assert result.redirect_url == "https://192.168.1.1:8443/"
            assert result.status_code == 302

    def test_probe_batch_parallel(self):
        """probe_batch() runs probes in parallel and returns correct mapping."""
        with patch.object(self.service, "probe") as mock_probe:
            # Return a simple result for all calls
            mock_probe.return_value = HttpProbeResult(is_http=True, status_code=200)

            targets = [
                ("192.168.1.1", 80),
                ("192.168.1.1", 443),
                ("192.168.1.1", 8080),
            ]
            results = self.service.probe_batch(targets)

            assert len(results) == 3
            assert results[("192.168.1.1", 80)].is_http is True
            assert results[("192.168.1.1", 443)].is_http is True
            assert results[("192.168.1.1", 8080)].is_http is True
            # Verify called for each target
            assert mock_probe.call_count == 3
