"""CVE enrichment service using NIST NVD API v2."""

import logging
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

NIST_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RETRY_DELAY_SECONDS = 7


@dataclass
class CveRecord:
    """CVE record from NIST NVD API."""

    cve_id: str
    description: str
    cvss_v3_score: Optional[float] = None
    cvss_v3_severity: Optional[str] = None
    published_date: Optional[str] = None


class CveService:
    """NIST NVD API v2 client for CVE lookups based on CPE strings.

    Implements in-memory caching and rate-limit retry logic.
    """

    def __init__(self, api_key: Optional[str] = None):
        """Initialize the CVE service.

        Args:
            api_key: Optional NIST NVD API key for higher rate limits.
        """
        self._cache: Dict[str, List[CveRecord]] = {}
        self._session = requests.Session()
        headers: Dict[str, str] = {}
        if api_key:
            headers["apiKey"] = api_key
        self._session.headers.update(headers)

    def lookup_cpe(self, cpe: str) -> List[CveRecord]:
        """Look up CVEs associated with a CPE string.

        Args:
            cpe: CPE string (e.g. cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*).

        Returns:
            List of CveRecord objects.
        """
        if cpe in self._cache:
            logger.debug(f"CVE cache hit for CPE: {cpe}")
            return self._cache[cpe]

        url = NIST_API_BASE
        params = {"keywordSearch": cpe}

        try:
            response = self._session.get(url, params=params, timeout=30)
            if response.status_code == 429:
                logger.warning("NIST NVD API rate-limited, retrying after %ds", RETRY_DELAY_SECONDS)
                time.sleep(RETRY_DELAY_SECONDS)
                response = self._session.get(url, params=params, timeout=30)

            if response.status_code == 200:
                records = self._parse_response(response.json())
                self._cache[cpe] = records
                return records
            else:
                logger.warning("NIST NVD API returned %s for CPE %s", response.status_code, cpe)
                self._cache[cpe] = []
                return []
        except requests.RequestException as e:
            logger.error("Failed to query NIST NVD API for CPE %s: %s", cpe, e)
            self._cache[cpe] = []
            return []

    def lookup_product_version(
        self, product: str, version: str, product_type: str = "a"
    ) -> List[CveRecord]:
        """Look up CVEs for a product and version combination.

        Constructs a partial CPE string and queries NIST NVD.

        Args:
            product: Product name (e.g. "apache").
            version: Version string (e.g. "2.4.41").
            product_type: CPE product type (default "a" for application).

        Returns:
            List of CveRecord objects.
        """
        # Build a minimal CPE string for the search
        cpe = f"cpe:2.3:{product_type}:{product}:{version}"
        return self.lookup_cpe(cpe)

    def _parse_response(self, data: dict) -> List[CveRecord]:
        """Parse NIST NVD API JSON response into CveRecord objects."""
        records: List[CveRecord] = []

        vulnerabilities = data.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")

            descriptions = cve.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "",
            )

            published_date = cve.get("published", None)

            # Extract CVSS v3 metrics
            metrics = cve.get("metrics", {})
            cvss_v3_score: Optional[float] = None
            cvss_v3_severity: Optional[str] = None

            cvss_v3_data = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
            if cvss_v3_data:
                cvss_entry = cvss_v3_data[0]
                cvss = cvss_entry.get("cvssData", {})
                cvss_v3_score = cvss.get("baseScore")
                cvss_v3_severity = cvss.get("baseSeverity")

            records.append(
                CveRecord(
                    cve_id=cve_id,
                    description=description,
                    cvss_v3_score=cvss_v3_score,
                    cvss_v3_severity=cvss_v3_severity,
                    published_date=published_date,
                )
            )

        return records
