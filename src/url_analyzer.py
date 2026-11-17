import re
from urllib.parse import urlparse


class URLAnalyzer:
    """Analyze URLs for potentially suspicious characteristics."""

    URL_PATTERN = r"https?://[^\s]+|www\.[^\s]+"

    def extract_urls(self, text: str) -> list[str]:
        """Extract URLs from text."""
        return re.findall(self.URL_PATTERN, text)

    def analyze_url(self, url: str) -> dict:
        """Analyze a single URL."""

        normalized_url = url

        if url.startswith("www."):
            normalized_url = "http://" + url

        parsed = urlparse(normalized_url)

        hostname = parsed.hostname or ""

        indicators = []

        if parsed.scheme != "https":
            indicators.append("no_https")

        if self._is_ip_address(hostname):
            indicators.append("ip_address")

        if len(url) > 100:
            indicators.append("long_url")

        if "@" in url:
            indicators.append("at_symbol")

        if hostname.count(".") >= 3:
            indicators.append("excessive_subdomains")

        suspicious_terms = [
            "login",
            "verify",
            "account",
            "secure",
            "update",
            "password",
            "bank",
            "confirm",
        ]

        found_terms = [
            term
            for term in suspicious_terms
            if term in url.lower()
        ]

        if found_terms:
            indicators.append("suspicious_terms")

        return {
            "url": url,
            "scheme": parsed.scheme,
            "hostname": hostname,
            "indicators": indicators,
            "suspicious_terms": found_terms,
            "indicator_count": len(indicators),
        }

    def _is_ip_address(self, hostname: str) -> bool:
        """Check whether hostname is an IPv4 address."""

        parts = hostname.split(".")

        if len(parts) != 4:
            return False

        return all(
            part.isdigit() and 0 <= int(part) <= 255
            for part in parts
        )

    def analyze(self, text: str) -> dict:
        """Extract and analyze all URLs in text."""

        urls = self.extract_urls(text)

        analyses = [
            self.analyze_url(url)
            for url in urls
        ]

        total_indicators = sum(
            analysis["indicator_count"]
            for analysis in analyses
        )

        return {
            "urls": urls,
            "analyses": analyses,
            "total_url_indicators": total_indicators,
        }