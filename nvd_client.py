import re
import time
from typing import Any, Dict, List, Optional
import requests

BASE_URL = "https://services.nvd.nist.gov/rest/json"
CVE_ENDPOINT = f"{BASE_URL}/cves/2.0"
CPE_ENDPOINT = f"{BASE_URL}/cpes/2.0"

class NVDClient:
    def __init__(self, api_key: Optional[str] = None, timeout: int = 30):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "VulnScope/1.0"})
        if api_key:
            self.session.headers["apiKey"] = api_key
        self.delay = 0.7 if api_key else 6.0

    def _get(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        response = self.session.get(url, params=params, timeout=self.timeout)
        if response.status_code == 403:
            raise RuntimeError("NVD rejected the request. Check your API key or rate limit.")
        if response.status_code == 429:
            raise RuntimeError("NVD rate limit reached. Wait and try again, or use an NVD API key.")
        response.raise_for_status()
        time.sleep(self.delay)
        return response.json()

    @staticmethod
    def _version_matches(version: str, candidate: str) -> bool:
        if not candidate or candidate in ("*", "-"):
            return True
        version = version.lower().strip()
        candidate = candidate.lower().strip()
        if candidate == version:
            return True
        # Handle simple wildcard versions such as 120.*
        if "*" in candidate:
            pattern = "^" + re.escape(candidate).replace(r"\*", ".*") + "$"
            return bool(re.match(pattern, version))
        return False

    @staticmethod
    def _extract_cpe_matches(configurations: List[Dict[str, Any]], version: str):
        matches = []
        for config in configurations or []:
            VulnScope._walk_nodes(config.get("nodes", []), matches, version)
        return matches

    @staticmethod
    def _walk_nodes(nodes, matches, version):
        for node in nodes or []:
            for cm in node.get("cpeMatch", []) or []:
                criteria = cm.get("criteria", "")
                if not criteria:
                    continue
                parts = criteria.split(":")
                cpe_version = parts[5] if len(parts) > 5 else ""
                version_start_inc = cm.get("versionStartIncluding")
                version_start_exc = cm.get("versionStartExcluding")
                version_end_inc = cm.get("versionEndIncluding")
                version_end_exc = cm.get("versionEndExcluding")

                # Exact CPE version or a bounded range.
                exact = VulnScope._version_matches(version, cpe_version)
                bounded = True

                # Basic lexical/numeric comparison for common dotted versions.
                def vt(v):
                    nums = re.findall(r"\d+", str(v))
                    return tuple(int(x) for x in nums[:6]) or (0,)

                v = vt(version)
                if version_start_inc and v < vt(version_start_inc):
                    bounded = False
                if version_start_exc and v <= vt(version_start_exc):
                    bounded = False
                if version_end_inc and v > vt(version_end_inc):
                    bounded = False
                if version_end_exc and v >= vt(version_end_exc):
                    bounded = False

                if (exact or bounded) and cm.get("vulnerable", True):
                    matches.append(criteria)

            if node.get("children"):
                VulnScope._walk_nodes(node["children"], matches, version)

    def _find_candidate_cpes(self, product: str, version: str) -> List[str]:
        # CPE search gives better product/version matching than CVE keyword search alone.
        data = self._get(CPE_ENDPOINT, {
            "keywordSearch": product,
            "resultsPerPage": 50
        })
        candidates = []

        product_words = set(re.findall(r"[a-z0-9]+", product.lower()))
        for item in data.get("products", []):
            cpe = item.get("cpe", {})
            name = cpe.get("cpeName", [{}])[0].get("cpeName", "")
            title = " ".join(
                t.get("title", "") if isinstance(t, dict) else str(t)
                for t in cpe.get("titles", [])
            ).lower()
            if not name:
                continue
            score = sum(w in name.lower() or w in title for w in product_words)
            if score:
                candidates.append((score, name))

        candidates.sort(reverse=True)
        return [name for _, name in candidates[:10]]

    def _parse_cve(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        cve = vuln.get("cve", {})
        metrics = cve.get("metrics", {})
        cvss = None
        severity = "UNKNOWN"

        metric_obj = None
        if metrics.get("cvssMetricV31"):
            metric_obj = metrics["cvssMetricV31"][0]
        elif metrics.get("cvssMetricV30"):
            metric_obj = metrics["cvssMetricV30"][0]
        elif metrics.get("cvssMetricV2"):
            metric_obj = metrics["cvssMetricV2"][0]

        if metric_obj:
            cvss_data = metric_obj.get("cvssData", {})
            cvss = cvss_data.get("baseScore")
            severity = (cvss_data.get("baseSeverity") or metric_obj.get("baseSeverity") or "UNKNOWN").upper()

        descriptions = cve.get("descriptions", [])
        description = next(
            (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
            descriptions[0].get("value", "") if descriptions else ""
        )

        references = [r.get("url") for r in cve.get("references", []) if r.get("url")]
        affected_cpes = []
        for config in cve.get("configurations", []) or []:
            for node in config.get("nodes", []) or []:
                for cm in node.get("cpeMatch", []) or []:
                    if cm.get("criteria"):
                        affected_cpes.append(cm["criteria"])

        return {
            "id": cve.get("id", "UNKNOWN"),
            "cvss": cvss if cvss is not None else "N/A",
            "severity": severity,
            "description": description,
            "published": cve.get("published", "N/A"),
            "last_modified": cve.get("lastModified", "N/A"),
            "references": references,
            "affected_cpes": list(dict.fromkeys(affected_cpes))
        }

    def find_cves(self, product: str, version: str) -> List[Dict[str, Any]]:
        cpe_names = self._find_candidate_cpes(product, version)
        vulnerabilities = []

        # Prefer exact CPE-based queries.
        for cpe in cpe_names:
            data = self._get(CVE_ENDPOINT, {
                "cpeName": cpe,
                "resultsPerPage": 100
            })
            vulnerabilities.extend(data.get("vulnerabilities", []))

        # If CPE discovery did not produce results, use keyword search as a fallback.
        if not vulnerabilities:
            data = self._get(CVE_ENDPOINT, {
                "keywordSearch": f"{product} {version}",
                "resultsPerPage": 100
            })
            vulnerabilities = data.get("vulnerabilities", [])

        unique = {}
        for vuln in vulnerabilities:
            parsed = self._parse_cve(vuln)
            # Require the requested version to be represented by the CVE's
            # affected CPE/range when configuration data exists.
            affected = parsed["affected_cpes"]
            if affected:
                version_ok = any(
                    self._version_matches(version, cpe.split(":")[5])
                    or version.lower() in cpe.lower()
                    for cpe in affected
                )
                # Keep candidates from keyword fallback if their CPE data is
                # not specific enough; avoid claiming certainty.
                if not version_ok:
                    continue
            unique[parsed["id"]] = parsed

        return list(unique.values())
