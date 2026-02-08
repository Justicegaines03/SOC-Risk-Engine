"""
Cortex REST API Client

Reads analyzer job results from Cortex to extract threat verdicts.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import requests

from risk_engine import config
from risk_engine.models import AnalyzerResult

logger = logging.getLogger(__name__)


class CortexClient:
    """Thin wrapper around the Cortex REST API."""

    def __init__(
        self,
        url: str = config.CORTEX_URL,
        api_key: str = config.CORTEX_API_KEY,
    ):
        self.base_url = url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            }
        )

    # ------------------------------------------------------------------
    # Low-level request helper
    # ------------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        json: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        url = f"{self.base_url}{path}"
        resp = self.session.request(method, url, json=json, params=params)
        resp.raise_for_status()
        if resp.content:
            return resp.json()
        return None

    # ------------------------------------------------------------------
    # Jobs
    # ------------------------------------------------------------------

    def get_observable_jobs(self, observable_value: str, data_type: str) -> List[Dict[str, Any]]:
        """Search for completed Cortex jobs that analyzed this observable.

        Cortex doesn't index jobs by TheHive observable ID directly, so we
        search by the observable's data value and type.
        """
        query = {
            "query": {
                "_and": [
                    {"_field": "data", "_value": observable_value},
                    {"_field": "dataType", "_value": data_type},
                    {"_field": "status", "_value": "Success"},
                ]
            }
        }
        jobs = self._request("POST", "/api/job/_search", json=query) or []
        logger.debug(
            "Found %d Cortex job(s) for %s (%s)",
            len(jobs),
            observable_value,
            data_type,
        )
        return jobs

    def get_job_report(self, job_id: str) -> Dict[str, Any]:
        """Get the full report for a completed Cortex job."""
        return self._request("GET", f"/api/job/{job_id}/report") or {}

    # ------------------------------------------------------------------
    # Verdict Extraction
    # ------------------------------------------------------------------

    @staticmethod
    def extract_verdicts(job: Dict[str, Any]) -> List[AnalyzerResult]:
        """Parse Cortex taxonomies from a job into structured AnalyzerResult objects.

        Cortex jobs store their verdicts in a ``report.summary.taxonomies`` list.
        Each taxonomy has a ``level`` (info / safe / suspicious / malicious),
        a ``namespace``, a ``predicate``, and a ``value``.
        """
        analyzer_name = job.get("analyzerName", "unknown")
        report = job.get("report", {}) or {}
        summary = report.get("summary", {}) or {}
        taxonomies = summary.get("taxonomies", [])

        if not taxonomies:
            logger.debug("Job %s (%s) has no taxonomies", job.get("id"), analyzer_name)
            return []

        results: List[AnalyzerResult] = []
        for tax in taxonomies:
            level = tax.get("level", "info").lower()
            # Normalise level to our four canonical values
            if level not in ("malicious", "suspicious", "safe", "info"):
                level = "info"

            results.append(
                AnalyzerResult(
                    analyzer_name=analyzer_name,
                    level=level,
                    score=_parse_score(tax.get("value", "0")),
                    namespace=tax.get("namespace", ""),
                    predicate=tax.get("predicate", ""),
                    raw_value=str(tax.get("value", "")),
                )
            )
        return results

    def get_analyzer_results(
        self, observable_value: str, data_type: str
    ) -> List[AnalyzerResult]:
        """Convenience: fetch all Cortex jobs for an observable and return parsed verdicts."""
        jobs = self.get_observable_jobs(observable_value, data_type)
        all_results: List[AnalyzerResult] = []
        for job in jobs:
            # The search endpoint may not include the full report inline;
            # fetch it explicitly if missing.
            if "report" not in job or not job.get("report"):
                full_report = self.get_job_report(job["id"])
                job["report"] = full_report.get("report", full_report)

            all_results.extend(self.extract_verdicts(job))
        return all_results


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _parse_score(value: str) -> float:
    """Best-effort parse a taxonomy value into a float score."""
    try:
        # Handle fractions like "5/100"
        if "/" in str(value):
            parts = str(value).split("/")
            return float(parts[0]) / float(parts[1])
        return float(value)
    except (ValueError, ZeroDivisionError):
        return 0.0
