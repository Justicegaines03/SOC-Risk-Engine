"""
TheHive 5 REST API Client

Handles all communication with TheHive 5 via its /api/v1 endpoints.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import requests

from risk_engine import config
from risk_engine.models import Observable

logger = logging.getLogger(__name__)


class TheHiveClient:
    """Thin wrapper around the TheHive 5 REST API."""

    def __init__(
        self,
        url: str = config.THEHIVE_URL,
        api_key: str = config.THEHIVE_API_KEY,
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
        """Issue a request and return the parsed JSON response."""
        url = f"{self.base_url}{path}"
        resp = self.session.request(method, url, json=json, params=params)
        resp.raise_for_status()
        if resp.content:
            return resp.json()
        return None

    # ------------------------------------------------------------------
    # Cases
    # ------------------------------------------------------------------

    def get_open_cases(self) -> List[Dict[str, Any]]:
        """Return open cases that have NOT been risk-scored yet.

        Uses the TheHive 5 query API to filter by status and tag.
        """
        query = {
            "query": [
                {"_name": "listCase"},
                {
                    "_name": "filter",
                    "_not": {"_field": "tags", "_value": config.SCORED_TAG},
                },
                {
                    "_name": "filter",
                    "_field": "status",
                    "_value": "New",
                },
                {"_name": "sort", "_fields": [{"_name": "startDate", "_order": "desc"}]},
            ]
        }
        cases = self._request("POST", "/api/v1/query", json=query)
        logger.info("Found %d unscored open case(s)", len(cases) if cases else 0)
        return cases or []

    def get_case(self, case_id: str) -> Dict[str, Any]:
        """Fetch a single case by its ID."""
        return self._request("GET", f"/api/v1/case/{case_id}")

    # ------------------------------------------------------------------
    # Observables
    # ------------------------------------------------------------------

    def get_case_observables(self, case_id: str) -> List[Observable]:
        """Return all observables attached to a case."""
        query = {
            "query": [
                {"_name": "getCase", "idOrName": case_id},
                {"_name": "observables"},
            ]
        }
        raw = self._request("POST", "/api/v1/query", json=query) or []
        observables = [
            Observable(
                id=o.get("_id", ""),
                data_type=o.get("dataType", "unknown"),
                value=o.get("data", ""),
                tlp=o.get("tlp", 2),
                tags=o.get("tags", []),
            )
            for o in raw
        ]
        logger.info(
            "Case %s has %d observable(s)", case_id, len(observables)
        )
        return observables

    # ------------------------------------------------------------------
    # Tasks & Task Logs
    # ------------------------------------------------------------------

    def find_or_create_risk_task(self, case_id: str) -> str:
        """Return the task ID for the 'Risk Assessment' task, creating it if needed."""
        # Look for an existing task
        query = {
            "query": [
                {"_name": "getCase", "idOrName": case_id},
                {"_name": "tasks"},
                {"_name": "filter", "_field": "title", "_value": "Risk Assessment"},
            ]
        }
        existing = self._request("POST", "/api/v1/query", json=query) or []
        if existing:
            task_id = existing[0]["_id"]
            logger.debug("Found existing Risk Assessment task %s", task_id)
            return task_id

        # Create a new task
        task_data = {
            "title": "Risk Assessment",
            "group": "risk",
            "description": "Automated risk scoring by the Risk Engine",
        }
        result = self._request(
            "POST", f"/api/v1/case/{case_id}/task", json=task_data
        )
        task_id = result["_id"]
        logger.info("Created Risk Assessment task %s for case %s", task_id, case_id)
        return task_id

    def add_task_log(self, task_id: str, content: str) -> None:
        """Post a markdown log entry to a task."""
        log_data = {"message": content}
        self._request("POST", f"/api/v1/task/{task_id}/log", json=log_data)
        logger.info("Posted risk report to task %s", task_id)

    # ------------------------------------------------------------------
    # Tags
    # ------------------------------------------------------------------

    def add_case_tag(self, case_id: str, tag: str) -> None:
        """Add a tag to a case (used to mark it as scored)."""
        case = self.get_case(case_id)
        current_tags = case.get("tags", [])
        if tag not in current_tags:
            updated_tags = current_tags + [tag]
            self._request(
                "PATCH", f"/api/v1/case/{case_id}", json={"tags": updated_tags}
            )
            logger.info("Tagged case %s with '%s'", case_id, tag)
