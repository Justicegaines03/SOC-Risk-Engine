"""
Risk Engine Data Models

Plain dataclasses that flow through the pipeline:
  Observable -> AnalyzerResult -> RiskScore -> CaseRiskAssessment
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional


@dataclass
class Observable:
    """A single observable extracted from a TheHive case."""

    id: str
    data_type: str          # e.g. "ip", "domain", "hash", "url"
    value: str              # e.g. "8.8.8.8"
    tlp: int = 2            # Traffic Light Protocol (0-4)
    tags: List[str] = field(default_factory=list)


@dataclass
class AnalyzerResult:
    """One Cortex analyzer verdict for an observable."""

    analyzer_name: str      # e.g. "VirusTotal_GetReport_3_1"
    level: str              # "malicious" | "suspicious" | "safe" | "info"
    score: float            # Numeric score if the analyzer provides one
    namespace: str = ""     # Taxonomy namespace (e.g. "VT")
    predicate: str = ""     # Taxonomy predicate (e.g. "Score")
    raw_value: str = ""     # Original taxonomy value string


@dataclass
class ObservableRisk:
    """Risk assessment for a single observable."""

    observable: Observable
    analyzer_results: List[AnalyzerResult] = field(default_factory=list)
    likelihood: float = 0.0  # 0.0 - 1.0


@dataclass
class RiskScore:
    """Final computed risk numbers for a case."""

    likelihood: float       # 0.0 - 1.0  (aggregate across observables)
    impact_dollars: float   # Dollar value of potential loss
    ale: float              # Annualized Loss Expectancy = likelihood * impact
    risk_level: str         # "Critical" | "High" | "Medium" | "Low" | "Info"


@dataclass
class CaseRiskAssessment:
    """Complete risk assessment for one TheHive case."""

    case_id: str
    case_title: str
    case_severity: int = 2                                  # TheHive severity 1-4
    asset_type: str = "server"
    sensitivity: str = "internal"
    observables: List[ObservableRisk] = field(default_factory=list)
    risk_score: Optional[RiskScore] = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
