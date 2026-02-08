"""
Risk Report Generator

Produces a clean markdown report from a CaseRiskAssessment and posts it
back to TheHive as a task log.
"""

from __future__ import annotations

import logging
from typing import Dict, List

from risk_engine.models import CaseRiskAssessment, ObservableRisk

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------
# Markdown Generation
# -----------------------------------------------------------------------

def _risk_emoji(level: str) -> str:
    """Return a text indicator for a risk level (safe for markdown)."""
    return {
        "Critical": "[!!!]",
        "High": "[!!]",
        "Medium": "[!]",
        "Low": "[-]",
        "Info": "[i]",
    }.get(level, "")


def _verdict_summary(obs: ObservableRisk) -> str:
    """One-line summary of analyzer verdicts for an observable."""
    if not obs.analyzer_results:
        return "No analyzer results"
    counts: Dict[str, int] = {}
    for r in obs.analyzer_results:
        counts[r.level] = counts.get(r.level, 0) + 1
    parts = [f"{count} {level}" for level, count in sorted(counts.items())]
    return ", ".join(parts)


def _recommendations(level: str) -> List[str]:
    """Return recommended actions based on risk level."""
    base = {
        "Critical": [
            "Escalate to incident commander immediately",
            "Isolate affected assets from the network",
            "Begin forensic evidence preservation",
            "Notify executive leadership and legal counsel",
            "Activate incident response plan",
        ],
        "High": [
            "Escalate to senior SOC analyst",
            "Restrict access to affected assets",
            "Run full endpoint scan on associated hosts",
            "Review related cases for lateral movement indicators",
        ],
        "Medium": [
            "Assign to SOC analyst for investigation",
            "Run additional Cortex analyzers for enrichment",
            "Monitor associated assets for 48 hours",
        ],
        "Low": [
            "Document findings for trend analysis",
            "Schedule routine review within 7 days",
        ],
        "Info": [
            "No immediate action required",
            "Log for baseline and reporting purposes",
        ],
    }
    return base.get(level, ["Review case manually"])


def generate_report(assessment: CaseRiskAssessment) -> str:
    """Build a full markdown risk report."""
    risk = assessment.risk_score
    if risk is None:
        return "**Error:** Case has not been scored yet."

    indicator = _risk_emoji(risk.risk_level)
    lines = [
        f"# Risk Assessment Report",
        "",
        f"**Case:** {assessment.case_title} (`{assessment.case_id}`)",
        f"**Assessed:** {assessment.timestamp}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        (
            f"{indicator} This case has a **{risk.risk_level}** risk level "
            f"with an estimated annual loss exposure of **${risk.ale:,.2f}**."
        ),
        "",
        "---",
        "",
        "## Risk Calculation",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Likelihood | {risk.likelihood:.2%} |",
        f"| Asset Type | {assessment.asset_type} |",
        f"| Sensitivity | {assessment.sensitivity} |",
        f"| Impact (SLE) | ${risk.impact_dollars:,.0f} |",
        f"| **ALE (Annualized Loss)** | **${risk.ale:,.2f}** |",
        f"| **Risk Level** | **{risk.risk_level}** |",
        "",
        "> *ALE = Likelihood x Impact (Single Loss Expectancy)*",
        "",
    ]

    # Observable breakdown
    if assessment.observables:
        lines += [
            "---",
            "",
            "## Observable Breakdown",
            "",
            "| Observable | Type | Likelihood | Verdicts |",
            "|------------|------|------------|----------|",
        ]
        for obs in assessment.observables:
            lines.append(
                f"| `{obs.observable.value}` "
                f"| {obs.observable.data_type} "
                f"| {obs.likelihood:.2%} "
                f"| {_verdict_summary(obs)} |"
            )
        lines.append("")

        # Detailed analyzer results per observable
        lines += ["### Detailed Analyzer Results", ""]
        for obs in assessment.observables:
            if not obs.analyzer_results:
                continue
            lines.append(f"**`{obs.observable.value}`** ({obs.observable.data_type})")
            lines.append("")
            lines.append("| Analyzer | Verdict | Score | Detail |")
            lines.append("|----------|---------|-------|--------|")
            for r in obs.analyzer_results:
                lines.append(
                    f"| {r.analyzer_name} | {r.level} | {r.raw_value} "
                    f"| {r.namespace}:{r.predicate} |"
                )
            lines.append("")

    # Recommendations
    recs = _recommendations(risk.risk_level)
    lines += [
        "---",
        "",
        "## Recommended Actions",
        "",
    ]
    for i, rec in enumerate(recs, 1):
        lines.append(f"{i}. {rec}")
    lines += [
        "",
        "---",
        "*Report generated by SOC Risk Engine*",
    ]

    return "\n".join(lines)
