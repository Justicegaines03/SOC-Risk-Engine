"""
Risk Calculator — The Math

Converts Cortex analyzer verdicts into a quantitative financial risk score.

    Likelihood  (0-1)   × Impact ($)  =  ALE ($)
    ──────────────────   ───────────      ──────
    From analyzer        From asset       Annualized
    verdicts             value +          Loss
                         sensitivity      Expectancy
"""

from __future__ import annotations

import logging
from typing import List

from risk_engine import config
from risk_engine.models import (
    AnalyzerResult,
    CaseRiskAssessment,
    ObservableRisk,
    RiskScore,
)

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------
# Likelihood
# -----------------------------------------------------------------------

def compute_likelihood(results: List[AnalyzerResult]) -> float:
    """Compute a likelihood score (0.0 – 1.0) from a set of analyzer verdicts.

    Algorithm
    ---------
    1. Map each verdict level to its configured weight.
    2. Take the weighted average.
    3. If multiple *independent* analyzers agree on "malicious", apply a
       consensus boost (capped at 1.0).
    """
    if not results:
        return 0.0

    weights = [
        config.VERDICT_WEIGHTS.get(r.level, 0.0) for r in results
    ]
    avg = sum(weights) / len(weights)

    # Consensus boost
    malicious_count = sum(1 for r in results if r.level == "malicious")
    unique_analyzers = len({r.analyzer_name for r in results if r.level == "malicious"})

    if unique_analyzers >= config.MALICIOUS_CONSENSUS_THRESHOLD:
        avg *= config.MALICIOUS_CONSENSUS_BOOST
        logger.debug(
            "Consensus boost applied (%d independent malicious verdicts)",
            unique_analyzers,
        )

    return min(avg, 1.0)


# -----------------------------------------------------------------------
# Impact
# -----------------------------------------------------------------------

def compute_impact(asset_type: str, sensitivity: str) -> float:
    """Compute a dollar-value impact from asset type and data sensitivity.

    Impact ($) = base_asset_value × sensitivity_multiplier
    """
    base = config.ASSET_VALUES.get(
        asset_type.lower(), config.DEFAULT_ASSET_VALUE
    )
    multiplier = config.SENSITIVITY_MULTIPLIERS.get(
        sensitivity.lower(), config.SENSITIVITY_MULTIPLIERS[config.DEFAULT_SENSITIVITY]
    )
    return float(base * multiplier)


# -----------------------------------------------------------------------
# Risk Level
# -----------------------------------------------------------------------

def classify_risk(ale: float) -> str:
    """Map an ALE value to a human-readable risk level."""
    if ale >= config.RISK_THRESHOLDS["critical"]:
        return "Critical"
    if ale >= config.RISK_THRESHOLDS["high"]:
        return "High"
    if ale >= config.RISK_THRESHOLDS["medium"]:
        return "Medium"
    if ale >= config.RISK_THRESHOLDS["low"]:
        return "Low"
    return "Info"


# -----------------------------------------------------------------------
# Top-level scoring
# -----------------------------------------------------------------------

def score_observable(observable_risk: ObservableRisk) -> float:
    """Score a single observable and set its likelihood in-place. Returns the likelihood."""
    likelihood = compute_likelihood(observable_risk.analyzer_results)
    observable_risk.likelihood = likelihood
    return likelihood


def score_case(assessment: CaseRiskAssessment) -> RiskScore:
    """Score an entire case and attach the RiskScore.

    Case-level likelihood is the *maximum* observable likelihood (worst-case)
    because a single highly-malicious indicator is enough to drive risk.
    """
    # Score each observable
    likelihoods: List[float] = []
    for obs_risk in assessment.observables:
        lh = score_observable(obs_risk)
        likelihoods.append(lh)

    # Case likelihood = max across observables (worst-case driver)
    case_likelihood = max(likelihoods) if likelihoods else 0.0

    # Impact
    impact = compute_impact(assessment.asset_type, assessment.sensitivity)

    # ALE
    ale = case_likelihood * impact

    risk = RiskScore(
        likelihood=round(case_likelihood, 4),
        impact_dollars=impact,
        ale=round(ale, 2),
        risk_level=classify_risk(ale),
    )
    assessment.risk_score = risk

    logger.info(
        "Case %s scored: likelihood=%.2f, impact=$%,.0f, ALE=$%,.2f (%s)",
        assessment.case_id,
        risk.likelihood,
        risk.impact_dollars,
        risk.ale,
        risk.risk_level,
    )
    return risk
