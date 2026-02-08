"""
SOC Risk Engine — CLI Entry Point

Usage:
    python -m risk_engine score  --case-id <CASE_ID>
    python -m risk_engine watch  [--interval 30]

The "score" command processes a single case.
The "watch" command polls TheHive for unscored cases on a loop.
"""

from __future__ import annotations

import argparse
import logging
import sys
import time

from risk_engine import config
from risk_engine.clients.thehive import TheHiveClient
from risk_engine.clients.cortex import CortexClient
from risk_engine.calculator import score_case
from risk_engine.reporter import generate_report
from risk_engine.models import CaseRiskAssessment, ObservableRisk

logger = logging.getLogger("risk_engine")


# -----------------------------------------------------------------------
# Core scoring pipeline
# -----------------------------------------------------------------------

def process_case(
    case_id: str,
    hive: TheHiveClient,
    cortex: CortexClient,
    *,
    asset_type: str = "",
    sensitivity: str = "",
) -> CaseRiskAssessment:
    """Run the full pipeline for one case: fetch → enrich → score → report."""

    # 1. Fetch case metadata
    case = hive.get_case(case_id)
    case_title = case.get("title", "Untitled")
    case_severity = case.get("severity", 2)
    case_tags = case.get("tags", [])

    # Derive asset_type / sensitivity from tags if not overridden
    if not asset_type:
        asset_type = _extract_tag(case_tags, "asset:", config.DEFAULT_SENSITIVITY)
    if not sensitivity:
        sensitivity = _extract_tag(case_tags, "sensitivity:", config.DEFAULT_SENSITIVITY)

    logger.info("Processing case: %s — %s", case_id, case_title)

    # 2. Get observables
    observables = hive.get_case_observables(case_id)

    # 3. Enrich each observable with Cortex results
    obs_risks = []
    for obs in observables:
        results = cortex.get_analyzer_results(obs.value, obs.data_type)
        obs_risks.append(ObservableRisk(observable=obs, analyzer_results=results))

    # 4. Build assessment and score
    assessment = CaseRiskAssessment(
        case_id=case_id,
        case_title=case_title,
        case_severity=case_severity,
        asset_type=asset_type,
        sensitivity=sensitivity,
        observables=obs_risks,
    )
    score_case(assessment)

    # 5. Generate report and post to TheHive
    report_md = generate_report(assessment)
    task_id = hive.find_or_create_risk_task(case_id)
    hive.add_task_log(task_id, report_md)
    hive.add_case_tag(case_id, config.SCORED_TAG)

    logger.info(
        "Case %s scored: %s (ALE $%,.2f)",
        case_id,
        assessment.risk_score.risk_level if assessment.risk_score else "N/A",
        assessment.risk_score.ale if assessment.risk_score else 0,
    )
    return assessment


# -----------------------------------------------------------------------
# CLI subcommands
# -----------------------------------------------------------------------

def cmd_score(args: argparse.Namespace) -> None:
    """Score a single case by ID."""
    hive = TheHiveClient()
    cortex = CortexClient()
    assessment = process_case(
        args.case_id,
        hive,
        cortex,
        asset_type=args.asset_type or "",
        sensitivity=args.sensitivity or "",
    )
    risk = assessment.risk_score
    if risk:
        print(f"\n{'='*60}")
        print(f"  Case:       {assessment.case_title}")
        print(f"  Risk Level: {risk.risk_level}")
        print(f"  Likelihood: {risk.likelihood:.2%}")
        print(f"  Impact:     ${risk.impact_dollars:,.0f}")
        print(f"  ALE:        ${risk.ale:,.2f}")
        print(f"{'='*60}\n")
        print("Report posted to TheHive.")


def cmd_watch(args: argparse.Namespace) -> None:
    """Poll for unscored cases on a loop."""
    interval = args.interval
    hive = TheHiveClient()
    cortex = CortexClient()

    logger.info("Watch mode started (polling every %ds)", interval)
    print(f"Risk Engine watching for new cases (every {interval}s). Ctrl+C to stop.")

    try:
        while True:
            cases = hive.get_open_cases()
            if cases:
                logger.info("Found %d unscored case(s)", len(cases))
                for case in cases:
                    case_id = case.get("_id", "")
                    try:
                        process_case(case_id, hive, cortex)
                    except Exception:
                        logger.exception("Failed to process case %s", case_id)
            else:
                logger.debug("No unscored cases found")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nWatch mode stopped.")


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

def _extract_tag(tags: list, prefix: str, default: str) -> str:
    """Pull a value from a tag list by prefix (e.g., 'asset:server' → 'server')."""
    for tag in tags:
        if tag.lower().startswith(prefix.lower()):
            return tag[len(prefix):]
    return default


# -----------------------------------------------------------------------
# Argument parser
# -----------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="risk_engine",
        description="SOC Risk Engine — Quantitative risk scoring for TheHive cases",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # -- score --
    score_p = sub.add_parser("score", help="Score a single case")
    score_p.add_argument(
        "--case-id", required=True, help="TheHive case ID to score"
    )
    score_p.add_argument(
        "--asset-type",
        default="",
        help="Override asset type (workstation/server/database/critical_infra)",
    )
    score_p.add_argument(
        "--sensitivity",
        default="",
        help="Override data sensitivity (public/internal/confidential/restricted)",
    )

    # -- watch --
    watch_p = sub.add_parser("watch", help="Poll for unscored cases")
    watch_p.add_argument(
        "--interval",
        type=int,
        default=config.WATCH_INTERVAL_SECONDS,
        help=f"Polling interval in seconds (default: {config.WATCH_INTERVAL_SECONDS})",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Configure logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    if args.command == "score":
        cmd_score(args)
    elif args.command == "watch":
        cmd_watch(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
