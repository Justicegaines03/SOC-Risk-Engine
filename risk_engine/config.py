"""
Risk Engine Configuration

Loads settings from environment variables / .env file.
All values have sensible defaults for local development.
"""

import os
from dotenv import load_dotenv

# Load .env from project root (one level up from risk_engine/)
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))


# ---------------------------------------------------------------------------
# API Connections
# ---------------------------------------------------------------------------

THEHIVE_URL = os.getenv("THEHIVE_URL", "http://localhost:9000")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY", "")

CORTEX_URL = os.getenv("CORTEX_URL", "http://localhost:9001")
CORTEX_API_KEY = os.getenv("CORTEX_API_KEY", "")

# ---------------------------------------------------------------------------
# Asset Value Tiers (USD)
# Used when a case doesn't specify its own asset value via tags/custom fields.
# ---------------------------------------------------------------------------

ASSET_VALUES = {
    "workstation": 5_000,
    "server": 50_000,
    "database": 500_000,
    "critical_infra": 2_000_000,
}

DEFAULT_ASSET_VALUE = int(os.getenv("DEFAULT_ASSET_VALUE", "50000"))

# ---------------------------------------------------------------------------
# Data Sensitivity Multipliers
# Applied on top of the base asset value.
# ---------------------------------------------------------------------------

SENSITIVITY_MULTIPLIERS = {
    "public": 1.0,
    "internal": 2.0,
    "confidential": 5.0,
    "restricted": 10.0,
}

DEFAULT_SENSITIVITY = "internal"

# ---------------------------------------------------------------------------
# Analyzer Verdict Weights  (used to compute Likelihood)
# Each Cortex taxonomy level maps to a weight between 0 and 1.
# ---------------------------------------------------------------------------

VERDICT_WEIGHTS = {
    "malicious": 1.0,
    "suspicious": 0.6,
    "safe": 0.1,
    "info": 0.0,
}

# Bonus multiplier when >=N independent analyzers agree on "malicious"
MALICIOUS_CONSENSUS_THRESHOLD = 2
MALICIOUS_CONSENSUS_BOOST = 1.25  # 25 % bump, capped at 1.0

# ---------------------------------------------------------------------------
# Risk Level Thresholds (ALE in USD)
# ---------------------------------------------------------------------------

RISK_THRESHOLDS = {
    "critical": 500_000,
    "high": 100_000,
    "medium": 10_000,
    "low": 1_000,
    # anything below "low" is "info"
}

# ---------------------------------------------------------------------------
# Watch-mode defaults
# ---------------------------------------------------------------------------

WATCH_INTERVAL_SECONDS = int(os.getenv("WATCH_INTERVAL", "30"))

# Tag applied to cases after scoring so they aren't re-scored
SCORED_TAG = "risk:scored"
