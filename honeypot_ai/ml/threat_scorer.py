"""
threat_scorer.py
~~~~~~~~~~~~~~~~
Compute a composite threat score (0–100) for each honeypot session.

Score is the weighted sum of five normalised signals:

  ┌──────────────────────────────┬────────┐
  │ Signal                       │ Weight │
  ├──────────────────────────────┼────────┤
  │ Malware download attempt     │  35    │
  │ Lateral movement command     │  20    │
  │ Anomalous command count      │  20    │
  │ Unique attack tactics (ITPs) │  15    │
  │ Login success                │  10    │
  └──────────────────────────────┴────────┘
"""

from __future__ import annotations

import numpy as np
import pandas as pd


def score_sessions(
    sessions: pd.DataFrame,
    commands: pd.DataFrame,
) -> pd.DataFrame:
    """
    Attach a ``threat_score`` column (float, 0–100) to each session.

    Parameters
    ----------
    sessions:
        DataFrame produced by :func:`cowrie_parser.parse_cowrie_log`.
    commands:
        Commands DataFrame with ``anomaly`` and ``intent`` columns
        (output of anomaly_detector.detect_anomalies).

    Returns
    -------
    pd.DataFrame
        Sessions DataFrame with ``threat_score`` and ``threat_level`` columns.
    """
    df = sessions.copy()

    # ── signal: malware download ─────────────────────────────────────────────
    has_malware = df.get("has_malware", pd.Series(False, index=df.index)).astype(float)

    # ── signal: lateral movement command ────────────────────────────────────
    has_lateral = df.get("has_lateral", pd.Series(False, index=df.index)).astype(float)

    # ── signal: anomalous command count (normalised 0–1) ────────────────────
    if not commands.empty and "anomaly" in commands.columns:
        anom_per_session = (
            commands[commands["anomaly"]]
            .groupby("session")
            .size()
            .rename("anom_count")
        )
        df = df.merge(anom_per_session, on="session", how="left")
        df["anom_count"] = df["anom_count"].fillna(0).astype(int)
        max_anom = df["anom_count"].max()
        anom_norm = df["anom_count"] / max_anom if max_anom > 0 else pd.Series(0.0, index=df.index)
    else:
        df["anom_count"] = 0
        anom_norm = pd.Series(0.0, index=df.index)

    # ── signal: unique tactics (normalised 0–1) ──────────────────────────────
    max_intents = 5  # RECON, PERSISTENCE, LATERAL_MOVEMENT, MALWARE_DOWNLOAD, OTHER
    tactics_norm = (df.get("unique_intents", pd.Series(0, index=df.index)) / max_intents).clip(0, 1)

    # ── signal: login success ─────────────────────────────────────────────────
    login_success = df.get("login_success_rate", pd.Series(0.0, index=df.index)).clip(0, 1)

    # ── composite score ───────────────────────────────────────────────────────
    score = (
        35 * has_malware
        + 20 * has_lateral
        + 20 * anom_norm
        + 15 * tactics_norm
        + 10 * login_success
    ).clip(0, 100).round(1)

    df["threat_score"] = score.values

    # Human-readable label
    def _level(s: float) -> str:
        if s >= 70:
            return "CRITICAL"
        if s >= 45:
            return "HIGH"
        if s >= 20:
            return "MEDIUM"
        return "LOW"

    df["threat_level"] = df["threat_score"].apply(_level)
    return df
