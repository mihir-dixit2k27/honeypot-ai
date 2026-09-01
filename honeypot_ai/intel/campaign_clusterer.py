"""
campaign_clusterer.py
~~~~~~~~~~~~~~~~~~~~~
Group honeypot sessions into likely attacker campaigns using DBSCAN.

Feature vector per session:
  - TF-IDF of all commands (bag-of-words profile)
  - login success rate
  - has_malware flag
  - has_lateral flag
  - cmd_count (normalised log1p)

DBSCAN is used instead of k-means because:
  1. Number of campaigns is unknown a priori.
  2. It naturally handles noise (outlier sessions → cluster -1).
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.cluster import DBSCAN
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import MinMaxScaler


def cluster_campaigns(
    sessions: pd.DataFrame,
    commands: pd.DataFrame,
    eps: float = 0.5,
    min_samples: int = 2,
) -> pd.DataFrame:
    """
    Assign a ``campaign_id`` to each session.

    Parameters
    ----------
    sessions:
        Sessions DataFrame (output of cowrie_parser + threat_scorer).
    commands:
        Commands DataFrame (with intent column).
    eps:
        DBSCAN neighbourhood radius.
    min_samples:
        Minimum sessions per cluster.

    Returns
    -------
    pd.DataFrame
        Sessions with an extra ``campaign_id`` column.
        -1 means "noise" (unclustered singleton).
    """
    df = sessions.copy()

    if df.empty or len(df) < 2:
        df["campaign_id"] = -1
        return df

    # ── command profile per session ──────────────────────────────────────────
    if not commands.empty:
        cmd_profiles = (
            commands.groupby("session")["input"]
            .apply(lambda x: " ".join(x.astype(str)))
            .rename("cmd_profile")
        )
        df = df.merge(cmd_profiles, on="session", how="left")
        df["cmd_profile"] = df["cmd_profile"].fillna("")
    else:
        df["cmd_profile"] = ""

    texts = df["cmd_profile"].tolist()
    vect = TfidfVectorizer(max_features=200, min_df=1)
    try:
        X_text = vect.fit_transform(texts).toarray()
    except ValueError:
        X_text = np.zeros((len(df), 1))

    # ── numeric features ─────────────────────────────────────────────────────
    num_cols = ["login_success_rate", "has_malware", "has_lateral", "cmd_count"]
    for col in num_cols:
        if col not in df.columns:
            df[col] = 0.0

    X_num = df[num_cols].fillna(0).astype(float).values
    X_num[:, 3] = np.log1p(X_num[:, 3])  # log-normalise cmd_count

    scaler = MinMaxScaler()
    X_num = scaler.fit_transform(X_num)

    # ── combine and cluster ───────────────────────────────────────────────────
    from scipy.sparse import issparse  # noqa: PLC0415
    X = np.hstack([X_text, X_num])

    db = DBSCAN(eps=eps, min_samples=min_samples, metric="euclidean", n_jobs=-1)
    labels = db.fit_predict(X)

    df["campaign_id"] = labels
    if "cmd_profile" in df.columns:
        df.drop(columns=["cmd_profile"], inplace=True)

    return df
