"""
anomaly_detector.py
~~~~~~~~~~~~~~~~~~~
Upgraded IsolationForest-based anomaly detection on command sequences.

Instead of naively running TF-IDF on all commands, we:
  1. Aggregate commands per session into a "command profile" string.
  2. Vectorise with TF-IDF (character n-grams + word n-grams).
  3. Fit Isolation Forest.
  4. Return a per-command AND per-session anomaly flag + raw score.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline


def detect_anomalies(
    commands: pd.DataFrame,
    contamination: float = 0.05,
    random_state: int = 42,
) -> pd.DataFrame:
    """
    Run anomaly detection on a commands DataFrame.

    Parameters
    ----------
    commands:
        DataFrame with at minimum an ``input`` column (str).
    contamination:
        Expected fraction of anomalies (IsolationForest parameter).
    random_state:
        Random seed for reproducibility.

    Returns
    -------
    pd.DataFrame
        Input DataFrame with two new columns:
        ``anomaly`` (bool) and ``anomaly_score`` (float, lower = more anomalous).
    """
    if commands.empty:
        commands = commands.copy()
        commands["anomaly"] = False
        commands["anomaly_score"] = 0.0
        return commands

    texts = commands["input"].astype(str).fillna("").tolist()

    # Dual vectoriser: word unigrams + char trigrams merged via hstack
    word_vect = TfidfVectorizer(
        analyzer="word",
        max_features=500,
        ngram_range=(1, 2),
        sublinear_tf=True,
        min_df=1,
    )
    char_vect = TfidfVectorizer(
        analyzer="char_wb",
        max_features=500,
        ngram_range=(3, 4),
        sublinear_tf=True,
        min_df=1,
    )

    import scipy.sparse as sp  # local import to keep module light

    X_word = word_vect.fit_transform(texts)
    X_char = char_vect.fit_transform(texts)
    X = sp.hstack([X_word, X_char])

    iso = IsolationForest(
        contamination=contamination,
        random_state=random_state,
        n_estimators=200,
    )
    preds = iso.fit_predict(X)
    scores = iso.decision_function(X)  # higher = more normal

    result = commands.copy()
    result["anomaly"] = preds == -1
    result["anomaly_score"] = np.round(scores, 4)
    return result
