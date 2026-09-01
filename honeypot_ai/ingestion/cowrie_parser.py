"""
cowrie_parser.py
~~~~~~~~~~~~~~~~
Parse a Cowrie SSH/Telnet honeypot JSON log file into structured DataFrames.

Cowrie emits one JSON object per line (NDJSON). Each line has an `eventid`
field that identifies the type of event. This module collects every event and
produces:

    * ``raw_df``     – all events as a flat DataFrame
    * ``sessions``   – one row per TCP session with aggregated statistics
    * ``commands``   – every ``cowrie.command.input`` event, enriched
    * ``logins``     – every login attempt (success + failure)
    * ``downloads``  – every file-download event
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pandas as pd


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

MALWARE_KEYWORDS = re.compile(
    r"(wget|curl|chmod\s+\+x|base64|python\s+-c|perl\s+-e|"
    r"bash\s+-i|/dev/tcp|nc\s+-|mkfifo|xterm|exec\s+/bin)",
    re.IGNORECASE,
)

RECON_KEYWORDS = re.compile(
    r"^(ls|whoami|id|uname|cat\s+/etc/(passwd|shadow|hosts)|"
    r"ifconfig|ip\s+addr|netstat|ps\s+|top|find\s+/)",
    re.IGNORECASE,
)

PERSISTENCE_KEYWORDS = re.compile(
    r"(crontab|/etc/rc|systemctl|chpasswd|useradd|usermod|"
    r"authorized_keys|\.bashrc|\.profile)",
    re.IGNORECASE,
)

LATERAL_KEYWORDS = re.compile(
    r"(ssh\s+|scp\s+|rsync\s+|nmap\s+|masscan)",
    re.IGNORECASE,
)


def _classify_command(cmd: str) -> str:
    """Return a single intent label for a shell command string."""
    if MALWARE_KEYWORDS.search(cmd):
        return "MALWARE_DOWNLOAD"
    if LATERAL_KEYWORDS.search(cmd):
        return "LATERAL_MOVEMENT"
    if PERSISTENCE_KEYWORDS.search(cmd):
        return "PERSISTENCE"
    if RECON_KEYWORDS.search(cmd):
        return "RECON"
    return "OTHER"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ParsedLog:
    """Container returned by :func:`parse_cowrie_log`."""

    raw_df: pd.DataFrame
    sessions: pd.DataFrame
    commands: pd.DataFrame
    logins: pd.DataFrame
    downloads: pd.DataFrame
    source_path: Path


# ---------------------------------------------------------------------------
# Core parser
# ---------------------------------------------------------------------------

def parse_cowrie_log(path: str | Path) -> ParsedLog:
    """
    Parse a Cowrie NDJSON log file.

    Parameters
    ----------
    path:
        Absolute or relative path to ``cowrie.json``.

    Returns
    -------
    ParsedLog
        Structured container with four ready-to-use DataFrames.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Cowrie log not found: {path}")

    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # skip malformed lines silently

    if not records:
        raise ValueError(f"No valid JSON records found in {path}")

    raw_df = pd.json_normalize(records)

    # Ensure essential columns exist
    for col in ("src_ip", "session", "eventid", "timestamp"):
        if col not in raw_df.columns:
            raw_df[col] = None

    raw_df["timestamp"] = pd.to_datetime(raw_df["timestamp"], utc=True, errors="coerce")
    raw_df["src_ip"] = raw_df["src_ip"].fillna("unknown")

    commands = _extract_commands(raw_df)
    logins = _extract_logins(raw_df)
    downloads = _extract_downloads(raw_df)
    sessions = _build_sessions(raw_df, commands, logins, downloads)

    return ParsedLog(
        raw_df=raw_df,
        sessions=sessions,
        commands=commands,
        logins=logins,
        downloads=downloads,
        source_path=path,
    )


# ---------------------------------------------------------------------------
# Private extractors
# ---------------------------------------------------------------------------

def _extract_commands(raw: pd.DataFrame) -> pd.DataFrame:
    mask = raw["eventid"] == "cowrie.command.input"
    if not mask.any():
        return pd.DataFrame(columns=["session", "src_ip", "timestamp", "input", "intent"])

    cmds = raw.loc[mask, ["session", "src_ip", "timestamp", "input"]].copy()
    cmds["input"] = cmds["input"].astype(str).str.strip().fillna("")
    cmds["intent"] = cmds["input"].apply(_classify_command)
    cmds.reset_index(drop=True, inplace=True)
    return cmds


def _extract_logins(raw: pd.DataFrame) -> pd.DataFrame:
    mask = raw["eventid"].str.startswith("cowrie.login", na=False)
    if not mask.any():
        return pd.DataFrame(columns=["session", "src_ip", "timestamp", "username", "password", "success"])

    cols = [c for c in ["session", "src_ip", "timestamp", "username", "password", "eventid"] if c in raw.columns]
    logins = raw.loc[mask, cols].copy()
    logins["success"] = logins["eventid"] == "cowrie.login.success"
    logins.drop(columns=["eventid"], inplace=True, errors="ignore")
    logins.reset_index(drop=True, inplace=True)
    return logins


def _extract_downloads(raw: pd.DataFrame) -> pd.DataFrame:
    mask = raw["eventid"].isin(["cowrie.session.file_download", "cowrie.session.file_download.failed"])
    if not mask.any():
        return pd.DataFrame(columns=["session", "src_ip", "timestamp", "url", "outfile", "shasum"])

    cols = [c for c in ["session", "src_ip", "timestamp", "url", "outfile", "shasum"] if c in raw.columns]
    dl = raw.loc[mask, cols].copy()
    dl.reset_index(drop=True, inplace=True)
    return dl


def _build_sessions(
    raw: pd.DataFrame,
    commands: pd.DataFrame,
    logins: pd.DataFrame,
    downloads: pd.DataFrame,
) -> pd.DataFrame:
    """Aggregate per-session statistics."""

    connect_mask = raw["eventid"] == "cowrie.session.connect"
    close_mask = raw["eventid"].isin(["cowrie.session.closed", "cowrie.log.closed"])

    base = (
        raw.loc[connect_mask, ["session", "src_ip", "timestamp"]]
        .rename(columns={"timestamp": "connect_time"})
        .drop_duplicates("session")
    )

    close_times = (
        raw.loc[close_mask, ["session", "timestamp"]]
        .rename(columns={"timestamp": "close_time"})
        .drop_duplicates("session")
    )

    sessions = base.merge(close_times, on="session", how="left")

    sessions["duration_s"] = (
        sessions["close_time"] - sessions["connect_time"]
    ).dt.total_seconds()

    # Login stats
    if not logins.empty:
        login_agg = logins.groupby("session").agg(
            login_attempts=("success", "count"),
            login_successes=("success", "sum"),
        )
        login_agg["login_success_rate"] = login_agg["login_successes"] / login_agg["login_attempts"]
        sessions = sessions.merge(login_agg, on="session", how="left")
    else:
        sessions[["login_attempts", "login_successes", "login_success_rate"]] = 0

    # Command stats
    if not commands.empty:
        cmd_agg = commands.groupby("session").agg(
            cmd_count=("input", "count"),
            unique_intents=("intent", "nunique"),
            has_malware=("intent", lambda x: (x == "MALWARE_DOWNLOAD").any()),
            has_lateral=("intent", lambda x: (x == "LATERAL_MOVEMENT").any()),
        )
        sessions = sessions.merge(cmd_agg, on="session", how="left")
    else:
        sessions[["cmd_count", "unique_intents", "has_malware", "has_lateral"]] = 0

    # Download stats
    if not downloads.empty:
        dl_count = downloads.groupby("session").size().rename("download_count")
        sessions = sessions.merge(dl_count, on="session", how="left")
    else:
        sessions["download_count"] = 0

    sessions = sessions.fillna(0)
    sessions[["login_attempts", "login_successes", "cmd_count", "unique_intents", "download_count"]] = (
        sessions[["login_attempts", "login_successes", "cmd_count", "unique_intents", "download_count"]].astype(int)
    )

    return sessions.reset_index(drop=True)
