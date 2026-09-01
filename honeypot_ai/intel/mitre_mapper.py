"""
mitre_mapper.py
~~~~~~~~~~~~~~~
Map command intents to MITRE ATT&CK for Enterprise technique IDs and names.

Reference: https://attack.mitre.org/

The mapping is intentionally pragmatic (not exhaustive) — focused on the
commands that appear commonly in Cowrie SSH honeypot sessions.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    id: str          # e.g. "T1059.004"
    name: str        # e.g. "Unix Shell"
    tactic: str      # e.g. "Execution"
    url: str         # MITRE ATT&CK URL


# Intent label → list of relevant techniques
INTENT_TO_TECHNIQUES: dict[str, list[Technique]] = {
    "RECON": [
        Technique("T1082", "System Information Discovery", "Discovery",
                  "https://attack.mitre.org/techniques/T1082/"),
        Technique("T1049", "System Network Connections Discovery", "Discovery",
                  "https://attack.mitre.org/techniques/T1049/"),
        Technique("T1033", "System Owner/User Discovery", "Discovery",
                  "https://attack.mitre.org/techniques/T1033/"),
        Technique("T1083", "File and Directory Discovery", "Discovery",
                  "https://attack.mitre.org/techniques/T1083/"),
    ],
    "PERSISTENCE": [
        Technique("T1053.003", "Cron", "Persistence",
                  "https://attack.mitre.org/techniques/T1053/003/"),
        Technique("T1098.004", "SSH Authorized Keys", "Persistence",
                  "https://attack.mitre.org/techniques/T1098/004/"),
        Technique("T1136.001", "Local Account", "Persistence",
                  "https://attack.mitre.org/techniques/T1136/001/"),
    ],
    "LATERAL_MOVEMENT": [
        Technique("T1021.004", "SSH", "Lateral Movement",
                  "https://attack.mitre.org/techniques/T1021/004/"),
        Technique("T1570", "Lateral Tool Transfer", "Lateral Movement",
                  "https://attack.mitre.org/techniques/T1570/"),
        Technique("T1046", "Network Service Discovery", "Discovery",
                  "https://attack.mitre.org/techniques/T1046/"),
    ],
    "MALWARE_DOWNLOAD": [
        Technique("T1105", "Ingress Tool Transfer", "Command and Control",
                  "https://attack.mitre.org/techniques/T1105/"),
        Technique("T1059.004", "Unix Shell", "Execution",
                  "https://attack.mitre.org/techniques/T1059/004/"),
        Technique("T1027", "Obfuscated Files or Information", "Defense Evasion",
                  "https://attack.mitre.org/techniques/T1027/"),
    ],
    "OTHER": [
        Technique("T1059.004", "Unix Shell", "Execution",
                  "https://attack.mitre.org/techniques/T1059/004/"),
    ],
}


def map_intent(intent: str) -> list[Technique]:
    """Return the MITRE techniques associated with an intent label."""
    return INTENT_TO_TECHNIQUES.get(intent, INTENT_TO_TECHNIQUES["OTHER"])


def build_technique_frequency(commands_df) -> dict[str, int]:
    """
    Count how many times each MITRE technique ID appears in the commands.

    Parameters
    ----------
    commands_df:
        DataFrame with an ``intent`` column.

    Returns
    -------
    dict mapping technique_id → count
    """
    freq: dict[str, int] = {}
    for intent in commands_df["intent"]:
        for tech in map_intent(intent):
            freq[tech.id] = freq.get(tech.id, 0) + 1
    return freq


def build_tactic_frequency(commands_df) -> dict[str, int]:
    """
    Count hits per MITRE tactic (e.g. 'Discovery', 'Persistence', …).
    """
    freq: dict[str, int] = {}
    for intent in commands_df["intent"]:
        seen_tactics: set[str] = set()
        for tech in map_intent(intent):
            if tech.tactic not in seen_tactics:
                freq[tech.tactic] = freq.get(tech.tactic, 0) + 1
                seen_tactics.add(tech.tactic)
    return freq
