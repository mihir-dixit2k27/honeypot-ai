<div align="center">

# honeypot-ai

**Cowrie SSH Honeypot + Threat Intelligence Pipeline**

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4+-F7931E?style=flat-square&logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.35+-FF4B4B?style=flat-square&logo=streamlit&logoColor=white)](https://streamlit.io)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

*Raw Cowrie logs in. Scored, enriched, clustered threat intel out.*

</div>

---

## What it does

honeypot-ai sits on top of [Cowrie](https://github.com/cowrie/cowrie) and turns its NDJSON event logs into something you can actually act on:

- composite threat scores (0-100) per attacker session
- MITRE ATT&CK tactic mapping from captured shell commands
- ML anomaly detection (Isolation Forest) on command sequences
- campaign clustering (DBSCAN) to group related attacker sessions
- attacker geolocation on an interactive world map
- Markdown + JSON report export

---

## Architecture

```
cowrie.json
    |
    v
ingestion/cowrie_parser.py     -- NDJSON -> structured DataFrames
    |
    +-- ml/anomaly_detector.py -- Isolation Forest on dual TF-IDF features
    |
    +-- ml/threat_scorer.py    -- 5-signal composite score (0-100)
    |
    +-- intel/geoip.py         -- ip-api.com batch geolocation
    +-- intel/mitre_mapper.py  -- intent -> ATT&CK technique IDs
    +-- intel/campaign_clusterer.py -- DBSCAN attacker grouping
    |
    +-- report/generator.py    -- Markdown + JSON export
    |
    +-- cli.py                 -- Click + Rich CLI
    +-- dashboard/app.py       -- Streamlit dashboard (7 panels)
```

---

## Quick start

```bash
git clone https://github.com/mihirdixit2k27/honeypot-ai.git
cd honeypot-ai
pip install -r requirements.txt

# Run analysis
python -m honeypot_ai.cli analyze -i cowrie/var/log/cowrie/cowrie.json -o output

# Launch dashboard
streamlit run dashboard/app.py
```

Docker:

```bash
docker-compose up -d
# dashboard -> http://localhost:8501
# honeypot  -> localhost:2222
```

---

## Threat scoring

The threat scorer is the piece I spent the most time on. The ML pipeline (TF-IDF, Isolation Forest, DBSCAN) was fairly standard once I picked the right algorithms. The harder problem was the scoring layer on top: taking five noisy signals from the model output and combining them into a single number that means something to a human reviewer.

Getting the weights right so the classifier does not flag every brute-force scan as CRITICAL took several iterations. That iteration is where I learned the most about when model output is genuinely useful versus when it is just noise.

| Signal | Weight | Why |
|---|---|---|
| Malware download attempt | 35 | Attacker has moved past recon into active exploitation |
| Lateral movement command | 20 | Suggests a coordinated campaign, not an isolated scan |
| Anomalous command count | 20 | Model-driven; catches sequences rule sets miss |
| Unique ATT&CK tactics | 15 | Multi-stage attacks span more tactic categories |
| Login success rate | 10 | Useful but noisy on brute-force heavy traffic |

```python
score = (
    35 * has_malware
    + 20 * has_lateral
    + 20 * anom_norm        # normalised Isolation Forest anomaly count
    + 15 * tactics_norm     # unique MITRE tactics / 5
    + 10 * login_success
).clip(0, 100)
```

Labels: `CRITICAL >= 70`, `HIGH >= 45`, `MEDIUM >= 20`, `LOW < 20`

See [`honeypot_ai/ml/threat_scorer.py`](honeypot_ai/ml/threat_scorer.py).

---

## Tests

```bash
pytest tests/ -v
```

---

## Project layout

```
honeypot-ai/
+-- honeypot_ai/
|   +-- cli.py
|   +-- ingestion/cowrie_parser.py
|   +-- ml/anomaly_detector.py
|   +-- ml/threat_scorer.py
|   +-- intel/geoip.py
|   +-- intel/mitre_mapper.py
|   +-- intel/campaign_clusterer.py
|   +-- report/generator.py
+-- dashboard/app.py
+-- tests/
+-- docker-compose.yml
+-- Dockerfile
+-- Makefile
```

---

**Mihir Dixit** - [github.com/mihirdixit2k27](https://github.com/mihirdixit2k27)
