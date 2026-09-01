<div align="center">

# 🛡 Honeypot-AI

**Cowrie SSH Honeypot · Real-Time Threat Intelligence Platform**

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.35+-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)](https://streamlit.io)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4+-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

*Parse → Enrich → Score → Visualise — from raw Cowrie logs to actionable threat intelligence in seconds.*

</div>

---

## ✨ What is Honeypot-AI?

**Honeypot-AI** is a production-grade intelligence layer that sits on top of [Cowrie](https://github.com/cowrie/cowrie), the SSH/Telnet honeypot. It transforms raw JSON event logs into a rich, interactive threat intelligence dashboard — giving you:

- **Composite threat scores** (0–100) per attacker session
- **MITRE ATT&CK tactic mapping** from captured shell commands
- **Attacker geolocation** on an interactive world map
- **ML anomaly detection** (Isolation Forest) on command sequences
- **Campaign clustering** (DBSCAN) to group coordinated attacker sessions
- **Markdown + JSON report export** for incident documentation

---

## 🏗 Architecture

```
cowrie.json (NDJSON)
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│  honeypot_ai/                                                   │
│                                                                 │
│  ingestion/                  ml/                  intel/        │
│  ┌─────────────────┐   ┌──────────────────┐   ┌────────────┐   │
│  │ cowrie_parser   │──▶│ anomaly_detector │   │   geoip    │   │
│  │ (NDJSON → DFs)  │   │ (IsolationForest)│   │ (ip-api)   │   │
│  └─────────────────┘   ├──────────────────┤   ├────────────┤   │
│                         │ threat_scorer    │   │mitre_mapper│   │
│                         │ (0–100 composite)│   ├────────────┤   │
│                         └──────────────────┘   │ campaign_  │   │
│                                                │ clusterer  │   │
│                                                │ (DBSCAN)   │   │
│                                                └────────────┘   │
└──────────────────────────────┬──────────────────────────────────┘
                               │
              ┌────────────────┴────────────────┐
              │                                 │
              ▼                                 ▼
   dashboard/app.py                    honeypot_ai/cli.py
   (Streamlit · 7 panels)              (Click + Rich CLI)
```

---

## 🚀 Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/mihirdixit/honeypot-ai.git
cd honeypot-ai
pip install -r requirements.txt
```

### 2. Run Analysis (CLI)

```bash
python -m honeypot_ai.cli analyze \
  -i cowrie/var/log/cowrie/cowrie.json \
  -o output
```

Output:

```
  sessions.csv       — per-session threat data
  commands_all.csv   — all commands with intent + anomaly score
  anomalies.csv      — flagged anomalous commands
  report.md          — Markdown threat intelligence report
  report.json        — machine-readable JSON report
```

### 3. Launch Dashboard

```bash
streamlit run dashboard/app.py
# → http://localhost:8501
```

---

## 🐳 Docker (Full Stack)

```bash
# Spin up Cowrie + Honeypot-AI dashboard
docker-compose up -d

# Dashboard → http://localhost:8501
# Cowrie SSH honeypot → localhost:2222
```

---

## 🧠 Intelligence Features

| Feature | Implementation |
|---|---|
| **Anomaly detection** | `IsolationForest` on dual TF-IDF (word + char n-grams) |
| **Threat scoring** | Weighted composite: malware·35 + lateral·20 + anomalies·20 + tactics·15 + login·10 |
| **Command intent** | Rule-based regex → `RECON`, `PERSISTENCE`, `LATERAL_MOVEMENT`, `MALWARE_DOWNLOAD` |
| **MITRE mapping** | Intent → ATT&CK technique IDs (T1059, T1082, T1105, …) |
| **GeoIP enrichment** | ip-api.com batch endpoint (no key required) |
| **Campaign clustering** | `DBSCAN` on TF-IDF command profile + numeric session features |

---

## 🎯 Threat Scoring Engine

The threat scoring module is the core of Honeypot-AI — and the piece that took the most iteration to get right.

The ML pipeline (TF-IDF feature extraction, Isolation Forest anomaly detection, DBSCAN campaign clustering) was relatively straightforward once the right algorithms were selected. The hard problem was the **scoring layer on top**: taking five noisy signals from the model output and combining them into a single number that actually means something to a human analyst reviewing it.

### Signal Weights

| Signal | Weight | Rationale |
|---|---|---|
| Malware download attempt | **35** | Strongest indicator of intent — attacker has moved past recon |
| Lateral movement command | **20** | Suggests an active campaign, not a lone scan |
| Anomalous command count | **20** | Model-driven; accounts for unusual sequences IDS rules miss |
| Unique ATT&CK tactics | **15** | Multi-stage attacks span more tactic categories |
| Login success rate | **10** | Useful signal, but brute-force is noisy — kept low to reduce false positives |

### Calibration Philosophy

A naive approach — equal weights or pure model score — flagged nearly every brute-force attempt as CRITICAL. The weight calibration went through several iterations:

1. **Start heavy on model output** → too many false positives on commodity scanners
2. **Downweight anomaly score, upweight behavioural signals** (malware, lateral movement) → false-positive rate dropped significantly
3. **Cap tactics at five known categories** to prevent score inflation from repeated recon

The result is a score that reserves CRITICAL (≥ 70) for sessions where the attacker has already demonstrated capability — not just intent — and HIGH (≥ 45) for multi-stage attempts worth human review.

```python
score = (
    35 * has_malware       # binary: wget/curl to external host
    + 20 * has_lateral     # binary: ssh/scp pivoting commands
    + 20 * anom_norm       # normalised anomaly count (0–1)
    + 15 * tactics_norm    # unique MITRE tactics / 5 (0–1)
    + 10 * login_success   # login success rate (0–1)
).clip(0, 100)
```

See [`honeypot_ai/ml/threat_scorer.py`](honeypot_ai/ml/threat_scorer.py) for the full implementation.

---

## 📊 Dashboard Panels

| # | Panel | What it shows |
|---|---|---|
| 1 | **KPI Overview** | Sessions, IPs, commands, anomalies, max score, CRITICAL count |
| 2 | **Threat Leaderboard** | Sessions ranked by threat score with color-coded levels |
| 3 | **Command Inspector** | Filterable command log with intent labels + anomaly scores |
| 4 | **MITRE ATT&CK Tactics** | Horizontal bar chart of tactic hit frequency |
| 5 | **GeoIP World Map** | Plotly globe — bubble size = command count, color = threat score |
| 6 | **Anomaly Explorer** | Scatter plot of Isolation Forest decision scores |
| 7 | **Campaign Clusters** | DBSCAN scatter — grouped attacker campaigns |

---

## 🧪 Tests

```bash
pytest tests/ -v
```

Covers: parser correctness, threat scorer range, MITRE mapper, anomaly detector.

---

## 📁 Project Structure

```
honeypot-ai/
├── honeypot_ai/
│   ├── cli.py                    # Click + Rich CLI
│   ├── ingestion/
│   │   └── cowrie_parser.py      # NDJSON → structured DataFrames
│   ├── ml/
│   │   ├── anomaly_detector.py   # IsolationForest (dual TF-IDF)
│   │   └── threat_scorer.py      # Composite 0–100 threat score
│   ├── intel/
│   │   ├── geoip.py              # GeoIP enrichment (ip-api.com)
│   │   ├── mitre_mapper.py       # MITRE ATT&CK technique mapping
│   │   └── campaign_clusterer.py # DBSCAN campaign detection
│   └── report/
│       └── generator.py          # Markdown + JSON report export
├── dashboard/
│   └── app.py                    # Streamlit dashboard (7 panels)
├── tests/
│   └── test_parser.py            # pytest test suite
├── cowrie/                       # Cowrie honeypot (submodule)
├── docker-compose.yml
├── Dockerfile
├── Makefile
├── requirements.txt
└── .env.example
```

---

## 🛣 Roadmap

- [ ] Live log tailing (auto-refresh dashboard)
- [ ] Threat feed integration (AbuseIPDB, VirusTotal)
- [ ] Password spray / brute-force pattern detection
- [ ] Grafana + InfluxDB real-time metrics export
- [ ] Telegram / Slack alerting on CRITICAL sessions

---

## 👤 Author

**Mihir Dixit** · [GitHub](https://github.com/mihirdixit)

---

<div align="center">
<sub>Built with ❤️ on top of <a href="https://github.com/cowrie/cowrie">Cowrie</a></sub>
</div>
