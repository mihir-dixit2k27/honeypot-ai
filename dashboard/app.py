"""
app.py — Honeypot-AI Flagship Streamlit Dashboard
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
7 panels:
  1. KPI Overview cards
  2. Threat Leaderboard
  3. Command Inspector
  4. MITRE ATT&CK Heatmap
  5. GeoIP World Map
  6. Anomaly Explorer
  7. Campaign View
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Allow running `streamlit run dashboard/app.py` from the project root
ROOT = Path(__file__).parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from honeypot_ai.ingestion.cowrie_parser import parse_cowrie_log
from honeypot_ai.ml.anomaly_detector import detect_anomalies
from honeypot_ai.ml.threat_scorer import score_sessions
from honeypot_ai.intel.mitre_mapper import build_tactic_frequency, build_technique_frequency
from honeypot_ai.intel.campaign_clusterer import cluster_campaigns
from honeypot_ai.intel.geoip import enrich_ips

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Honeypot-AI · Threat Intelligence",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

/* Dark glassmorphism background */
.stApp {
    background: linear-gradient(135deg, #0a0e1a 0%, #0d1526 50%, #0a1020 100%);
}

/* Hero banner */
.hero-banner {
    background: linear-gradient(135deg,
        rgba(0, 212, 255, 0.12) 0%,
        rgba(139, 92, 246, 0.08) 50%,
        rgba(236, 72, 153, 0.06) 100%);
    border: 1px solid rgba(0, 212, 255, 0.2);
    border-radius: 16px;
    padding: 28px 36px;
    margin-bottom: 24px;
    backdrop-filter: blur(10px);
    text-align: center;
}

.hero-banner h1 {
    font-size: 2.4rem;
    font-weight: 700;
    background: linear-gradient(135deg, #00d4ff, #8b5cf6, #ec4899);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin: 0;
    letter-spacing: -0.5px;
}

.hero-banner p {
    color: rgba(255,255,255,0.5);
    margin: 8px 0 0;
    font-size: 0.95rem;
}

/* KPI cards */
.kpi-card {
    background: linear-gradient(145deg, rgba(255,255,255,0.06), rgba(255,255,255,0.02));
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 12px;
    padding: 20px 24px;
    text-align: center;
    transition: transform 0.2s, border-color 0.2s;
    cursor: default;
}
.kpi-card:hover {
    transform: translateY(-2px);
    border-color: rgba(0,212,255,0.3);
}
.kpi-label {
    font-size: 0.75rem;
    font-weight: 500;
    letter-spacing: 1.2px;
    text-transform: uppercase;
    color: rgba(255,255,255,0.45);
    margin-bottom: 8px;
}
.kpi-value {
    font-size: 2.4rem;
    font-weight: 700;
    line-height: 1;
    font-family: 'JetBrains Mono', monospace;
}
.kpi-sub {
    font-size: 0.75rem;
    color: rgba(255,255,255,0.35);
    margin-top: 4px;
}

/* Threat level badges */
.badge-critical { color: #ff4444; font-weight: 700; }
.badge-high     { color: #ff8c42; font-weight: 700; }
.badge-medium   { color: #ffd23f; font-weight: 700; }
.badge-low      { color: #44ff88; font-weight: 700; }

/* Section headers */
.section-header {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 16px 0 8px;
    border-bottom: 1px solid rgba(255,255,255,0.06);
    margin-bottom: 16px;
}
.section-header h2 {
    font-size: 1.1rem;
    font-weight: 600;
    color: rgba(255,255,255,0.9);
    margin: 0;
    letter-spacing: -0.2px;
}

/* Sidebar tweaks */
section[data-testid="stSidebar"] {
    background: rgba(0,0,0,0.4);
    border-right: 1px solid rgba(255,255,255,0.06);
}

/* Table tweaks */
.dataframe {
    font-size: 0.85rem !important;
}

/* Plotly charts - transparent backgrounds */
.js-plotly-plot .plotly .bg {
    fill: transparent !important;
}
</style>
""", unsafe_allow_html=True)


# ── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### ⚙️ Configuration")
    default_log = os.environ.get(
        "HONEYPOT_AI_LOG",
        str(ROOT / "cowrie" / "var" / "log" / "cowrie" / "cowrie.json"),
    )
    log_path = st.text_input("Cowrie log path", value=default_log)
    contamination = st.slider("Anomaly sensitivity", 0.01, 0.5, 0.05, 0.01,
                              help="IsolationForest contamination parameter")
    enable_geo = st.toggle("GeoIP enrichment", value=True,
                           help="Calls ip-api.com — disable when offline")
    st.divider()
    run_btn = st.button("🚀 Run Analysis", type="primary", use_container_width=True)
    st.divider()
    st.caption("**Honeypot-AI** v1.0.0")
    st.caption("Cowrie SSH honeypot intelligence platform")


# ── Hero banner ────────────────────────────────────────────────────────────────
st.markdown("""
<div class="hero-banner">
  <h1>🛡 Honeypot-AI</h1>
  <p>Real-time Cowrie SSH Honeypot · Threat Intelligence Dashboard</p>
</div>
""", unsafe_allow_html=True)


# ── Session state ─────────────────────────────────────────────────────────────
if "analysed" not in st.session_state:
    st.session_state.analysed = False
    st.session_state.sessions = pd.DataFrame()
    st.session_state.commands = pd.DataFrame()
    st.session_state.geo = {}


@st.cache_data(show_spinner=False)
def run_analysis(log_path: str, contamination: float, enable_geo: bool):
    parsed = parse_cowrie_log(log_path)
    commands = detect_anomalies(parsed.commands, contamination=contamination)
    sessions = score_sessions(parsed.sessions, commands)
    sessions = cluster_campaigns(sessions, commands)

    geo = {}
    if enable_geo and not sessions.empty:
        unique_ips = sessions["src_ip"].dropna().unique().tolist()
        geo = enrich_ips(unique_ips)

    return sessions, commands, geo, parsed


# ── Trigger analysis ─────────────────────────────────────────────────────────
if run_btn or not st.session_state.analysed:
    with st.spinner("🔍 Analysing honeypot data…"):
        try:
            sessions, commands, geo, parsed = run_analysis(log_path, contamination, enable_geo)
            st.session_state.sessions = sessions
            st.session_state.commands = commands
            st.session_state.geo = geo
            st.session_state.analysed = True
            if run_btn:
                st.success(f"✅ Loaded {len(parsed.raw_df)} events from {log_path}")
        except Exception as e:
            st.error(f"❌ Failed to parse log: {e}")
            st.stop()

sessions: pd.DataFrame = st.session_state.sessions
commands: pd.DataFrame = st.session_state.commands
geo: dict = st.session_state.geo

if sessions.empty and commands.empty:
    st.info("👆 Click **Run Analysis** in the sidebar to begin.")
    st.stop()


# ═══════════════════════════════════════════════════════════════════════════════
# PANEL 1 — KPI cards
# ═══════════════════════════════════════════════════════════════════════════════
st.markdown('<div class="section-header"><h2>📊 Threat Overview</h2></div>', unsafe_allow_html=True)

total_sessions = len(sessions)
unique_ips = sessions["src_ip"].nunique() if "src_ip" in sessions.columns else 0
total_cmds = len(commands)
anomalies = int(commands["anomaly"].sum()) if "anomaly" in commands.columns else 0
max_score = float(sessions["threat_score"].max()) if "threat_score" in sessions.columns else 0.0
critical_count = int((sessions["threat_level"] == "CRITICAL").sum()) if "threat_level" in sessions.columns else 0

k1, k2, k3, k4, k5, k6 = st.columns(6)
kpis = [
    (k1, "🖥", "SESSIONS", str(total_sessions), "total connections"),
    (k2, "🌐", "UNIQUE IPs", str(unique_ips), "distinct attackers"),
    (k3, "💻", "COMMANDS", str(total_cmds), "captured inputs"),
    (k4, "⚠️", "ANOMALIES", str(anomalies), "flagged commands"),
    (k5, "🔥", "MAX THREAT", f"{max_score:.0f}/100", "composite score"),
    (k6, "🚨", "CRITICAL", str(critical_count), "high-risk sessions"),
]
for col, icon, label, value, sub in kpis:
    color = "#ff4444" if label == "CRITICAL" else ("#ff8c42" if label == "MAX THREAT" else "#00d4ff")
    col.markdown(f"""
    <div class="kpi-card">
      <div class="kpi-label">{label}</div>
      <div class="kpi-value" style="color:{color}">{value}</div>
      <div class="kpi-sub">{sub}</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
# PANEL 2 — Threat Leaderboard
# ═══════════════════════════════════════════════════════════════════════════════
st.markdown('<div class="section-header"><h2>🏆 Threat Leaderboard</h2></div>', unsafe_allow_html=True)

if not sessions.empty and "threat_score" in sessions.columns:
    display_cols = [c for c in ["session", "src_ip", "threat_score", "threat_level",
                                "cmd_count", "login_attempts", "login_successes",
                                "has_malware", "has_lateral", "campaign_id"]
                   if c in sessions.columns]
    leaderboard = sessions.nlargest(20, "threat_score")[display_cols].reset_index(drop=True)
    leaderboard.index += 1

    def color_level(val):
        colors = {"CRITICAL": "color: #ff4444; font-weight:700",
                  "HIGH": "color: #ff8c42; font-weight:700",
                  "MEDIUM": "color: #ffd23f; font-weight:700",
                  "LOW": "color: #44ff88; font-weight:700"}
        return colors.get(val, "")

    styled = leaderboard.style.applymap(color_level, subset=["threat_level"] if "threat_level" in leaderboard.columns else [])
    st.dataframe(styled, use_container_width=True, height=320)
else:
    st.info("No session data available.")

st.markdown("<br>", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
# PANEL 3 — Command Inspector + MITRE side by side
# ═══════════════════════════════════════════════════════════════════════════════
col_left, col_right = st.columns([3, 2])

with col_left:
    st.markdown('<div class="section-header"><h2>🖥 Command Inspector</h2></div>', unsafe_allow_html=True)

    if not commands.empty:
        intent_filter = st.multiselect(
            "Filter by intent",
            options=commands["intent"].unique().tolist() if "intent" in commands.columns else [],
            default=commands["intent"].unique().tolist() if "intent" in commands.columns else [],
        )
        anomaly_only = st.checkbox("Show anomalies only", value=False)

        filtered = commands.copy()
        if intent_filter and "intent" in filtered.columns:
            filtered = filtered[filtered["intent"].isin(intent_filter)]
        if anomaly_only and "anomaly" in filtered.columns:
            filtered = filtered[filtered["anomaly"]]

        display_cmd_cols = [c for c in ["session", "src_ip", "timestamp", "input", "intent", "anomaly", "anomaly_score"]
                           if c in filtered.columns]
        st.dataframe(filtered[display_cmd_cols].reset_index(drop=True),
                     use_container_width=True, height=340)
    else:
        st.info("No command data.")

with col_right:
    st.markdown('<div class="section-header"><h2>🎯 MITRE ATT&CK Tactics</h2></div>', unsafe_allow_html=True)

    if not commands.empty and "intent" in commands.columns:
        tactic_freq = build_tactic_frequency(commands)
        if tactic_freq:
            tdf = pd.DataFrame(list(tactic_freq.items()), columns=["Tactic", "Count"])
            tdf = tdf.sort_values("Count", ascending=True)

            fig_mitre = px.bar(
                tdf, x="Count", y="Tactic", orientation="h",
                color="Count",
                color_continuous_scale=["#1a1a2e", "#8b5cf6", "#ec4899", "#ff4444"],
                title="Tactic Hit Frequency",
            )
            fig_mitre.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="rgba(255,255,255,0.7)", size=11),
                coloraxis_showscale=False,
                margin=dict(l=0, r=0, t=40, b=0),
                height=340,
                title_font_color="rgba(255,255,255,0.9)",
                xaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
                yaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
            )
            st.plotly_chart(fig_mitre, use_container_width=True)
    else:
        st.info("No command data for MITRE mapping.")

st.markdown("<br>", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
# PANEL 4 — GeoIP Map + Anomaly Explorer side by side
# ═══════════════════════════════════════════════════════════════════════════════
col_map, col_anom = st.columns([3, 2])

with col_map:
    st.markdown('<div class="section-header"><h2>🌍 Attacker GeoIP Map</h2></div>', unsafe_allow_html=True)

    if geo:
        geo_rows = []
        for ip, data in geo.items():
            count = sessions[sessions["src_ip"] == ip]["cmd_count"].sum() if not sessions.empty else 1
            score = sessions[sessions["src_ip"] == ip]["threat_score"].max() if not sessions.empty else 0
            geo_rows.append({
                "ip": ip,
                "country": data.get("country", "Unknown"),
                "city": data.get("city", "Unknown"),
                "lat": data.get("lat", 0),
                "lon": data.get("lon", 0),
                "isp": data.get("isp", "Unknown"),
                "cmd_count": int(count),
                "threat_score": float(score),
            })
        geo_df = pd.DataFrame(geo_rows)

        fig_map = px.scatter_geo(
            geo_df,
            lat="lat", lon="lon",
            hover_name="ip",
            hover_data={"country": True, "city": True, "isp": True,
                        "cmd_count": True, "threat_score": True,
                        "lat": False, "lon": False},
            size="cmd_count",
            size_max=30,
            color="threat_score",
            color_continuous_scale=["#00d4ff", "#8b5cf6", "#ec4899", "#ff4444"],
            projection="natural earth",
            title="Attacker Origin — bubble size = command count",
        )
        fig_map.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            geo=dict(
                bgcolor="rgba(0,0,0,0)",
                showland=True, landcolor="rgba(30,40,60,0.8)",
                showocean=True, oceancolor="rgba(10,20,40,0.8)",
                showframe=False, showcountries=True,
                countrycolor="rgba(255,255,255,0.1)",
            ),
            coloraxis_colorbar=dict(title="Threat", tickfont=dict(color="rgba(255,255,255,0.6)")),
            margin=dict(l=0, r=0, t=40, b=0),
            height=380,
            font=dict(color="rgba(255,255,255,0.7)"),
            title_font_color="rgba(255,255,255,0.9)",
        )
        st.plotly_chart(fig_map, use_container_width=True)
    else:
        st.info("GeoIP disabled or no public IP data. Enable GeoIP in the sidebar.")

with col_anom:
    st.markdown('<div class="section-header"><h2>🔬 Anomaly Explorer</h2></div>', unsafe_allow_html=True)

    if not commands.empty and "anomaly_score" in commands.columns:
        fig_anom = px.scatter(
            commands,
            x=commands.index,
            y="anomaly_score",
            color="anomaly",
            color_discrete_map={True: "#ff4444", False: "#00d4ff"},
            hover_data=["input", "intent"],
            labels={"x": "Command #", "anomaly_score": "IF Score (lower = more anomalous)"},
            title="Anomaly Score Distribution",
        )
        fig_anom.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="rgba(255,255,255,0.7)", size=11),
            legend_title_text="Anomaly",
            margin=dict(l=0, r=0, t=40, b=0),
            height=380,
            title_font_color="rgba(255,255,255,0.9)",
            xaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
            yaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
        )
        st.plotly_chart(fig_anom, use_container_width=True)
    else:
        st.info("No anomaly score data.")

st.markdown("<br>", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
# PANEL 5 — Threat Score Timeline + Campaign View
# ═══════════════════════════════════════════════════════════════════════════════
col_timeline, col_camp = st.columns([3, 2])

with col_timeline:
    st.markdown('<div class="section-header"><h2>📈 Threat Score by Session</h2></div>', unsafe_allow_html=True)

    if not sessions.empty and "threat_score" in sessions.columns:
        chart_df = sessions.sort_values("connect_time") if "connect_time" in sessions.columns else sessions
        fig_bar = px.bar(
            chart_df,
            x="session",
            y="threat_score",
            color="threat_level" if "threat_level" in chart_df.columns else "threat_score",
            color_discrete_map={
                "CRITICAL": "#ff4444",
                "HIGH": "#ff8c42",
                "MEDIUM": "#ffd23f",
                "LOW": "#44ff88",
            },
            hover_data=[c for c in ["src_ip", "cmd_count", "threat_level"] if c in chart_df.columns],
            title="Composite Threat Score per Session",
        )
        fig_bar.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="rgba(255,255,255,0.7)", size=11),
            margin=dict(l=0, r=0, t=40, b=0),
            height=320,
            title_font_color="rgba(255,255,255,0.9)",
            xaxis=dict(gridcolor="rgba(255,255,255,0.05)", tickangle=-30),
            yaxis=dict(gridcolor="rgba(255,255,255,0.05)", range=[0, 105]),
            showlegend=True,
        )
        st.plotly_chart(fig_bar, use_container_width=True)

with col_camp:
    st.markdown('<div class="section-header"><h2>🕸 Campaign Clusters</h2></div>', unsafe_allow_html=True)

    if not sessions.empty and "campaign_id" in sessions.columns and "cmd_count" in sessions.columns:
        camp_df = sessions.copy()
        camp_df["campaign_label"] = camp_df["campaign_id"].apply(
            lambda x: f"Noise" if x == -1 else f"Campaign {x}"
        )
        fig_camp = px.scatter(
            camp_df,
            x="cmd_count",
            y="threat_score" if "threat_score" in camp_df.columns else "cmd_count",
            color="campaign_label",
            hover_data=[c for c in ["session", "src_ip", "threat_level"] if c in camp_df.columns],
            size="cmd_count",
            size_max=20,
            title="Campaign Clusters (DBSCAN)",
            labels={"cmd_count": "Command Count", "threat_score": "Threat Score"},
        )
        fig_camp.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="rgba(255,255,255,0.7)", size=11),
            margin=dict(l=0, r=0, t=40, b=0),
            height=320,
            title_font_color="rgba(255,255,255,0.9)",
            xaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
            yaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
        )
        st.plotly_chart(fig_camp, use_container_width=True)
    else:
        st.info("Insufficient sessions for campaign clustering.")

# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown(
    "<center><span style='color:rgba(255,255,255,0.25);font-size:0.8rem;'>"
    "🛡 Honeypot-AI v1.0.0 · Built with Streamlit, Plotly, scikit-learn · "
    "Cowrie SSH/Telnet Honeypot Intelligence Platform"
    "</span></center>",
    unsafe_allow_html=True,
)
