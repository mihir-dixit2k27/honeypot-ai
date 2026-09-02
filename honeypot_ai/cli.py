"""
cli.py
~~~~~~
Rich CLI entrypoint for honeypot-ai.

Commands:
    honeypot-ai analyze    -- run full analysis pipeline on a cowrie.json file
    honeypot-ai dashboard  -- launch the Streamlit dashboard
    honeypot-ai report     -- export Markdown + JSON report after analysis
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import box

console = Console()

BANNER = """[bold cyan]
  _   _  _____  _   _  _____  _____  _____  _____  __   __       ___   _____
 | | | ||  _  || \ | ||  ___||_   _||  _  ||  _  ||  \_/  |     / _ \ |_   _|
 | |_| || | | ||  \| || |__    | |  | |_| || |_| || |_+_| |    / /_\ \  | |
 |  _  || | | || . ` ||  __|   | |  |  ___||  _  ||  | |  |   /  _  _\  | |
 | | | |\ \_/ /| |\  || |___   | |  | |    | | | || | | | |  / / | | \  | |
 \_| |_/ \___/ \_| \_/\____/   \_/  \_|    \_| |_/\_| |_/ / /_/  |_|  \ \_/
[/bold cyan]
[dim]Cowrie SSH Honeypot Intelligence Platform  •  v1.0.0[/dim]
"""


@click.group()
def cli():
    """🛡  Honeypot-AI — Cowrie intelligence platform."""
    pass


@cli.command()
@click.option("-i", "--input", "input_path",
              default="cowrie/var/log/cowrie/cowrie.json",
              show_default=True,
              help="Path to cowrie.json log file.")
@click.option("-o", "--out", "out_dir",
              default="output",
              show_default=True,
              help="Output directory for CSVs and reports.")
@click.option("-c", "--contamination", type=float, default=0.05,
              show_default=True,
              help="IsolationForest contamination (0.0–0.5).")
@click.option("--geo/--no-geo", default=True,
              help="Enable/disable GeoIP enrichment (requires internet).")
@click.option("--report/--no-report", default=True,
              help="Generate Markdown + JSON report.")
def analyze(input_path, out_dir, contamination, geo, report):
    """Run the full Honeypot-AI analysis pipeline."""
    console.print(BANNER)

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    from honeypot_ai.ingestion.cowrie_parser import parse_cowrie_log
    from honeypot_ai.ml.anomaly_detector import detect_anomalies
    from honeypot_ai.ml.threat_scorer import score_sessions
    from honeypot_ai.intel.campaign_clusterer import cluster_campaigns

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console) as prog:

        t = prog.add_task("📂  Parsing Cowrie log…", total=None)
        try:
            parsed = parse_cowrie_log(input_path)
        except (FileNotFoundError, ValueError) as e:
            console.print(f"[bold red]✗ Error:[/bold red] {e}")
            sys.exit(1)
        prog.update(t, description="✅  Parsed log")

        t2 = prog.add_task("🤖  Running anomaly detection…", total=None)
        commands = detect_anomalies(parsed.commands, contamination=contamination)
        prog.update(t2, description="✅  Anomaly detection complete")

        t3 = prog.add_task("🏆  Scoring sessions…", total=None)
        sessions = score_sessions(parsed.sessions, commands)
        prog.update(t3, description="✅  Threat scoring complete")

        t4 = prog.add_task("🗺  Clustering campaigns…", total=None)
        sessions = cluster_campaigns(sessions, commands)
        prog.update(t4, description="✅  Campaign clustering complete")

        geo_data = {}
        if geo and not parsed.sessions.empty:
            t5 = prog.add_task("🌍  Enriching IPs with GeoIP…", total=None)
            from honeypot_ai.intel.geoip import enrich_ips
            unique_ips = sessions["src_ip"].dropna().unique().tolist()
            geo_data = enrich_ips(unique_ips)
            prog.update(t5, description="✅  GeoIP enrichment complete")

        t6 = prog.add_task("💾  Saving outputs…", total=None)
        sessions.to_csv(out / "sessions.csv", index=False)
        commands.to_csv(out / "commands_all.csv", index=False)
        commands[commands["anomaly"]].to_csv(out / "anomalies.csv", index=False)

        if report:
            from honeypot_ai.report.generator import to_markdown, to_json
            to_markdown(sessions, commands, geo_data,
                        out / "report.md", source=input_path)
            to_json(sessions, commands, out / "report.json")

        prog.update(t6, description="✅  Outputs saved")

    # ── Summary table ─────────────────────────────────────────────────────────
    console.print()
    tbl = Table(title="[bold]📊 Analysis Summary[/bold]", box=box.ROUNDED)
    tbl.add_column("Metric", style="cyan")
    tbl.add_column("Value", style="white bold")

    tbl.add_row("Total sessions", str(len(sessions)))
    tbl.add_row("Unique attacker IPs", str(sessions["src_ip"].nunique() if not sessions.empty else 0))
    tbl.add_row("Total commands", str(len(commands)))
    tbl.add_row("Anomalous commands", str(commands["anomaly"].sum() if not commands.empty and "anomaly" in commands.columns else 0))

    if not sessions.empty and "threat_level" in sessions.columns:
        for lvl in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = (sessions["threat_level"] == lvl).sum()
            color = {"CRITICAL": "red", "HIGH": "orange1", "MEDIUM": "yellow", "LOW": "green"}[lvl]
            tbl.add_row(f"[{color}]{lvl}[/{color}] sessions", f"[{color}]{count}[/{color}]")

    if geo_data:
        countries = {v["country"] for v in geo_data.values()}
        tbl.add_row("Countries of origin", str(len(countries)))

    console.print(tbl)
    console.print()
    console.print(Panel(
        f"[bold green]✓ All outputs saved to:[/bold green] [cyan]{out.resolve()}[/cyan]\n"
        f"  • sessions.csv  • commands_all.csv  • anomalies.csv\n"
        + ("  • report.md  • report.json" if report else ""),
        title="Done",
        border_style="green",
    ))
    console.print("\n[dim]Run [bold]honeypot-ai dashboard[/bold] to explore results visually.[/dim]")


@cli.command()
@click.option("-i", "--input", "input_path",
              default="cowrie/var/log/cowrie/cowrie.json",
              show_default=True,
              help="Cowrie log file for the dashboard to load.")
@click.option("--port", default=8501, show_default=True, help="Streamlit port.")
def dashboard(input_path, port):
    """Launch the interactive Streamlit dashboard."""
    console.print(BANNER)
    dashboard_path = Path(__file__).parent.parent / "dashboard" / "app.py"
    if not dashboard_path.exists():
        console.print("[red]Dashboard not found at:[/] " + str(dashboard_path))
        sys.exit(1)

    console.print(f"[bold cyan]🚀 Launching dashboard on http://localhost:{port}[/bold cyan]")
    os.environ["HONEYPOT_AI_LOG"] = str(input_path)
    subprocess.run([
        sys.executable, "-m", "streamlit", "run",
        str(dashboard_path),
        f"--server.port={port}",
        "--server.headless=true",
    ])


if __name__ == "__main__":
    cli()
