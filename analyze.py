#!/usr/bin/env python3
"""
analyze.py — backward-compatible entrypoint.

This script is kept for compatibility. For full functionality use:

    python -m honeypot_ai.cli analyze --help
    streamlit run dashboard/app.py
"""

import sys
import subprocess

if __name__ == "__main__":
    # Forward all arguments to the new CLI
    cmd = [sys.executable, "-m", "honeypot_ai.cli", "analyze"] + sys.argv[1:]
    sys.exit(subprocess.call(cmd))
