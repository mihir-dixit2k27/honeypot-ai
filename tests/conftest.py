"""
conftest.py — add the project root to sys.path so pytest can import honeypot_ai
without needing a pip install -e . step.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
