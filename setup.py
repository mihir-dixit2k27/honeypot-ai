from setuptools import setup, find_packages

setup(
    name="honeypot-ai",
    version="1.0.0",
    author="Mihir Dixit",
    description="Cowrie SSH Honeypot Threat Intelligence Platform",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[
        "pandas>=2.0",
        "scikit-learn>=1.4",
        "matplotlib>=3.7",
        "scipy>=1.12",
        "numpy>=1.26",
        "joblib>=1.3",
        "streamlit>=1.35",
        "plotly>=5.20",
        "click>=8.1",
        "rich>=13.0",
        "requests>=2.31",
        "python-dotenv>=1.0",
        "tabulate>=0.9",
    ],
    entry_points={
        "console_scripts": [
            "honeypot-ai=honeypot_ai.cli:cli",
        ],
    },
)
