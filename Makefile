.PHONY: install dev test lint dashboard analyze clean

# Install all dependencies
install:
	pip install -r requirements.txt

# Run test suite
test:
	pytest tests/ -v --tb=short

# Run the CLI analysis against the sample log
analyze:
	python -m honeypot_ai.cli analyze \
		-i cowrie/var/log/cowrie/cowrie.json \
		-o output

# Launch the Streamlit dashboard
dashboard:
	streamlit run dashboard/app.py --server.port=8501

# Lint
lint:
	python -m py_compile honeypot_ai/ingestion/cowrie_parser.py
	python -m py_compile honeypot_ai/ml/anomaly_detector.py
	python -m py_compile honeypot_ai/ml/threat_scorer.py
	python -m py_compile honeypot_ai/intel/geoip.py
	python -m py_compile honeypot_ai/intel/mitre_mapper.py
	python -m py_compile honeypot_ai/intel/campaign_clusterer.py
	python -m py_compile honeypot_ai/cli.py
	python -m py_compile dashboard/app.py
	@echo "All files compile OK"

# Docker
docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

# Clean outputs
clean:
	rm -rf output/*.csv output/*.png output/*.json output/*.md __pycache__ .pytest_cache
