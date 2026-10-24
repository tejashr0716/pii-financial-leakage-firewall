# Setup & Operations Guide: PII Financial Leakage Firewall

## Prerequisites
- Python 3.12+ (tested on Python 3.14)
- Internet access to monitor the GitHub Public Events stream (`https://api.github.com/events`)

## Installation
```bash
git clone https://github.com/tejashr0716/pii-financial-leakage-firewall.git
cd pii-financial-leakage-firewall

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Configuration (.env)
```bash
cp .env.example .env
```

Available configuration flags:
- `GITHUB_EVENTS_API_URL`: Live public stream endpoint
- `DATABASE_URL`: SQLite connection URI
- `DB_PATH`: Local database path (`data/firewall.db`)
- `DEFAULT_MASK_MODE`: Default redaction style (`PARTIAL_MASK` or `FULL_MASK`)
- `REQUEST_TIMEOUT_SECONDS`: Network timeout for streaming monitor

## Running the API Gateway
```bash
uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload
```

## Running Automated Tests
```bash
pytest -v --junitxml=artifacts/test-results.xml
```

## Running Empirical Benchmark
```bash
python benchmarks/benchmark_dlp_inspection.py
```
Outputs empirical inspection latency and throughput metrics to `artifacts/benchmark-results.json`.
