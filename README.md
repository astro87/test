# VULNERA-MAP

VULNERA-MAP is an advanced SBOM-based vulnerability detection and risk intelligence system designed for high speed and accuracy. It features a neuro-symbolic reasoning engine that combines machine learning with expert rules to provide explainable risk assessments.

## Features

- **Ultra-fast Ingestion**: Streaming parsing of CycloneDX/SPDX JSON files (< 10ms for 1k components).
- **Dependency Intelligence**: Builds full dependency graphs to calculate depth and critical paths.
- **Local Vulnerability Database**: Low-latency CVE matching using an optimized local SQLite database.
- **ML Risk Classification**: Lightweight ML model to score risk based on CVSS, depth, and exploit maturity.
- **Neuro-Symbolic Reasoning**: Expert rules engine to provide human-readable explanations for risk decisions.
- **Interactive Dashboard**: Real-time visualization of risk distribution and system performance.

## Architecture

The system is modular and decoupled:
- **Backend**: Python (FastAPI)
- **Frontend**: HTML/JS (Chart.js)
- **Database**: SQLite
- **ML/Graph**: Scikit-Learn, NetworkX

## Installation

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Initialize the database (automatically done on first run or manually):
   ```bash
   python backend/vuln_db.py
   ```

## Usage

1. Start the API server:
   ```bash
   uvicorn backend.main:app --reload
   ```

2. Open the dashboard at `http://localhost:8000`.

3. Upload a CycloneDX JSON SBOM file to analyze vulnerabilities.

## Performance

Benchmark results on 1000 components (Synthetic Data):
- **Parsing**: ~9 ms
- **Graph Build**: ~6 ms
- **CVE Matching**: ~170 ms
- **ML Inference**: ~1.5 ms
- **Reasoning**: ~1 ms
- **Total**: ~187 ms (Target < 1.2s)

## Testing

Run unit tests:
```bash
python -m unittest discover tests
```

Run benchmark:
```bash
python benchmark.py
```
