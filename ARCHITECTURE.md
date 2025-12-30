# System Architecture

VULNERA-MAP follows a layered architecture to ensure modularity, scalability, and performance.

## Layers

### 1. Ingestion Layer (`backend/ingestion.py`)
- **Responsibility**: Parse incoming SBOM files.
- **Technology**: `ijson` for streaming JSON parsing.
- **Optimization**: Reads file incrementally to avoid memory spikes; extracts only relevant fields.

### 2. Dependency Intelligence Layer (`backend/graph.py`)
- **Responsibility**: Model component relationships.
- **Technology**: `NetworkX`.
- **Logic**: Builds a directed graph to calculate dependency depth and identify critical path components (centrality).

### 3. Vulnerability Intelligence Layer (`backend/vuln_db.py`, `backend/matcher.py`)
- **Responsibility**: Identify known vulnerabilities.
- **Technology**: SQLite with indexed columns.
- **Logic**: Matches components against local DB by name and version range. Supports bloom filters (placeholder) for rapid elimination.

### 4. ML Risk Classification Layer (`backend/ml.py`)
- **Responsibility**: Predict risk score.
- **Technology**: `Scikit-Learn` (or lightweight Numpy implementation).
- **Features**: Base CVSS, Dependency Depth, Exploit Maturity, Transitive Count.
- **Output**: 0-100 Risk Score.

### 5. Neuro-Symbolic Reasoning Layer (`backend/reasoning.py`)
- **Responsibility**: Refine scores and explain decisions.
- **Logic**: Rule-based system that amplifies risk based on context (e.g., "Critical vulnerability near root").
- **Output**: Final Score + Explanation Strings.

### 6. API & Orchestration Layer (`backend/main.py`)
- **Responsibility**: Expose functionality via REST.
- **Technology**: `FastAPI`.
- **Concurrency**: Uses `asyncio` for non-blocking file processing.

### 7. Visualization Layer (`frontend/`)
- **Responsibility**: User Interface.
- **Technology**: HTML5, CSS3, Vanilla JS, Chart.js.
- **Features**: Drag-and-drop upload, real-time status polling, interactive charts.

## Data Flow

1. **Upload**: User uploads SBOM -> `POST /api/upload`.
2. **Ingest**: File streamed -> List of Components + Dependencies.
3. **Graph**: Components -> Dependency Graph -> Depths/Centrality.
4. **Match**: Components -> CVE Matcher -> Vulnerabilities.
5. **Score**: Matched Components -> ML Model -> Raw Risk Score.
6. **Reason**: Raw Score + Graph Context -> Reasoning Engine -> Final Score + Explanations.
7. **Response**: JSON result returned to Frontend -> Rendered.
