# VULNERA-MAP: Intelligent SBOM Vulnerability Analysis

**VULNERA-MAP** is a high-performance, intelligent security tool designed to analyze **Software Bills of Materials (SBOMs)**. It helps developers and security teams identifying vulnerabilities in their software supply chain with unprecedented speed and precision.

Unlike traditional scanners that simply match names to lists, VULNERA-MAP uses a **Neuro-Symbolic AI engine**—combining the speed of Machine Learning with the logic of expert security rules—to not only find risks but explain *why* they matter.

---

## 📖 Table of Contents
- [Why VULNERA-MAP?](#why-vulnera-map)
- [Key Features](#-key-features)
- [How It Works (The Pipeline)](#-how-it-works-the-pipeline)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
- [Usage Guide](#-usage-guide)
- [Technical Architecture](#-technical-architecture)

---

## Why VULNERA-MAP?
Modern software is built on thousands of third-party libraries. An **SBOM** is like a list of ingredients for your software. However, knowing the ingredients isn't enough; you need to know if any of them are "poisonous" (vulnerable).

VULNERA-MAP solves three key problems:
1.  **Speed**: It processes huge files instantly (milliseconds vs. minutes).
2.  **Context**: It understands *how* a library is used (dependencies of dependencies).
3.  **Explainability**: It doesn't just say "High Risk"; it tells you "High Risk because this is a networking library widely exposed to the internet."

---

## 🚀 Key Features

*   **⚡ Ultra-Fast Ingestion**: Uses streaming parsing to handle massive CycloneDX/SPDX JSON files in milliseconds.
*   **🧠 Neuro-Symbolic AI**: Merges **Machine Learning** (for pattern recognition) with **Reasoning Rules** (logic-based decision making) to reduce false positives.
*   **🕸️ Dependency Graph Intelligence**: Builds a visual graph of your software to calculate "Depth"—identifying if a vulnerability is deep in your core system or just on the surface.
*   **🛡️ Local Vulnerability Database**: Uses an optimized local SQLite database for instant CVE (Common Vulnerabilities and Exposures) lookups, ensuring privacy and speed without needing constant internet access.
*   **📊 Interactive Dashboard**: A professional-grade, real-time dashboard to visualize risks, critical paths, and analysis scores.

---

## ⚙️ How It Works (The Pipeline)

1.  **Upload**: You upload an SBOM file (JSON format).
2.  **Ingestion**: The system parses the file, extracting components (libraries) and their relationships.
3.  **Graph Construction**: A mathematical graph is built to understand which library depends on which.
4.  **Vulnerability Matching**: Components are checked against the local CVE database.
5.  **Risk Analysis**:
    *   **ML Model**: Predicts risk scores based on exploitability and impact.
    *   **Reasoning Engine**: Applies expert rules (e.g., "If this is a web framework, increase risk score").
6.  **Visualization**: Results are sent to the frontend dashboard for you to explore.

---

## 📂 Project Structure

Here is a breakdown of the files to help you navigate the codebase:

### `backend/` (The Brain)
*   **`main.py`**: The entry point. Runs the API server that connects everything.
*   **`controller.py`**: Manages the flow of data between modules.
*   **`ingestion.py`**: Handles file reading and parsing (fast!).
*   **`matcher.py`**: Finds vulnerabilities in the database.
*   **`graph.py`**: detailed dependency math (calculating depths).
*   **`ml.py`**: The Artificial Intelligence model for risk scoring.
*   **`reasoning.py`**: The Logic Engine for explaining risks.
*   **`vuln_db.py`**: Manages the local SQLite database of vulnerabilities.

### `frontend/` (The Face)
*   **`index.html`**: The main dashboard page.
*   **`script.js`**: Handles user interactions, charts, and data fetching.
*   **`styles.css`**: Defines the dark-mode, premium look and feel.

---

## 🏁 Getting Started

### Prerequisites
*   **Python 3.8+** installed.
*   **pip** (Python package manager).

### Installation Steps

1.  **Clone the Project** (if you haven't already):
    ```bash
    git clone https://github.com/yourusername/vulnera-map.git
    cd vulnera-map
    ```

2.  **Set Up a Virtual Environment** (Recommended):
    ```bash
    python -m venv .venv
    # Windows:
    .venv\Scripts\activate
    # Mac/Linux:
    source .venv/bin/activate
    ```

3.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

4.  **Initialize the Database**:
    This downloads/prepares the local vulnerability data.
    ```bash
    python backend/vuln_db.py
    ```

---

## 🖥️ Usage Guide

1.  **Start the Backend Server**:
    Run the following command in your terminal:
    ```bash
    uvicorn backend.main:app --reload
    ```
    *You should see a message saying the server is running at `http://127.0.0.1:8000`.*

2.  **Open the Dashboard**:
    Open your web browser and go to:
    `http://localhost:8000` (or the URL shown in your terminal).

3.  **Analyze an SBOM**:
    *   Click the **"Upload SBOM"** button.
    *   Select a valid `cyclonedx.json` or `spdx.json` file.
    *   Watch the dashboard light up with insights!

---

## 🛠️ Technical Architecture

*   **Backend**: Python (FastAPI) for high-performance Async I/O.
*   **Frontend**: Vanilla JavaScript + Chart.js (No heavy frameworks needed for this speed).
*   **Database**: SQLite (ACID compliant, zero-config).
*   **AI/ML**: Scikit-Learn (Risk Model) + NetworkX (Graph Theory).

---

## ❓ Troubleshooting

**Q: The server says "Address already in use".**
A: Another program is using port 8000. Try stopping other python processes or change the port in `main.py`.

**Q: My SBOM isn't loading.**
A: Ensure your SBOM is in valid JSON format (CycloneDX 1.4+ is recommended).
