# Security Scanner

Static Code Vulnerability & Secret Scanner with AI Analysis.

Scans a project (uploaded as a `.zip` or cloned from a public Git URL) with
**Semgrep** (SAST / OWASP Top Ten) and **Gitleaks** (hardcoded secrets),
then optionally enriches each finding with **DeepSeek AI** for a plain-English
explanation, severity assessment, and a suggested fix — exported as a `.patch`
file. A **GitHub Actions** workflow gates pull requests on scan results.

## Architecture

```
Streamlit UI  ->  Flask API  ->  Semgrep + Gitleaks  ->  Results Parser
                                                              |
                                                              v
                                                   DeepSeek AI Analysis
                                                              |
                                                              v
                                                   Patch Generator (.patch)
```

## 1. Prerequisites

- Python 3.11+
- Git
- [Semgrep](https://semgrep.dev/docs/getting-started/) (installed via `requirements.txt`)
- [Gitleaks](https://github.com/gitleaks/gitleaks#installing) (install separately — it's a Go binary, not a pip package)
- A DeepSeek API key ([platform.deepseek.com](https://platform.deepseek.com))

## 2. Setup

```bash
# Create & activate a virtual environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\Activate.ps1

# Install Python dependencies
pip install -r requirements.txt

# Configure secrets
cp .env.example .env
# then edit .env and set DEEPSEEK_API_KEY

# Verify the scanners are installed
semgrep --version
gitleaks version
```

## 3. Run it

Start the Flask API (terminal 1):

```bash
python run.py
```

Start the Streamlit UI (terminal 2):

```bash
streamlit run streamlit_app.py
```

Then open the Streamlit URL it prints (usually `http://localhost:8501`).

## 4. API reference (Flask backend)

| Method | Endpoint             | Description                              |
|--------|-----------------------|-------------------------------------------|
| GET    | `/api/health`          | Liveness check                            |
| POST   | `/api/scan/upload`     | multipart `file` (.zip) → runs full scan  |
| POST   | `/api/scan/git`        | JSON `{"repo_url": "...", "branch": "..."}` |
| GET    | `/api/reports`         | List past scan reports                    |
| GET    | `/api/reports/<id>`    | Fetch one full report                     |

Reports are also saved to `reports/report_<scan_id>.json`.

## 5. Project layout

```
security-scanner/
├── app/
│   ├── config.py            # env-driven configuration
│   ├── main.py               # Flask app factory
│   ├── api/routes.py         # Flask API endpoints
│   ├── scanner/
│   │   ├── semgrep_runner.py
│   │   ├── gitleaks_runner.py
│   │   └── orchestrator.py   # runs both scanners + AI + patches
│   ├── ai/deepseek_client.py # DeepSeek API integration
│   ├── ingestion/
│   │   ├── zip_handler.py    # safe ZIP extraction (zip-slip guarded)
│   │   └── git_handler.py    # public repo cloning
│   └── remediation/
│       └── patch_generator.py # unified-diff .patch generation
├── streamlit_app.py          # UI client
├── run.py                    # Flask entrypoint
├── uploads/ temp/ patches/ reports/
├── .github/workflows/security-scan.yml
├── .env.example
└── requirements.txt
```

## 6. CI/CD

`.github/workflows/security-scan.yml` runs Semgrep and Gitleaks on every
push/PR to `main` and fails the build if either tool finds issues. Adjust
`--config` / `--exit-code` flags as your team's policy evolves.

## 7. Notes

- `.env` is git-ignored — never commit real API keys.
- Uploaded projects are extracted into `temp/scan_<id>/` and deleted after
  the report is generated (see `cleanup=True` in `orchestrator.run_full_scan`).
- Secrets in reports are masked (`secret_masked`) rather than stored in full.
