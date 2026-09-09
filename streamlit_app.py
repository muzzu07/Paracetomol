"""
Streamlit frontend for the Security Scanner.

This is a thin UI client that talks to the Flask backend API
(run.py, default http://127.0.0.1:5000). Start the Flask API first:

    python run.py

Then in another terminal:

    streamlit run streamlit_app.py
"""

import os

import requests
import streamlit as st

API_BASE_URL = os.getenv("SCANNER_API_URL", "http://127.0.0.1:5000")

st.set_page_config(page_title="Security Scanner", page_icon="🛡️", layout="wide")
st.title("🛡️ Static Code Vulnerability & Secret Scanner")
st.caption("Semgrep + Gitleaks scanning, with DeepSeek-powered AI remediation.")

tab_upload, tab_git, tab_reports = st.tabs(
    ["📦 Upload ZIP", "🔗 Scan Git Repo", "📊 Past Reports"]
)


def render_report(report: dict):
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total findings", report.get("total_findings", 0))
    col2.metric("Semgrep", report.get("semgrep_findings", 0))
    col3.metric("Gitleaks", report.get("gitleaks_findings", 0))
    col4.metric("Duration (s)", report.get("duration_seconds", 0))

    sev = report.get("severity_counts", {})
    st.write(
        f"🔴 Critical: {sev.get('critical', 0)}  |  "
        f"🟠 High: {sev.get('high', 0)}  |  "
        f"🟡 Medium: {sev.get('medium', 0)}  |  "
        f"🟢 Low: {sev.get('low', 0)}"
    )

    if report.get("errors"):
        for err in report["errors"]:
            st.warning(err)

    for finding in report.get("findings", []):
        label = finding.get("rule_id") or finding.get("description") or "Finding"
        with st.expander(f"[{finding.get('tool')}] {label} — {finding.get('path')}"):
            st.json(finding)


with tab_upload:
    st.subheader("Upload a project as a .zip file")
    use_ai_upload = st.checkbox("Use DeepSeek AI analysis", value=True, key="ai_upload")
    uploaded_file = st.file_uploader("Choose a .zip file", type=["zip"])

    if st.button("Scan uploaded project", disabled=uploaded_file is None):
        with st.spinner("Scanning... this can take a minute."):
            files = {"file": (uploaded_file.name, uploaded_file.getvalue())}
            try:
                resp = requests.post(
                    f"{API_BASE_URL}/api/scan/upload",
                    files=files,
                    params={"use_ai": str(use_ai_upload).lower()},
                    timeout=600,
                )
                if resp.ok:
                    st.success("Scan complete.")
                    render_report(resp.json())
                else:
                    st.error(f"Scan failed: {resp.json().get('error', resp.text)}")
            except requests.RequestException as exc:
                st.error(f"Could not reach the API at {API_BASE_URL}: {exc}")

with tab_git:
    st.subheader("Scan a public Git repository")
    use_ai_git = st.checkbox("Use DeepSeek AI analysis", value=True, key="ai_git")
    repo_url = st.text_input("Repository URL", placeholder="https://github.com/org/repo")
    branch = st.text_input("Branch (optional)", placeholder="main")

    if st.button("Scan repository", disabled=not repo_url):
        with st.spinner("Cloning and scanning... this can take a minute."):
            try:
                resp = requests.post(
                    f"{API_BASE_URL}/api/scan/git",
                    json={
                        "repo_url": repo_url,
                        "branch": branch or None,
                        "use_ai": use_ai_git,
                    },
                    timeout=600,
                )
                if resp.ok:
                    st.success("Scan complete.")
                    render_report(resp.json())
                else:
                    st.error(f"Scan failed: {resp.json().get('error', resp.text)}")
            except requests.RequestException as exc:
                st.error(f"Could not reach the API at {API_BASE_URL}: {exc}")

with tab_reports:
    st.subheader("Past scan reports")
    if st.button("Refresh list"):
        st.rerun()
    try:
        resp = requests.get(f"{API_BASE_URL}/api/reports", timeout=30)
        if resp.ok:
            reports = resp.json()
            if not reports:
                st.info("No reports yet. Run a scan first.")
            for r in reports:
                st.write(
                    f"**{r['scan_id']}** — {r['total_findings']} findings "
                    f"(critical: {r['severity_counts'].get('critical', 0)}, "
                    f"high: {r['severity_counts'].get('high', 0)})"
                )
        else:
            st.error("Could not load reports.")
    except requests.RequestException as exc:
        st.error(f"Could not reach the API at {API_BASE_URL}: {exc}")
