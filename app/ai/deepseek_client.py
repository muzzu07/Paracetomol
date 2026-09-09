"""
Thin client around the DeepSeek chat-completions API used to turn raw
Semgrep/Gitleaks findings into plain-English explanations and suggested
fixes / patches.
"""

import json
from typing import Any

import requests

from app.config import Config

_SYSTEM_PROMPT = (
    "You are a senior application security engineer. You are given a single "
    "static-analysis finding (from Semgrep or Gitleaks) along with the "
    "surrounding code. Respond ONLY with a JSON object with these keys: "
    '"explanation" (plain-English, 2-3 sentences on why this is a risk), '
    '"severity_assessment" (one of: critical, high, medium, low), '
    '"fixed_code" (the corrected code snippet, same language, minimal diff), '
    '"remediation_notes" (short actionable steps). '
    "No markdown fences, no preamble, JSON only."
)


class DeepSeekError(Exception):
    pass


def _call_deepseek(user_prompt: str) -> str:
    if not Config.DEEPSEEK_API_KEY:
        raise DeepSeekError(
            "DEEPSEEK_API_KEY is not set. Add it to your .env file."
        )

    headers = {
        "Authorization": f"Bearer {Config.DEEPSEEK_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": Config.DEEPSEEK_MODEL,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.2,
        "stream": False,
    }

    try:
        resp = requests.post(
            Config.DEEPSEEK_API_URL, headers=headers, json=payload, timeout=60
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise DeepSeekError(f"DeepSeek API request failed: {exc}") from exc

    data = resp.json()
    try:
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError) as exc:
        raise DeepSeekError(f"Unexpected DeepSeek response shape: {data}") from exc


def analyze_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """
    Send one normalized finding (from semgrep_runner or gitleaks_runner) to
    DeepSeek and return a structured analysis dict. Falls back to a safe
    default if the API is unavailable or returns malformed content.
    """
    prompt = (
        f"Tool: {finding.get('tool')}\n"
        f"Rule/ID: {finding.get('rule_id')}\n"
        f"Message: {finding.get('message') or finding.get('description')}\n"
        f"File: {finding.get('path')}\n"
        f"Lines: {finding.get('start_line')}-{finding.get('end_line')}\n"
        f"Code:\n{finding.get('code_snippet') or finding.get('match') or ''}\n"
    )

    raw_content = _call_deepseek(prompt)
    cleaned = raw_content.strip().removeprefix("```json").removesuffix("```").strip()

    try:
        analysis = json.loads(cleaned)
    except json.JSONDecodeError:
        analysis = {
            "explanation": raw_content,
            "severity_assessment": "unknown",
            "fixed_code": "",
            "remediation_notes": "Could not parse structured response.",
        }

    return analysis
