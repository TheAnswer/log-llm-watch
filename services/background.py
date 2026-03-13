"""Background analysis loop and related helpers."""
import json
import sqlite3
import time
from collections import defaultdict
from datetime import timedelta
from typing import Any

import requests

from core import config
from core.config import utcnow
from core.database import db
from services.housekeeping import maybe_run_cleanup
from services.incidents import analyze_missing_incidents, close_stale_incidents
from services.notifications import send_ntfy
from services.ollama import call_ollama
from services.reports import maybe_send_daily_report, maybe_send_weekly_report
from services.suppression import auto_suppress_ignored, flush_suppress_hits


def fetch_unprocessed_events() -> list[sqlite3.Row]:
    cutoff = utcnow() - timedelta(hours=config.CONFIG["analysis"]["ignore_if_older_than_hours"])
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM events WHERE processed = 0 AND created_at >= ? ORDER BY created_at ASC",
            (cutoff.isoformat(),),
        ).fetchall()
    return rows


def group_events(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    grouped = defaultdict(lambda: {
        "count": 0, "source": "", "host": "", "container": "", "level": "",
        "stream": "", "first_seen": None, "last_seen": None, "examples": [],
        "ids": [], "fingerprint": "", "message_template": "", "event_class": "",
    })
    max_examples = config.CONFIG["analysis"]["max_examples_per_group"]
    for row in rows:
        key = row["fingerprint"]
        g = grouped[key]
        g["count"] += 1
        g["source"] = row["source"]; g["host"] = row["host"]; g["container"] = row["container"]
        g["level"] = row["level"]; g["stream"] = row["stream"]; g["fingerprint"] = row["fingerprint"]
        if not g["message_template"] and row["message_template"]:
            g["message_template"] = row["message_template"]
        if not g["event_class"] and row["event_class"]:
            g["event_class"] = row["event_class"]
        g["ids"].append(row["id"])
        created_at = row["created_at"]
        if g["first_seen"] is None:
            g["first_seen"] = created_at
        g["last_seen"] = created_at
        if len(g["examples"]) < max_examples:
            g["examples"].append(row["message"])
    return sorted(grouped.values(), key=lambda x: x["count"], reverse=True)


def build_prompt(groups: list[dict[str, Any]]) -> str:
    payload = {
        "instruction": (
            "You are reviewing homelab operational alerts from multiple sources, "
            "including Docker container logs and Windows Event Logs. "
            "Classify only real operational issues. Be conservative. "
            "Ignore harmless noise. Return strict JSON only."
        ),
        "groups": groups,
    }
    return f"""
Analyze these grouped infrastructure alerts.

Rules:
- Classify each group as: ignore, low, medium, or high.
- Sources may include Docker logs and Windows Event Logs.
- Prefer real operational issues: crashes, permission problems, DB failures, OOM, disk full, network failures, bad gateway, TLS/cert failures, repeated exceptions, failed logons, unexpecte
- Ignore likely noise.
- Do not invent problems not supported by the data.
- Output JSON only with this schema:

{{
  "overall_status": "ok|warning|critical",
  "findings": [
    {{
      "fingerprint": "string",
      "container": "string",
      "severity": "ignore|low|medium|high",
      "title": "string",
      "summary": "string",
      "action": "string"
    }}
  ],
  "operator_summary": "string"
}}

Input:
{json.dumps(payload, ensure_ascii=False, indent=2)}
""".strip()


def mark_processed(ids: list[int]) -> None:
    if not ids:
        return
    placeholders = ",".join("?" for _ in ids)
    with db() as conn:
        conn.execute(f"UPDATE events SET processed = 1 WHERE id IN ({placeholders})", ids)
        conn.commit()


def store_analysis_run(
    prompt: str,
    raw_response: str,
    parsed_result: dict[str, Any] | None,
    event_count: int,
) -> None:
    overall_status = None
    finding_count = 0
    parsed_json = None
    if parsed_result is not None:
        overall_status = parsed_result.get("overall_status")
        findings = parsed_result.get("findings", [])
        if isinstance(findings, list):
            finding_count = len(findings)
        parsed_json = json.dumps(parsed_result, ensure_ascii=False)
    with db() as conn:
        conn.execute(
            """
            INSERT INTO analysis_runs (created_at, prompt, raw_response, parsed_json,
                                       overall_status, finding_count, event_count)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (utcnow().isoformat(), prompt, raw_response, parsed_json,
             overall_status, finding_count, event_count),
        )
        conn.commit()


def analyze_once() -> None:
    rows = fetch_unprocessed_events()
    if len(rows) < config.CONFIG["analysis"]["min_events_before_analysis"]:
        return

    all_ids = [row["id"] for row in rows]
    groups = group_events(rows)
    groups_by_fp = {g["fingerprint"]: g for g in groups}
    prompt = build_prompt(groups)

    try:
        result, raw_response = call_ollama(prompt)
        store_analysis_run(prompt=prompt, raw_response=raw_response,
                           parsed_result=result, event_count=len(all_ids))
    except Exception as e:
        store_analysis_run(prompt=prompt, raw_response=f"ERROR: {e}",
                           parsed_result=None, event_count=len(all_ids))
        raise

    all_findings = result.get("findings", [])
    findings = [f for f in all_findings if f.get("severity") in {"low", "medium", "high"}]

    ignored_fps = [f["fingerprint"] for f in all_findings
                   if f.get("severity") == "ignore" and f.get("fingerprint")]
    auto_suppress_ignored(groups_by_fp, ignored_fps)

    if findings:
        priority = "urgent" if any(f["severity"] == "high" for f in findings) else "default"
        lines = [result.get("operator_summary", "Infrastructure alerts detected."), ""]
        for f in findings[:10]:
            lines.append(f"[{f['severity'].upper()}] {f['container']}: {f['title']}")
            lines.append(f"  {f['summary']}")
            lines.append(f"  Action: {f['action']}")
            lines.append("")
        send_ntfy("\n".join(lines).strip(), priority=priority)

    mark_processed(all_ids)


def _run_backfill() -> None:
    from services.ingestion import backfill_existing_events
    try:
        while True:
            n = backfill_existing_events(limit=500)
            if n == 0:
                break
            print(f"[startup] backfilled {n} historical events", flush=True)
    except Exception as e:
        print(f"[startup] backfill error: {e}", flush=True)


def _check_ollama_health() -> None:
    ollama_url = config.CONFIG["ollama"]["url"]
    try:
        resp = requests.get(f"{ollama_url}/api/tags", timeout=5)
        if resp.status_code == 200:
            print(f"[startup] Ollama OK at {ollama_url}", flush=True)
        else:
            print(f"[startup] WARNING: Ollama at {ollama_url} returned HTTP {resp.status_code}", flush=True)
    except Exception as e:
        print(f"[startup] WARNING: Ollama unreachable at {ollama_url}: {e}", flush=True)


def analysis_loop() -> None:
    interval = max(60, config.CONFIG["analysis"]["batch_window_minutes"] * 60)
    while True:
        try:
            close_stale_incidents()
        except Exception as e:
            print(f"[analysis_loop] close incidents error: {e}", flush=True)

        try:
            analyze_once()
        except Exception as e:
            print(f"[analysis_loop] analyze error: {e}", flush=True)

        try:
            result = analyze_missing_incidents(limit=2, include_closed=False, skip_info_unknown=True)
            if result["processed_count"] or result["error_count"]:
                print(f"[analysis_loop] analyze_missing_incidents result={result}", flush=True)
        except Exception as e:
            print(f"[analysis_loop] analyze missing incidents error: {e}", flush=True)

        try:
            maybe_send_daily_report()
        except Exception as e:
            print(f"[analysis_loop] daily report error: {e}", flush=True)

        try:
            maybe_send_weekly_report()
        except Exception as e:
            print(f"[analysis_loop] weekly report error: {e}", flush=True)

        try:
            maybe_run_cleanup()
        except Exception as e:
            print(f"[analysis_loop] cleanup error: {e}", flush=True)

        try:
            flush_suppress_hits()
        except Exception as e:
            print(f"[analysis_loop] flush suppress hits error: {e}", flush=True)

        time.sleep(interval)
