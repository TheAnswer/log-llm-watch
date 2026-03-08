#!/usr/bin/env python3
import json
import re
import sqlite3
import threading
import time
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests
import yaml
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

BASE_DIR = Path("/opt/dozzle-llm-watch")
CONFIG_PATH = BASE_DIR / "config.yaml"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def load_config() -> dict[str, Any]:
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


CONFIG = load_config()
DB_PATH = CONFIG["storage"]["db_path"]

app = FastAPI(title="Dozzle LLM Watch")


def init_db() -> None:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            processed INTEGER NOT NULL DEFAULT 0,
            source TEXT,
            host TEXT,
            container TEXT,
            stream TEXT,
            level TEXT,
            message TEXT NOT NULL,
            raw_json TEXT NOT NULL,
            fingerprint TEXT NOT NULL
        )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_processed_created ON events(processed, created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_fingerprint ON events(fingerprint)")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS daily_runs (
            run_date TEXT PRIMARY KEY,
            created_at TEXT NOT NULL
        )
        """)
        conn.commit()


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH)
    try:
        yield conn
    finally:
        conn.close()


def normalize_message(msg: str) -> str:
    msg = re.sub(r"\b\d{4}-\d{2}-\d{2}[T ][0-9:\.\+\-Z]+\b", "<ts>", msg)
    msg = re.sub(r"\b[0-9a-f]{8,}\b", "<hex>", msg, flags=re.IGNORECASE)
    msg = re.sub(r"\b\d+\b", "<num>", msg)
    msg = re.sub(r"\s+", " ", msg).strip()
    return msg[:500]


def fingerprint(container: str, message: str) -> str:
    return f"{container}::{normalize_message(message)}"


def find_first(d: Any, keys: list[str], default=None):
    if isinstance(d, dict):
        for k in keys:
            if k in d and d[k] not in (None, ""):
                return d[k]
        for v in d.values():
            found = find_first(v, keys, default=None)
            if found not in (None, ""):
                return found
    elif isinstance(d, list):
        for item in d:
            found = find_first(item, keys, default=None)
            if found not in (None, ""):
                return found
    return default


def extract_event(payload: Any) -> dict[str, str]:
    source = "dozzle-webhook"
    host = ""
    container = "unknown"
    stream = ""
    level = ""
    message = ""

    if not isinstance(payload, dict):
        return {
            "source": source,
            "host": host,
            "container": container,
            "stream": stream,
            "level": level,
            "message": json.dumps(payload, ensure_ascii=False),
        }

    # Dozzle formatted webhook payload
    # Example:
    # {
    #   "text": "prowlarr",
    #   "blocks": [
    #     {"type":"section","text":{"type":"mrkdwn","text":"*prowlarr*\nactual log..."}},
    #     {"type":"context","elements":[{"type":"mrkdwn","text":"Host: unraid | Image: linuxserver/prowlarr:latest"}]}
    #   ]
    # }

    container = str(payload.get("text") or "unknown").strip() or "unknown"

    blocks = payload.get("blocks", [])
    if isinstance(blocks, list):
        # Main message block
        if len(blocks) > 0 and isinstance(blocks[0], dict):
            text_obj = blocks[0].get("text", {})
            if isinstance(text_obj, dict):
                message = str(text_obj.get("text") or "").strip()

        # Context block: Host / Image
        if len(blocks) > 1 and isinstance(blocks[1], dict):
            elements = blocks[1].get("elements", [])
            if isinstance(elements, list) and elements:
                first_el = elements[0]
                if isinstance(first_el, dict):
                    context_text = str(first_el.get("text") or "")
                    # Example: "Host: unraid | Image: linuxserver/prowlarr:latest"
                    m = re.search(r"Host:\s*([^|]+)", context_text)
                    if m:
                        host = m.group(1).strip()

    if not message:
        message = json.dumps(payload, ensure_ascii=False)

    # Strip the leading "*container*\n" if present
    prefix_pattern = rf"^\*?{re.escape(container)}\*?\s*\n"
    message = re.sub(prefix_pattern, "", message, count=1, flags=re.IGNORECASE).strip()

    # Infer rough level from message contents
    lowered = message.lower()
    if any(x in lowered for x in ["panic", "fatal", "segfault", "out of memory", "no space left"]):
        level = "critical"
    elif any(x in lowered for x in ["error", "exception", "traceback", "badrequest", "warn", "warning"]):
        level = "error"

    return {
        "source": source,
        "host": host,
        "container": container,
        "stream": stream,
        "level": level,
        "message": message,
    }

def should_ignore(message: str) -> bool:
    for pattern in CONFIG["filters"]["ignore_message_regex"]:
        if re.search(pattern, message):
            return True
    return False


@app.on_event("startup")
def startup_event():
    init_db()
    t = threading.Thread(target=analysis_loop, daemon=True)
    t.start()


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.post("/dozzle")
async def dozzle_webhook(request: Request):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Expected JSON body")

    event = extract_event(payload)

    if should_ignore(event["message"]):
        return JSONResponse({"stored": False, "reason": "ignored"})

    fp = fingerprint(event["container"], event["message"])

    with db() as conn:
        conn.execute(
            """
            INSERT INTO events (created_at, processed, source, host, container, stream, level, message, raw_json, fingerprint)
            VALUES (?, 0, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                utcnow().isoformat(),
                event["source"],
                event["host"],
                event["container"],
                event["stream"],
                event["level"],
                event["message"],
                json.dumps(payload, ensure_ascii=False),
                fp,
            ),
        )
        conn.commit()

    return JSONResponse({"stored": True, "container": event["container"], "fingerprint": fp})


def fetch_unprocessed_events() -> list[sqlite3.Row]:
    cutoff = utcnow() - timedelta(hours=CONFIG["analysis"]["ignore_if_older_than_hours"])
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT * FROM events
            WHERE processed = 0
              AND created_at >= ?
            ORDER BY created_at ASC
            """,
            (cutoff.isoformat(),),
        ).fetchall()
    return rows


def group_events(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    grouped = defaultdict(lambda: {
        "count": 0,
        "container": "",
        "level": "",
        "stream": "",
        "first_seen": None,
        "last_seen": None,
        "examples": [],
        "ids": [],
        "fingerprint": "",
    })

    max_examples = CONFIG["analysis"]["max_examples_per_group"]

    for row in rows:
        key = row["fingerprint"]
        g = grouped[key]
        g["count"] += 1
        g["container"] = row["container"]
        g["level"] = row["level"]
        g["stream"] = row["stream"]
        g["fingerprint"] = row["fingerprint"]
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
            "You are reviewing homelab Docker log alerts forwarded by Dozzle. "
            "Classify only real operational issues. Be conservative. "
            "Ignore harmless noise. Return strict JSON only."
        ),
        "groups": groups,
    }
    return f"""
Analyze these grouped container log alerts.

Rules:
- Classify each group as: ignore, low, medium, or high.
- Prefer real operational issues: crashes, permission problems, DB failures, OOM, disk full, network failures, bad gateway, TLS/cert failures, repeated exceptions.
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


#def call_ollama(prompt: str) -> dict[str, Any]:
#    url = CONFIG["ollama"]["url"].rstrip("/") + "/api/generate"
#    body = {
#        "model": CONFIG["ollama"]["model"],
#        "prompt": prompt,
#        "stream": False,
#        "format": "json",
#        "options": {
#            "temperature": 0.1,
#        },
#    }
#    r = requests.post(url, json=body, timeout=CONFIG["ollama"]["timeout_seconds"])
#    r.raise_for_status()
#    data = r.json()
#    return json.loads(data["response"])

def call_ollama(prompt: str) -> dict[str, Any]:
    url = CONFIG["ollama"]["url"].rstrip("/") + "/api/generate"
    body = {
        "model": CONFIG["ollama"]["model"],
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.1,
        },
    }

    r = requests.post(url, json=body, timeout=CONFIG["ollama"]["timeout_seconds"])
    r.raise_for_status()
    data = r.json()

    print(f"[call_ollama] full response json: {data!r}", flush=True)

    raw_response = (data.get("response") or "").strip()
    raw_thinking = (data.get("thinking") or "").strip()

    candidate = raw_response or raw_thinking

    if not candidate:
        raise ValueError(f"Ollama returned empty response and empty thinking. Full payload: {data!r}")

    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        pass

    if candidate.startswith("```"):
        candidate = re.sub(r"^```[a-zA-Z0-9_-]*\n?", "", candidate)
        candidate = re.sub(r"\n?```$", "", candidate).strip()

    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        pass

    start = candidate.find("{")
    end = candidate.rfind("}")
    if start != -1 and end != -1 and end > start:
        return json.loads(candidate[start:end + 1])

    raise ValueError(f"Could not parse Ollama JSON response. Candidate: {candidate!r}")

def send_ntfy(message: str, priority: str = "default") -> None:
    url = CONFIG["notify"]["ntfy_url"]
    headers = {
        "Title": CONFIG["notify"]["title"],
        "Priority": priority,
        "Tags": "warning,robot_face",
    }
    r = requests.post(url, data=message.encode("utf-8"), headers=headers, timeout=30)
    r.raise_for_status()


def mark_processed(ids: list[int]) -> None:
    if not ids:
        return
    placeholders = ",".join("?" for _ in ids)
    with db() as conn:
        conn.execute(f"UPDATE events SET processed = 1 WHERE id IN ({placeholders})", ids)
        conn.commit()


def analyze_once() -> None:
    rows = fetch_unprocessed_events()
    if len(rows) < CONFIG["analysis"]["min_events_before_analysis"]:
        return

    groups = group_events(rows)
    prompt = build_prompt(groups)
    result = call_ollama(prompt)

    findings = [f for f in result.get("findings", []) if f.get("severity") in {"low", "medium", "high"}]
    all_ids = [row["id"] for row in rows]

    if findings:
        priority = "urgent" if any(f["severity"] == "high" for f in findings) else "default"
        lines = [result.get("operator_summary", "Log alerts detected."), ""]
        for f in findings[:10]:
            lines.append(f"[{f['severity'].upper()}] {f['container']}: {f['title']}")
            lines.append(f"  {f['summary']}")
            lines.append(f"  Action: {f['action']}")
            lines.append("")
        send_ntfy("\n".join(lines).strip(), priority=priority)

    mark_processed(all_ids)

def analysis_loop() -> None:
    interval = max(60, CONFIG["analysis"]["batch_window_minutes"] * 60)
    while True:
        try:
            analyze_once()
        except Exception as e:
            print(f"[analysis_loop] analyze error: {e}", flush=True)

        try:
            maybe_send_daily_report()
        except Exception as e:
            print(f"[analysis_loop] daily report error: {e}", flush=True)

        time.sleep(interval)

def today_local_date_str() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def daily_report_already_sent(run_date: str) -> bool:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT 1 FROM daily_runs WHERE run_date = ?",
            (run_date,),
        ).fetchone()
    return row is not None


def mark_daily_report_sent(run_date: str) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO daily_runs (run_date, created_at) VALUES (?, ?)",
            (run_date, utcnow().isoformat()),
        )
        conn.commit()

def fetch_events_for_lookback(hours: int) -> list[sqlite3.Row]:
    cutoff = utcnow() - timedelta(hours=hours)
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT *
            FROM events
            WHERE created_at >= ?
            ORDER BY created_at ASC
            """,
            (cutoff.isoformat(),),
        ).fetchall()
    return rows

def group_events_for_daily(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    grouped = defaultdict(lambda: {
        "count": 0,
        "container": "",
        "level": "",
        "stream": "",
        "first_seen": None,
        "last_seen": None,
        "examples": [],
        "fingerprint": "",
    })

    max_examples = CONFIG["analysis"]["max_examples_per_group"]

    for row in rows:
        key = row["fingerprint"]
        g = grouped[key]
        g["count"] += 1
        g["container"] = row["container"]
        g["level"] = row["level"]
        g["stream"] = row["stream"]
        g["fingerprint"] = row["fingerprint"]

        created_at = row["created_at"]
        if g["first_seen"] is None:
            g["first_seen"] = created_at
        g["last_seen"] = created_at

        if len(g["examples"]) < max_examples:
            g["examples"].append(row["message"])

    return sorted(grouped.values(), key=lambda x: x["count"], reverse=True)

def build_daily_report_prompt(groups: list[dict[str, Any]], lookback_hours: int) -> str:
    payload = {
        "instruction": (
            "You are summarizing the last 24 hours of homelab Docker alert events. "
            "Provide an operational summary for the owner. "
            "Be concise, accurate, and do not invent issues."
        ),
        "lookback_hours": lookback_hours,
        "groups": groups,
    }

    return f"""
Analyze these grouped homelab Docker alert events from the last {lookback_hours} hours.

Return ONLY valid JSON with this schema:

{{
  "overall_status": "healthy|warning|critical",
  "critical_issues": [
    {{
      "container": "string",
      "title": "string",
      "summary": "string",
      "action": "string"
    }}
  ],
  "warnings": [
    {{
      "container": "string",
      "title": "string",
      "summary": "string"
    }}
  ],
  "noise": [
    {{
      "container": "string",
      "title": "string"
    }}
  ],
  "operator_summary": "string"
}}

Input:
{json.dumps(payload, ensure_ascii=False, indent=2)}
""".strip()


def send_daily_report() -> None:
    cfg = CONFIG["daily_report"]
    lookback_hours = cfg["lookback_hours"]

    rows = fetch_events_for_lookback(lookback_hours)
    print(f"[daily_report] fetched {len(rows)} rows from last {lookback_hours}h", flush=True)

    if not rows:
        message = "Homelab Daily Health Report\n\nNo matching alert events were recorded in the last 24 hours.\n\nOverall Status: Healthy"
        send_ntfy(message, priority="default")
        print("[daily_report] sent empty healthy report", flush=True)
        return

    groups = group_events_for_daily(rows)
    prompt = build_daily_report_prompt(groups, lookback_hours)
    result = call_ollama(prompt)

    critical_issues = result.get("critical_issues", [])
    warnings = result.get("warnings", [])
    noise = result.get("noise", [])
    overall_status = result.get("overall_status", "warning")
    operator_summary = result.get("operator_summary", "Daily homelab summary generated.")

    lines = ["Homelab Daily Health Report", ""]
    lines.append(f"Overall Status: {overall_status.capitalize()}")
    lines.append("")
    lines.append(operator_summary)
    lines.append("")

    if critical_issues:
        lines.append("Critical Issues")
        for item in critical_issues[:10]:
            lines.append(f"- {item['container']}: {item['title']}")
            lines.append(f"  {item['summary']}")
            lines.append(f"  Action: {item['action']}")
        lines.append("")

    if warnings:
        lines.append("Warnings")
        for item in warnings[:10]:
            lines.append(f"- {item['container']}: {item['title']}")
            lines.append(f"  {item['summary']}")
        lines.append("")

    if noise:
        lines.append("Noise / Likely Harmless")
        for item in noise[:10]:
            lines.append(f"- {item['container']}: {item['title']}")
        lines.append("")

    priority = "urgent" if overall_status == "critical" else "default"
    send_ntfy("\n".join(lines).strip(), priority=priority)
    print("[daily_report] sent daily report", flush=True)


def maybe_send_daily_report() -> None:
    cfg = CONFIG.get("daily_report", {})
    if not cfg.get("enabled", False):
        return

    now = datetime.now()
    run_date = now.strftime("%Y-%m-%d")

    if daily_report_already_sent(run_date):
        return

    target_hour = int(cfg.get("hour", 9))
    target_minute = int(cfg.get("minute", 0))

    if now.hour > target_hour or (now.hour == target_hour and now.minute >= target_minute):
        send_daily_report()
        mark_daily_report_sent(run_date)


@app.post("/daily-report-now")
def daily_report_now():
    try:
        send_daily_report()
        return {"ok": True}
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})
