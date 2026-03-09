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

app = FastAPI(title="Homelab LLM Watch")


def init_db() -> None:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
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
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_processed_created ON events(processed, created_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_fingerprint ON events(fingerprint)"
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS daily_runs (
                run_date TEXT PRIMARY KEY,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS weekly_runs (
                run_key TEXT PRIMARY KEY,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS housekeeping_runs (
                run_key TEXT PRIMARY KEY,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS analysis_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                prompt TEXT NOT NULL,
                raw_response TEXT NOT NULL,
                parsed_json TEXT,
                overall_status TEXT,
                finding_count INTEGER NOT NULL DEFAULT 0,
                event_count INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_analysis_runs_created_at ON analysis_runs(created_at)"
        )
        conn.commit()


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH)
    try:
        yield conn
    finally:
        conn.close()


def current_system_time_str() -> str:
    return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def normalize_message(msg: str) -> str:
    msg = re.sub(r"\b\d{4}-\d{2}-\d{2}[T ][0-9:\.\+\-Z]+\b", "<ts>", msg)
    msg = re.sub(r"\b[0-9a-f]{8,}\b", "<hex>", msg, flags=re.IGNORECASE)
    msg = re.sub(r"\b\d+\b", "<num>", msg)
    msg = re.sub(r"\s+", " ", msg).strip()
    return msg[:500]


def fingerprint_for_event(event: dict[str, str]) -> str:
    source = event.get("source", "")
    host = event.get("host", "")
    container = event.get("container", "")
    stream = event.get("stream", "")
    message = event.get("message", "")
    return f"{source}::{host}::{container}::{stream}::{normalize_message(message)}"


def should_ignore(message: str) -> bool:
    for pattern in CONFIG["filters"]["ignore_message_regex"]:
        if re.search(pattern, message):
            return True
    return False


def extract_dozzle_event(payload: Any) -> dict[str, str]:
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

    container = str(payload.get("text") or "unknown").strip() or "unknown"

    blocks = payload.get("blocks", [])
    if isinstance(blocks, list):
        if len(blocks) > 0 and isinstance(blocks[0], dict):
            text_obj = blocks[0].get("text", {})
            if isinstance(text_obj, dict):
                message = str(text_obj.get("text") or "").strip()

        if len(blocks) > 1 and isinstance(blocks[1], dict):
            elements = blocks[1].get("elements", [])
            if isinstance(elements, list) and elements:
                first_el = elements[0]
                if isinstance(first_el, dict):
                    context_text = str(first_el.get("text") or "")
                    m = re.search(r"Host:\s*([^|]+)", context_text)
                    if m:
                        host = m.group(1).strip()

    if not message:
        message = json.dumps(payload, ensure_ascii=False)

    prefix_pattern = rf"^\*?{re.escape(container)}\*?\s*\n"
    message = re.sub(prefix_pattern, "", message, count=1, flags=re.IGNORECASE).strip()

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


def normalize_windows_level(level: Any, level_name: str | None = None) -> str:
    if level_name:
        name = str(level_name).strip().lower()
        if name in {"critical", "crit"}:
            return "critical"
        if name in {"error", "err"}:
            return "error"
        if name in {"warning", "warn"}:
            return "warning"
        if name in {"info", "information"}:
            return "info"

    try:
        lvl = int(level)
    except (TypeError, ValueError):
        return ""

    if lvl == 1:
        return "critical"
    if lvl == 2:
        return "error"
    if lvl == 3:
        return "warning"
    if lvl == 4:
        return "info"
    return ""


def extract_windows_event(payload: Any) -> dict[str, str]:
    source = "windows-event"
    host = ""
    container = "Windows"
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

    host = str(
        payload.get("Hostname")
        or payload.get("Computer")
        or payload.get("host")
        or ""
    ).strip().lower()

    channel = str(
        payload.get("Channel")
        or payload.get("channel")
        or payload.get("EventChannel")
        or "Windows"
    ).strip()

    provider = str(
        payload.get("ProviderName")
        or payload.get("SourceName")
        or payload.get("Provider")
        or payload.get("provider")
        or ""
    ).strip()

    rendered_message = (
        payload.get("Message")
        or payload.get("message")
        or payload.get("EventData")
        or payload.get("RenderedMessage")
        or ""
    )

    if isinstance(rendered_message, (dict, list)):
        message = json.dumps(rendered_message, ensure_ascii=False)
    else:
        message = str(rendered_message).strip()

    event_id = payload.get("EventID") or payload.get("EventId") or payload.get("event_id")
    level_name = payload.get("LevelName") or payload.get("level_name")

    level = normalize_windows_level(
        payload.get("SeverityValue")
        or payload.get("LevelValue")
        or payload.get("Level"),
        level_name,
    )

    # Override for known Security semantics
    try:
        event_id_int = int(event_id)
    except (TypeError, ValueError):
        event_id_int = None

    if channel.lower() == "security":
        if event_id_int == 4625:
            level = "warning"
        elif event_id_int in {4624, 4634}:
            level = "info"
        elif event_id_int in {4697, 4688}:
            level = level or "info"

    if not message:
        message = json.dumps(payload, ensure_ascii=False)

    stream_parts = []
    if provider:
        stream_parts.append(provider)
    if event_id not in (None, ""):
        stream_parts.append(f"EventID={event_id}")
    stream = " | ".join(stream_parts)

    container = channel or "Windows"

    return {
        "source": source,
        "host": host,
        "container": container,
        "stream": stream,
        "level": level,
        "message": message,
    }

def store_event(payload: Any, event: dict[str, str]) -> str:
    fp = fingerprint_for_event(event)

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

    return fp


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

    event = extract_dozzle_event(payload)

    if should_ignore(event["message"]):
        return JSONResponse({"stored": False, "reason": "ignored"})

    fp = store_event(payload, event)
    return JSONResponse(
        {
            "stored": True,
            "source": event["source"],
            "container": event["container"],
            "fingerprint": fp,
        }
    )


@app.post("/windows")
async def windows_webhook(request: Request):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Expected JSON body")

    event = extract_windows_event(payload)

    if should_ignore(event["message"]):
        return JSONResponse({"stored": False, "reason": "ignored"})

    fp = store_event(payload, event)
    return JSONResponse(
        {
            "stored": True,
            "source": event["source"],
            "container": event["container"],
            "fingerprint": fp,
        }
    )


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
    grouped = defaultdict(
        lambda: {
            "count": 0,
            "source": "",
            "host": "",
            "container": "",
            "level": "",
            "stream": "",
            "first_seen": None,
            "last_seen": None,
            "examples": [],
            "ids": [],
            "fingerprint": "",
        }
    )

    max_examples = CONFIG["analysis"]["max_examples_per_group"]

    for row in rows:
        key = row["fingerprint"]
        g = grouped[key]
        g["count"] += 1
        g["source"] = row["source"]
        g["host"] = row["host"]
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
- Prefer real operational issues: crashes, permission problems, DB failures, OOM, disk full, network failures, bad gateway, TLS/cert failures, repeated exceptions, failed logons, unexpected shutdowns, driver resets, service failures.
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

def call_ollama(prompt: str) -> tuple[dict[str, Any], str]:
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

    raw_response = (data.get("response") or "").strip()
    raw_thinking = (data.get("thinking") or "").strip()

    candidate = raw_response or raw_thinking

    if not candidate:
        raise ValueError(f"Ollama returned empty response and empty thinking. Full payload: {data!r}")

    cleaned = candidate

    try:
        return json.loads(cleaned), cleaned
    except json.JSONDecodeError:
        pass

    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-zA-Z0-9_-]*\n?", "", cleaned)
        cleaned = re.sub(r"\n?```$", "", cleaned).strip()

    try:
        return json.loads(cleaned), candidate
    except json.JSONDecodeError:
        pass

    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        extracted = cleaned[start:end + 1]
        return json.loads(extracted), candidate

    raise ValueError(f"Could not parse Ollama JSON response. Candidate: {candidate!r}")

def call_ollama_text(prompt: str) -> str:
    url = CONFIG["ollama"]["url"].rstrip("/") + "/api/generate"
    body = {
        "model": CONFIG["ollama"]["model"],
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2,
        },
    }

    r = requests.post(url, json=body, timeout=CONFIG["ollama"]["timeout_seconds"])
    r.raise_for_status()
    data = r.json()

    raw_response = (data.get("response") or "").strip()
    raw_thinking = (data.get("thinking") or "").strip()

    text = raw_response or raw_thinking
    if not text:
        raise ValueError(f"Ollama returned empty response and empty thinking. Full payload: {data!r}")

    return text


def send_ntfy(message: str, priority: str = "default") -> None:
    url = CONFIG["notify"]["ntfy_url"]
    headers = {
        "Title": CONFIG["notify"]["title"],
        "Priority": priority,
        "Tags": "warning,robot_face",
    }
    r = requests.post(url, data=message.encode("utf-8"), headers=headers, timeout=30)
    if not r.ok:
        raise RuntimeError(f"ntfy error {r.status_code}: {r.text}")


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
    all_ids = [row["id"] for row in rows]

    try:
        result, raw_response = call_ollama(prompt)
        store_analysis_run(
            prompt=prompt,
            raw_response=raw_response,
            parsed_result=result,
            event_count=len(rows),
        )
    except Exception as e:
        store_analysis_run(
            prompt=prompt,
            raw_response=f"ERROR: {e}",
            parsed_result=None,
            event_count=len(rows),
        )
        raise

    findings = [f for f in result.get("findings", []) if f.get("severity") in {"low", "medium", "high"}]

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

        try:
            maybe_send_weekly_report()
        except Exception as e:
            print(f"[analysis_loop] weekly report error: {e}", flush=True)

        try:
            maybe_run_cleanup()
        except Exception as e:
            print(f"[analysis_loop] cleanup error: {e}", flush=True)

        time.sleep(interval)


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
    grouped = defaultdict(
        lambda: {
            "count": 0,
            "source": "",
            "host": "",
            "container": "",
            "level": "",
            "stream": "",
            "first_seen": None,
            "last_seen": None,
            "examples": [],
            "fingerprint": "",
        }
    )

    max_examples = CONFIG["analysis"]["max_examples_per_group"]

    for row in rows:
        key = row["fingerprint"]
        g = grouped[key]
        g["count"] += 1
        g["source"] = row["source"]
        g["host"] = row["host"]
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
        "lookback_hours": lookback_hours,
        "groups": groups,
    }

    return f"""
You are a homelab SRE generating a daily operations digest from infrastructure alert events.

Current system date/time: {current_system_time_str()}
Assume this date is correct.
Do not question or validate the system clock unless the input explicitly shows clock drift evidence.

Your job:
- identify the most important operational issues
- separate real problems from repetitive noise
- keep the report concise
- prioritize service-impacting problems

Output rules:
- Output plain text only
- Do not output JSON
- Do not output markdown code fences
- Do not use conversational language
- Do not ask questions
- Do not offer help
- Do not address the reader directly
- Maximum length: 1200 characters
- If there are no serious problems, say so clearly

Write the report in exactly this structure:

Overall Status: Healthy|Warning|Critical

Summary:
<2-4 short sentences summarizing the day>

Critical Issues:
- <source/container>: <issue> — <brief impact/action>
- <source/container>: <issue> — <brief impact/action>

Warnings:
- <source/container>: <issue> — <brief impact/action>
- <source/container>: <issue> — <brief impact/action>

Noise / Likely Harmless:
- <source/container>: <short description>
- <source/container>: <short description>

Classification guidance:
- Critical = service crashes, database failures, repeated connection failures, disk/full filesystem issues, OOM, panic/fatal/segfault, persistent upstream failures, repeated failed logons, unexpected shutdowns, driver crashes
- Warning = transient errors, rate limits, lock contention, repeated retries, degraded features, missing cache directories, one-off failed logons, isolated service failures
- Noise / Likely Harmless = one-off warnings, routine transfer stats, benign retries, expected disconnects, repetitive low-value log spam

Selection rules:
- Prefer recurring and service-impacting issues
- Collapse repeated similar events into one bullet
- Omit empty sections
- Ignore stack trace details unless they change the diagnosis
- Do not mention every event; summarize patterns

Input:
{json.dumps(payload, ensure_ascii=False, indent=2)}
""".strip()


def clean_daily_report_text(text: str) -> str:
    text = text.strip()

    text = re.sub(
        r"\n*(Would you like.*|Let me know.*|If you want.*|I can help.*)$",
        "",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    ).strip()

    text = text.replace("**", "").replace("### ", "")

    if not text.startswith("Overall Status:"):
        text = "Overall Status: Warning\n\n" + text

    return text


def truncate_for_ntfy(text: str, max_chars: int = 3500) -> str:
    text = text.strip()

    if len(text) <= max_chars:
        return text

    truncated = text[:max_chars].rstrip()
    return truncated + "\n\n[message truncated]"


def send_daily_report() -> None:
    cfg = CONFIG["daily_report"]
    lookback_hours = cfg.get("lookback_hours", 24)

    rows = fetch_events_for_lookback(lookback_hours)
    print(f"[daily_report] fetched {len(rows)} rows from last {lookback_hours}h", flush=True)

    if not rows:
        message = (
            "Homelab Daily Health Report\n\n"
            "Overall Status: Healthy\n\n"
            "No alert-level events were recorded in the last 24 hours."
        )
        send_ntfy(message, priority="default")
        print("[daily_report] sent healthy empty report", flush=True)
        return

    groups = group_events_for_daily(rows)
    prompt = build_daily_report_prompt(groups, lookback_hours)

    try:
        report_body = call_ollama_text(prompt).strip()
        if not report_body:
            raise ValueError("LLM returned empty report")
    except Exception as e:
        print(f"[daily_report] LLM failure: {e}", flush=True)
        report_body = (
            "Overall Status: Warning\n\n"
            "Daily report generation failed. Review infrastructure logs manually."
        )

    report_body = clean_daily_report_text(report_body)

    message = f"Homelab Daily Health Report\n\n{report_body}"
    message = truncate_for_ntfy(message, max_chars=3500)

    priority = "default"
    if "Overall Status: Critical" in message:
        priority = "urgent"
    elif "Overall Status: Warning" in message:
        priority = "high"

    send_ntfy(message, priority=priority)
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


def weekly_run_key(now: datetime) -> str:
    year, week, _ = now.isocalendar()
    return f"{year}-W{week:02d}"


def weekly_report_already_sent(run_key: str) -> bool:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT 1 FROM weekly_runs WHERE run_key = ?",
            (run_key,),
        ).fetchone()
    return row is not None


def mark_weekly_report_sent(run_key: str) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO weekly_runs (run_key, created_at) VALUES (?, ?)",
            (run_key, utcnow().isoformat()),
        )
        conn.commit()


def fetch_events_for_days(days: int) -> list[sqlite3.Row]:
    cutoff = utcnow() - timedelta(days=days)
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


def group_events_for_weekly(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    grouped = defaultdict(
        lambda: {
            "count": 0,
            "source": "",
            "container": "",
            "host": "",
            "level": "",
            "stream": "",
            "first_seen": None,
            "last_seen": None,
            "examples": [],
            "fingerprint": "",
            "days_seen": set(),
        }
    )

    max_examples = CONFIG["analysis"]["max_examples_per_group"]

    for row in rows:
        key = row["fingerprint"]
        g = grouped[key]
        g["count"] += 1
        g["source"] = row["source"]
        g["container"] = row["container"]
        g["host"] = row["host"]
        g["level"] = row["level"]
        g["stream"] = row["stream"]
        g["fingerprint"] = row["fingerprint"]

        created_at = row["created_at"]
        day = str(created_at)[:10]
        g["days_seen"].add(day)

        if g["first_seen"] is None:
            g["first_seen"] = created_at
        g["last_seen"] = created_at

        if len(g["examples"]) < max_examples:
            g["examples"].append(row["message"])

    output = []
    for g in grouped.values():
        out = dict(g)
        out["days_seen"] = sorted(out["days_seen"])
        out["days_seen_count"] = len(out["days_seen"])
        output.append(out)

    return sorted(
        output,
        key=lambda x: (x["days_seen_count"], x["count"]),
        reverse=True,
    )


def build_weekly_report_prompt(groups: list[dict[str, Any]], lookback_days: int) -> str:
    payload = {
        "lookback_days": lookback_days,
        "groups": groups[:30],
    }

    return f"""
You are generating a weekly homelab reliability report from infrastructure alert events.

Current system date/time: {current_system_time_str()}
Assume this date is correct.
Do not question or validate the system clock unless the input explicitly shows clock drift evidence.

Output plain text only in exactly this structure:

Overall Status: Healthy|Warning|Critical

Summary:
<2-4 short sentences>

Top Recurring Issues:
- <source/container>: <issue> — <count/trend/impact>
- <source/container>: <issue> — <count/trend/impact>

Top Noisy Sources:
- <source/container>: <short description>
- <source/container>: <short description>

Recommended Actions:
- <short operational action>
- <short operational action>
- <short operational action>

Rules:
- Do not ask questions
- Do not offer help
- Do not address the reader directly
- Do not use markdown headings like ### or **
- Maximum length: 1600 characters
- Prioritize recurring and service-impacting issues
- Collapse repeated similar events into one bullet
- Mention harmless noise only if it is very frequent
- Prefer issues seen on multiple days over one-off bursts

Input:
{json.dumps(payload, ensure_ascii=False, indent=2)}
""".strip()


def send_weekly_report() -> None:
    cfg = CONFIG["weekly_report"]
    lookback_days = cfg.get("lookback_days", 7)

    rows = fetch_events_for_days(lookback_days)
    print(f"[weekly_report] fetched {len(rows)} rows from last {lookback_days}d", flush=True)

    if not rows:
        message = (
            "Homelab Weekly Reliability Report\n\n"
            "Overall Status: Healthy\n\n"
            "No alert-level events were recorded in the last 7 days."
        )
        send_ntfy(message, priority="default")
        print("[weekly_report] sent empty healthy report", flush=True)
        return

    groups = group_events_for_weekly(rows)
    groups = groups[:20]
    prompt = build_weekly_report_prompt(groups, lookback_days)

    try:
        report_body = call_ollama_text(prompt).strip()
        report_body = clean_daily_report_text(report_body)

        if not report_body.startswith("Overall Status:"):
            report_body = "Overall Status: Warning\n\n" + report_body

    except Exception as e:
        print(f"[weekly_report] LLM failure: {e}", flush=True)
        report_body = (
            "Overall Status: Warning\n\n"
            "Weekly reliability report generation failed. Review logs manually."
        )

    message = f"Homelab Weekly Reliability Report\n\n{report_body}"
    message = truncate_for_ntfy(message, max_chars=3500)

    priority = "urgent" if "Overall Status: Critical" in message else "default"
    send_ntfy(message, priority=priority)

    print("[weekly_report] sent weekly report", flush=True)


def maybe_send_weekly_report() -> None:
    cfg = CONFIG.get("weekly_report", {})
    if not cfg.get("enabled", False):
        return

    now = datetime.now()
    run_key = weekly_run_key(now)

    if weekly_report_already_sent(run_key):
        return

    target_weekday = int(cfg.get("weekday", 0))
    target_hour = int(cfg.get("hour", 9))
    target_minute = int(cfg.get("minute", 0))

    if (
        now.weekday() == target_weekday
        and (
            now.hour > target_hour
            or (now.hour == target_hour and now.minute >= target_minute)
        )
    ):
        send_weekly_report()
        mark_weekly_report_sent(run_key)


@app.post("/weekly-report-now")
def weekly_report_now():
    try:
        send_weekly_report()
        return {"ok": True}
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})


def cleanup_old_data() -> None:
    retention = CONFIG.get("retention", {})
    events_days = int(retention.get("events_days", 30))
    daily_runs_days = int(retention.get("daily_runs_days", 180))
    weekly_runs_days = int(retention.get("weekly_runs_days", 365))
    housekeeping_runs_days = int(retention.get("housekeeping_runs_days", 365))
    analysis_runs_days = int(retention.get("analysis_runs_days", 30))
    analysis_runs_cutoff = (utcnow() - timedelta(days=analysis_runs_days)).isoformat()

    events_cutoff = (utcnow() - timedelta(days=events_days)).isoformat()
    daily_cutoff = (utcnow() - timedelta(days=daily_runs_days)).isoformat()
    weekly_cutoff = (utcnow() - timedelta(days=weekly_runs_days)).isoformat()
    housekeeping_cutoff = (utcnow() - timedelta(days=housekeeping_runs_days)).isoformat()

    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()

        cur.execute("DELETE FROM events WHERE created_at < ?", (events_cutoff,))
        deleted_events = cur.rowcount

        cur.execute("DELETE FROM daily_runs WHERE created_at < ?", (daily_cutoff,))
        deleted_daily = cur.rowcount

        cur.execute("DELETE FROM weekly_runs WHERE created_at < ?", (weekly_cutoff,))
        deleted_weekly = cur.rowcount

        cur.execute("DELETE FROM housekeeping_runs WHERE created_at < ?", (housekeeping_cutoff,))
        deleted_housekeeping = cur.rowcount

        cur.execute("DELETE FROM analysis_runs WHERE created_at < ?", (analysis_runs_cutoff,))
        deleted_analysis_runs = cur.rowcount

        conn.commit()

    print(
        "[cleanup] deleted "
        f"events={deleted_events} "
        f"daily_runs={deleted_daily} "
        f"weekly_runs={deleted_weekly} "
        f"housekeeping_runs={deleted_housekeeping} "
        f"analysis_runs={deleted_analysis_runs}",
        flush=True,
    )

def vacuum_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("VACUUM")
    print("[cleanup] vacuum completed", flush=True)


def housekeeping_run_key(prefix: str, now: datetime) -> str:
    return f"{prefix}-{now.strftime('%Y-%m-%d')}"


def housekeeping_already_ran(run_key: str) -> bool:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT 1 FROM housekeeping_runs WHERE run_key = ?",
            (run_key,),
        ).fetchone()
    return row is not None


def mark_housekeeping_ran(run_key: str) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO housekeeping_runs (run_key, created_at) VALUES (?, ?)",
            (run_key, utcnow().isoformat()),
        )
        conn.commit()


def maybe_run_cleanup() -> None:
    now = datetime.now()
    run_key = housekeeping_run_key("cleanup", now)

    if housekeeping_already_ran(run_key):
        return

    if now.hour >= 3:
        cleanup_old_data()
        mark_housekeeping_ran(run_key)


@app.post("/vacuum-now")
def vacuum_now():
    try:
        vacuum_db()
        return {"ok": True}
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})


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
            INSERT INTO analysis_runs (
                created_at,
                prompt,
                raw_response,
                parsed_json,
                overall_status,
                finding_count,
                event_count
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                utcnow().isoformat(),
                prompt,
                raw_response,
                parsed_json,
                overall_status,
                finding_count,
                event_count,
            ),
        )
        conn.commit()
