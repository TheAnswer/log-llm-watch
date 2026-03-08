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

now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z")
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
        conn.execute("""
        CREATE TABLE IF NOT EXISTS weekly_runs (
        run_key TEXT PRIMARY KEY,
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

    #print(f"[call_ollama] full response json: {data!r}", flush=True)

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

        try:
            maybe_send_weekly_report()
        except Exception as e:
            print(f"[analysis_loop] weekly report error: {e}", flush=True)

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
        "lookback_hours": lookback_hours,
        "groups": groups,
    }

    return f"""
You are a homelab SRE generating a daily operations digest from container alert events.

Current system date/time: {now_str}
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
- <container>: <issue> — <brief impact/action>
- <container>: <issue> — <brief impact/action>

Warnings:
- <container>: <issue> — <brief impact/action>
- <container>: <issue> — <brief impact/action>

Noise / Likely Harmless:
- <container>: <short description>
- <container>: <short description>

Classification guidance:
- Critical = service crashes, database failures, repeated connection failures, disk/full filesystem issues, OOM, panic/fatal/segfault, persistent upstream failures
- Warning = transient errors, rate limits, lock contention, repeated retries, degraded features, missing cache directories
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

    # Remove common chatbot endings
    text = re.sub(
        r"\n*(Would you like.*|Let me know.*|If you want.*|I can help.*)$",
        "",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    ).strip()

    # Remove markdown emphasis if the model sneaks it in
    text = text.replace("**", "").replace("### ", "")

    # Ensure status line exists
    if not text.startswith("Overall Status:"):
        text = "Overall Status: Warning\n\n" + text

    return text

def truncate_for_ntfy(text: str, max_chars: int = 3500) -> str:
    """
    ntfy rejects very large messages with HTTP 400.
    This safely truncates messages to a reasonable size.
    """
    text = text.strip()

    if len(text) <= max_chars:
        return text

    truncated = text[:max_chars].rstrip()

    return truncated + "\n\n[message truncated]"

def send_daily_report() -> None:
    cfg = CONFIG["daily_report"]
    lookback_hours = cfg.get("lookback_hours", 24)

    # Fetch recent events
    rows = fetch_events_for_lookback(lookback_hours)

    print(
        f"[daily_report] fetched {len(rows)} rows from last {lookback_hours}h",
        flush=True,
    )

    # If nothing happened, send healthy report
    if not rows:
        message = (
            "Homelab Daily Health Report\n\n"
            "Overall Status: Healthy\n\n"
            "No alert-level container events were recorded in the last 24 hours."
        )

        send_ntfy(message, priority="default")

        print("[daily_report] sent healthy empty report", flush=True)
        return

    # Group events for the LLM
    groups = group_events_for_daily(rows)

    # Build prompt
    prompt = build_daily_report_prompt(groups, lookback_hours)

    try:
        report_body = call_ollama_text(prompt).strip()

        if not report_body:
            raise ValueError("LLM returned empty report")

    except Exception as e:
        print(f"[daily_report] LLM failure: {e}", flush=True)

        report_body = (
            "Overall Status: Warning\n\n"
            "Daily report generation failed. Review container logs manually."
        )

    report_body = clean_daily_report_text(report_body)

    # Build final message
    message = f"Homelab Daily Health Report\n\n{report_body}"
    message = truncate_for_ntfy(message, max_chars=3500)

    # Determine ntfy priority
    priority = "default"

    if "Overall Status: Critical" in message:
        priority = "urgent"
    elif "Overall Status: Warning" in message:
        priority = "high"

    send_ntfy(message, priority=priority)

    print("[daily_report] sent daily report", flush=True)


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
    grouped = defaultdict(lambda: {
        "count": 0,
        "container": "",
        "host": "",
        "level": "",
        "stream": "",
        "first_seen": None,
        "last_seen": None,
        "examples": [],
        "fingerprint": "",
        "days_seen": set(),
    })

    max_examples = CONFIG["analysis"]["max_examples_per_group"]

    for row in rows:
        key = row["fingerprint"]
        g = grouped[key]
        g["count"] += 1
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
You are generating a weekly homelab reliability report from Docker alert events.

Current system date/time: {now_str}
Assume this date is correct.
Do not question or validate the system clock unless the input explicitly shows clock drift evidence.

Output plain text only in exactly this structure:

Overall Status: Healthy|Warning|Critical

Summary:
<2-4 short sentences>

Top Recurring Issues:
- <container>: <issue> — <count/trend/impact>
- <container>: <issue> — <count/trend/impact>

Top Noisy Containers:
- <container>: <short description>
- <container>: <short description>

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
            "No alert-level container events were recorded in the last 7 days."
        )
        send_ntfy(message, priority="default")
        print("[weekly_report] sent empty healthy report", flush=True)
        return

    groups = group_events_for_weekly(rows)

    # Keep the prompt compact and trend-focused
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

    target_weekday = int(cfg.get("weekday", 0))  # 0=Monday
    target_hour = int(cfg.get("hour", 9))
    target_minute = int(cfg.get("minute", 0))

    if (
        now.weekday() == target_weekday and
        (
            now.hour > target_hour or
            (now.hour == target_hour and now.minute >= target_minute)
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
