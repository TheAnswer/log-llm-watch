"""Daily and weekly report generation."""
import json
import re
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

import config
from config import current_system_time_str, utcnow
from notifications import send_ntfy, truncate_for_ntfy
from ollama import call_ollama_text


# --- Daily report ---

def daily_report_already_sent(run_date: str) -> bool:
    with sqlite3.connect(config.DB_PATH) as conn:
        row = conn.execute("SELECT 1 FROM daily_runs WHERE run_date = ?", (run_date,)).fetchone()
    return row is not None


def mark_daily_report_sent(run_date: str) -> None:
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.execute("INSERT OR REPLACE INTO daily_runs (run_date, created_at) VALUES (?, ?)", (run_date, utcnow().isoformat()))
        conn.commit()


def fetch_events_for_lookback(hours: int) -> list[sqlite3.Row]:
    cutoff = utcnow() - timedelta(hours=hours)
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM events WHERE created_at >= ? ORDER BY created_at ASC", (cutoff.isoformat(),)).fetchall()
    return rows


def group_events_for_daily(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    grouped = defaultdict(lambda: {
        "count": 0, "source": "", "host": "", "container": "", "level": "",
        "stream": "", "first_seen": None, "last_seen": None, "examples": [], "fingerprint": "",
    })
    max_examples = config.CONFIG["analysis"]["max_examples_per_group"]
    for row in rows:
        key = row["fingerprint"]
        g = grouped[key]
        g["count"] += 1
        g["source"] = row["source"]; g["host"] = row["host"]; g["container"] = row["container"]
        g["level"] = row["level"]; g["stream"] = row["stream"]; g["fingerprint"] = row["fingerprint"]
        created_at = row["created_at"]
        if g["first_seen"] is None:
            g["first_seen"] = created_at
        g["last_seen"] = created_at
        if len(g["examples"]) < max_examples:
            g["examples"].append(row["message"])
    return sorted(grouped.values(), key=lambda x: x["count"], reverse=True)


def build_daily_report_prompt(groups: list[dict[str, Any]], lookback_hours: int) -> str:
    payload = {"lookback_hours": lookback_hours, "groups": groups}
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

Warnings:
- <source/container>: <issue> — <brief impact/action>

Noise / Likely Harmless:
- <source/container>: <short description>

Classification guidance:
- Critical = service crashes, database failures, repeated connection failures, disk/full filesystem issues, OOM, panic/fatal/segfault, persistent upstream failures, repeated failed logons,
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
        "", text, flags=re.IGNORECASE | re.DOTALL,
    ).strip()
    text = text.replace("**", "").replace("### ", "")
    if not text.startswith("Overall Status:"):
        text = "Overall Status: Warning\n\n" + text
    return text


def send_daily_report() -> None:
    cfg = config.CONFIG["daily_report"]
    lookback_hours = cfg.get("lookback_hours", 24)
    rows = fetch_events_for_lookback(lookback_hours)
    print(f"[daily_report] fetched {len(rows)} rows from last {lookback_hours}h", flush=True)

    if not rows:
        message = "Homelab Daily Health Report\n\nOverall Status: Healthy\n\nNo alert-level events were recorded in the last 24 hours."
        send_ntfy(message, priority="default", source="daily_report")
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
        report_body = "Overall Status: Warning\n\nDaily report generation failed. Review infrastructure logs manually."

    report_body = clean_daily_report_text(report_body)
    message = f"Homelab Daily Health Report\n\n{report_body}"
    message = truncate_for_ntfy(message, max_chars=3500)

    priority = "default"
    if "Overall Status: Critical" in message:
        priority = "urgent"
    elif "Overall Status: Warning" in message:
        priority = "high"

    send_ntfy(message, priority=priority, source="daily_report")
    print("[daily_report] sent daily report", flush=True)


def maybe_send_daily_report() -> None:
    cfg = config.CONFIG.get("daily_report", {})
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


# --- Weekly report ---

def weekly_run_key(now: datetime) -> str:
    year, week, _ = now.isocalendar()
    return f"{year}-W{week:02d}"


def weekly_report_already_sent(run_key: str) -> bool:
    with sqlite3.connect(config.DB_PATH) as conn:
        row = conn.execute("SELECT 1 FROM weekly_runs WHERE run_key = ?", (run_key,)).fetchone()
    return row is not None


def mark_weekly_report_sent(run_key: str) -> None:
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.execute("INSERT OR REPLACE INTO weekly_runs (run_key, created_at) VALUES (?, ?)", (run_key, utcnow().isoformat()))
        conn.commit()


def fetch_events_for_days(days: int) -> list[sqlite3.Row]:
    cutoff = utcnow() - timedelta(days=days)
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM events WHERE created_at >= ? ORDER BY created_at ASC", (cutoff.isoformat(),)).fetchall()
    return rows


def group_events_for_weekly(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    grouped = defaultdict(lambda: {
        "count": 0, "source": "", "container": "", "host": "", "level": "",
        "stream": "", "first_seen": None, "last_seen": None, "examples": [],
        "fingerprint": "", "days_seen": set(),
    })
    max_examples = config.CONFIG["analysis"]["max_examples_per_group"]
    for row in rows:
        key = row["fingerprint"]
        g = grouped[key]
        g["count"] += 1
        g["source"] = row["source"]; g["container"] = row["container"]; g["host"] = row["host"]
        g["level"] = row["level"]; g["stream"] = row["stream"]; g["fingerprint"] = row["fingerprint"]
        created_at = row["created_at"]
        g["days_seen"].add(str(created_at)[:10])
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
    return sorted(output, key=lambda x: (x["days_seen_count"], x["count"]), reverse=True)


def build_weekly_report_prompt(groups: list[dict[str, Any]], lookback_days: int) -> str:
    payload = {"lookback_days": lookback_days, "groups": groups[:30]}
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

Top Noisy Sources:
- <source/container>: <short description>

Recommended Actions:
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
    cfg = config.CONFIG["weekly_report"]
    lookback_days = cfg.get("lookback_days", 7)
    rows = fetch_events_for_days(lookback_days)
    print(f"[weekly_report] fetched {len(rows)} rows from last {lookback_days}d", flush=True)

    if not rows:
        message = "Homelab Weekly Reliability Report\n\nOverall Status: Healthy\n\nNo alert-level events were recorded in the last 7 days."
        send_ntfy(message, priority="default", source="weekly_report")
        print("[weekly_report] sent empty healthy report", flush=True)
        return

    groups = group_events_for_weekly(rows)[:20]
    prompt = build_weekly_report_prompt(groups, lookback_days)

    try:
        report_body = call_ollama_text(prompt).strip()
        report_body = clean_daily_report_text(report_body)
        if not report_body.startswith("Overall Status:"):
            report_body = "Overall Status: Warning\n\n" + report_body
    except Exception as e:
        print(f"[weekly_report] LLM failure: {e}", flush=True)
        report_body = "Overall Status: Warning\n\nWeekly reliability report generation failed. Review logs manually."

    message = f"Homelab Weekly Reliability Report\n\n{report_body}"
    message = truncate_for_ntfy(message, max_chars=3500)
    priority = "urgent" if "Overall Status: Critical" in message else "default"
    send_ntfy(message, priority=priority, source="weekly_report")
    print("[weekly_report] sent weekly report", flush=True)


def maybe_send_weekly_report() -> None:
    cfg = config.CONFIG.get("weekly_report", {})
    if not cfg.get("enabled", False):
        return
    now = datetime.now()
    run_key = weekly_run_key(now)
    if weekly_report_already_sent(run_key):
        return
    target_weekday = int(cfg.get("weekday", 0))
    target_hour = int(cfg.get("hour", 9))
    target_minute = int(cfg.get("minute", 0))
    if now.weekday() == target_weekday and (now.hour > target_hour or (now.hour == target_hour and now.minute >= target_minute)):
        send_weekly_report()
        mark_weekly_report_sent(run_key)
