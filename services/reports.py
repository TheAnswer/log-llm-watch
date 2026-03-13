"""Daily and weekly report generation."""
import json
import re
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from core import config
from core.config import current_system_time_str, safe_json_loads, utcnow
from services.notifications import send_ntfy, truncate_for_ntfy
from services.ollama import call_ollama_text


# --- Shared helpers ---

def _fetch_incident_summaries(cutoff_iso: str) -> list[dict[str, Any]]:
    """Fetch analyzed open/recent incidents for report context."""
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT id, status, severity, title, event_class, event_count,
                   first_seen, last_seen, summary, probable_root_cause, confidence,
                   affected_nodes, affected_services
            FROM incidents
            WHERE last_seen >= ?
              AND summary IS NOT NULL AND summary != ''
            ORDER BY
                CASE severity WHEN 'critical' THEN 1 WHEN 'error' THEN 2
                              WHEN 'warning' THEN 3 ELSE 4 END,
                event_count DESC
            LIMIT 15
            """,
            (cutoff_iso,),
        ).fetchall()
    return [
        {
            "id": r["id"], "status": r["status"], "severity": r["severity"],
            "title": r["title"], "event_class": r["event_class"],
            "event_count": r["event_count"], "first_seen": r["first_seen"],
            "last_seen": r["last_seen"], "summary": r["summary"],
            "probable_root_cause": r["probable_root_cause"] or "",
            "confidence": r["confidence"] or "",
            "affected_nodes": safe_json_loads(r["affected_nodes"], []),
            "affected_services": safe_json_loads(r["affected_services"], []),
        }
        for r in rows
    ]


def _fetch_stats(cutoff_iso: str) -> dict[str, Any]:
    """Fetch high-level stats for the report period."""
    with sqlite3.connect(config.DB_PATH) as conn:
        total_events = conn.execute(
            "SELECT COUNT(*) FROM events WHERE created_at >= ?", (cutoff_iso,)
        ).fetchone()[0]
        by_severity = conn.execute(
            """
            SELECT COALESCE(severity_norm, 'unknown') AS sev, COUNT(*) AS cnt
            FROM events WHERE created_at >= ?
            GROUP BY sev ORDER BY cnt DESC
            """,
            (cutoff_iso,),
        ).fetchall()
        open_incidents = conn.execute(
            "SELECT COUNT(*) FROM incidents WHERE status = 'open'"
        ).fetchone()[0]
        suppress_rules = conn.execute(
            "SELECT COUNT(*) FROM suppress_rules"
        ).fetchone()[0]
        top_hosts = conn.execute(
            """
            SELECT host, COUNT(*) AS cnt FROM events
            WHERE created_at >= ? AND host != ''
            GROUP BY host ORDER BY cnt DESC LIMIT 5
            """,
            (cutoff_iso,),
        ).fetchall()
        top_containers = conn.execute(
            """
            SELECT container, COUNT(*) AS cnt FROM events
            WHERE created_at >= ? AND container != ''
            GROUP BY container ORDER BY cnt DESC LIMIT 5
            """,
            (cutoff_iso,),
        ).fetchall()
    return {
        "total_events": total_events,
        "by_severity": {r[0]: r[1] for r in by_severity},
        "open_incidents": open_incidents,
        "active_suppress_rules": suppress_rules,
        "top_hosts": {r[0]: r[1] for r in top_hosts},
        "top_containers": {r[0]: r[1] for r in top_containers},
    }


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
        "stream": "", "first_seen": None, "last_seen": None, "examples": [],
        "fingerprint": "", "event_class": "", "severity_norm": "", "dependency": "",
        "hosts_seen": set(),
    })
    max_examples = config.CONFIG["analysis"]["max_examples_per_group"]
    for row in rows:
        key = row["fingerprint"]
        g = grouped[key]
        g["count"] += 1
        g["source"] = row["source"]; g["host"] = row["host"]; g["container"] = row["container"]
        g["level"] = row["level"]; g["stream"] = row["stream"]; g["fingerprint"] = row["fingerprint"]
        if row["event_class"]:
            g["event_class"] = row["event_class"]
        if row["severity_norm"]:
            g["severity_norm"] = row["severity_norm"]
        if row["dependency"]:
            g["dependency"] = row["dependency"]
        if row["host"]:
            g["hosts_seen"].add(row["host"])
        created_at = row["created_at"]
        if g["first_seen"] is None:
            g["first_seen"] = created_at
        g["last_seen"] = created_at
        if len(g["examples"]) < max_examples:
            g["examples"].append(row["message"])

    output = []
    for g in grouped.values():
        out = dict(g)
        out["hosts_seen"] = sorted(out["hosts_seen"])
        output.append(out)
    return sorted(output, key=lambda x: x["count"], reverse=True)


def build_daily_report_prompt(groups: list[dict[str, Any]], lookback_hours: int,
                              stats: dict[str, Any], incidents: list[dict[str, Any]]) -> str:
    # Cap groups: top 20 by count, drop examples for noise (>3rd group)
    trimmed_groups = []
    for i, g in enumerate(groups[:20]):
        entry = {k: v for k, v in g.items() if k != "examples"}
        if i < 8:
            entry["examples"] = g["examples"][:3]
        else:
            entry["examples"] = [g["examples"][0]] if g["examples"] else []
        trimmed_groups.append(entry)

    payload = {
        "period": f"last {lookback_hours} hours",
        "stats": stats,
        "analyzed_incidents": incidents[:10],
        "event_groups": trimmed_groups,
    }

    data_json = json.dumps(payload, ensure_ascii=False, indent=2)

    return f"""You are a homelab SRE writing a daily operations report.

Current date/time: {current_system_time_str()}

INPUT DATA:
{data_json}

INSTRUCTIONS:
Write the report as plain text in exactly this structure. Omit any section that has no items.

Overall Status: Healthy|Warning|Critical

Summary:
<2-4 sentences: what happened today, what matters, what does not>

Critical Issues:
- <container/host>: <issue> (<count> events) — <impact and recommended action>

Warnings:
- <container/host>: <issue> (<count> events) — <brief note>

Noise / Suppressed:
- <container>: <short description>

Stats: <total_events> events, <open_incidents> open incidents, <suppress_rules> active suppress rules

RULES:
- Use the "analyzed_incidents" section — these contain LLM-analyzed root causes. Incorporate them.
- Use "event_class" and "severity_norm" fields to classify, not just the raw message text.
- Critical = service crashes, DB failures, repeated connection failures, disk full, OOM, panic/fatal, persistent upstream failures
- Warning = transient errors, lock contention, retries, degraded features, isolated failures
- Noise = one-off warnings, routine stats, benign retries, already-suppressed patterns
- Collapse similar issues into one bullet with combined counts.
- Do not list every group. Summarize patterns.
- Maximum 2000 characters. Plain text only. No markdown, no tables, no code fences.
- Do not use conversational language. Do not ask questions. Do not offer help.""".strip()


def clean_daily_report_text(text: str) -> str:
    text = text.strip()
    # Strip thinking tags if model leaked them
    text = re.sub(r"<think>[\s\S]*?</think>\s*", "", text).strip()
    text = re.sub(
        r"\n*(Would you like.*|Let me know.*|If you want.*|I can help.*)$",
        "", text, flags=re.IGNORECASE | re.DOTALL,
    ).strip()
    text = text.replace("**", "").replace("### ", "").replace("## ", "").replace("# ", "")
    # Remove markdown tables
    text = re.sub(r"\|[^\n]+\|\n", "", text)
    text = re.sub(r"\|[-:| ]+\|\n", "", text)
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

    cutoff_iso = (utcnow() - timedelta(hours=lookback_hours)).isoformat()
    groups = group_events_for_daily(rows)
    stats = _fetch_stats(cutoff_iso)
    incidents = _fetch_incident_summaries(cutoff_iso)
    prompt = build_daily_report_prompt(groups, lookback_hours, stats, incidents)

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
        "fingerprint": "", "event_class": "", "severity_norm": "", "dependency": "",
        "days_seen": set(), "hosts_seen": set(),
    })
    max_examples = config.CONFIG["analysis"]["max_examples_per_group"]
    for row in rows:
        key = row["fingerprint"]
        g = grouped[key]
        g["count"] += 1
        g["source"] = row["source"]; g["container"] = row["container"]; g["host"] = row["host"]
        g["level"] = row["level"]; g["stream"] = row["stream"]; g["fingerprint"] = row["fingerprint"]
        if row["event_class"]:
            g["event_class"] = row["event_class"]
        if row["severity_norm"]:
            g["severity_norm"] = row["severity_norm"]
        if row["dependency"]:
            g["dependency"] = row["dependency"]
        if row["host"]:
            g["hosts_seen"].add(row["host"])
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
        out["hosts_seen"] = sorted(out["hosts_seen"])
        output.append(out)
    return sorted(output, key=lambda x: (x["days_seen_count"], x["count"]), reverse=True)


def build_weekly_report_prompt(groups: list[dict[str, Any]], lookback_days: int,
                               stats: dict[str, Any], incidents: list[dict[str, Any]]) -> str:
    trimmed_groups = []
    for i, g in enumerate(groups[:25]):
        entry = {k: v for k, v in g.items() if k != "examples"}
        if i < 10:
            entry["examples"] = [g["examples"][0]] if g["examples"] else []
        trimmed_groups.append(entry)

    payload = {
        "period": f"last {lookback_days} days",
        "stats": stats,
        "analyzed_incidents": incidents[:10],
        "event_groups": trimmed_groups,
    }

    data_json = json.dumps(payload, ensure_ascii=False, indent=2)

    return f"""You are a homelab SRE writing a weekly reliability report.

Current date/time: {current_system_time_str()}

INPUT DATA:
{data_json}

INSTRUCTIONS:
Write the report as plain text in exactly this structure. Omit any section that has no items.

Overall Status: Healthy|Warning|Critical

Summary:
<2-4 sentences: week overview, trends, key concerns>

Top Recurring Issues:
- <container/host>: <issue> — seen <days_seen_count> days, <count> events — <impact>

Emerging Trends:
- <observation about changes this week>

Recommended Actions:
- <short operational action>

Noisy Sources:
- <container>: <count> events — <consider suppressing?>

Stats: <total_events> events across <num_hosts> hosts, <open_incidents> open incidents

RULES:
- Use "analyzed_incidents" for root cause context. Incorporate their summaries.
- Use "days_seen_count" to identify persistent vs one-off issues. Persistent issues matter more.
- Use "event_class" and "severity_norm" to classify severity.
- Critical = recurring service-impacting issues seen on multiple days
- Warning = intermittent issues or single-day bursts
- Collapse similar issues. Do not list every group.
- Maximum 2500 characters. Plain text only. No markdown, no tables, no code fences.
- Do not use conversational language. Do not ask questions. Do not offer help.""".strip()


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

    cutoff_iso = (utcnow() - timedelta(days=lookback_days)).isoformat()
    groups = group_events_for_weekly(rows)[:25]
    stats = _fetch_stats(cutoff_iso)
    incidents = _fetch_incident_summaries(cutoff_iso)
    prompt = build_weekly_report_prompt(groups, lookback_days, stats, incidents)

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
