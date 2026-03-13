"""Incident lifecycle: create, attach, close, context building, LLM analysis, and digest."""
import json
import sqlite3
import threading
import time
from datetime import timedelta
from typing import Any

from fastapi import HTTPException

from core import config
from core.config import safe_json_loads, utcnow
from core.database import db
from core.normalize import enrich_event
from services.ollama import call_ollama
from services.suppression import (
    _SUPPRESS_EC, _SUPPRESS_EC_HOST, _SUPPRESS_FP, _SUPPRESS_LOCK,
    load_suppressed_fingerprints, template_to_suppress_pattern,
)

_FALSE_POSITIVE_LABELS = {"false_positive", "false_positive_severity", "false_positive_noise"}

_DIGEST_CACHE: dict[str, Any] = {}
_DIGEST_CACHE_TTL_SECS = 300
_DIGEST_CACHE_LOCK = threading.Lock()


def incident_title_for_event(event: dict[str, str]) -> str:
    event_class = event.get("event_class", "unknown")
    service = event.get("service", "") or event.get("container", "") or event.get("source", "")
    title_map = {
        "ups_usb_comm_error": "UPS communication errors",
        "dns_failure": "DNS resolution failures",
        "connect_refused": "Connection refused errors",
        "routing_failure": "Routing failures",
        "tls_or_cert_issue": "TLS/certificate issues",
        "database_locked": "Database lock contention",
        "no_space_left": "Filesystem out of space",
        "oom_kill": "Out-of-memory kills",
        "proxy_upstream_failure": "Proxy upstream failures",
        "failed_logon": "Failed Windows logons",
        "auth_failure": "Authentication failures",
        "timeout": "Timeout errors",
        "unknown": "Unclassified operational events",
        "windows_udp_ephemeral_port_exhaustion": "Windows UDP ephemeral port exhaustion",
    }
    base = title_map.get(event_class, "Operational issue detected")
    return f"{base} ({service})" if service else base


def root_cause_candidates_for_event(event: dict[str, str]) -> list[str]:
    event_class = event.get("event_class", "unknown")
    mapping = {
        "ups_usb_comm_error": ["usb_connectivity", "ups_hardware", "duplicate_forwarding_noise"],
        "dns_failure": ["shared_network_or_dns_incident"],
        "connect_refused": ["service_unavailable", "routing_or_firewall_issue"],
        "routing_failure": ["routing_or_firewall_issue"],
        "tls_or_cert_issue": ["certificate_or_tls_misconfiguration"],
        "database_locked": ["storage_or_db_backpressure"],
        "no_space_left": ["filesystem_capacity_issue"],
        "oom_kill": ["memory_pressure"],
        "proxy_upstream_failure": ["upstream_service_unavailable"],
        "failed_logon": ["failed_authentication"],
        "auth_failure": ["failed_authentication"],
        "timeout": ["network_latency_or_dependency_stall"],
        "windows_udp_ephemeral_port_exhaustion": [
            "udp_port_exhaustion", "socket_leak_or_high_udp_churn", "application_network_burst",
        ],
        "unknown": [],
    }
    return mapping.get(event_class, [])


def attach_or_create_incident(conn: sqlite3.Connection, event: dict[str, str]) -> int | None:
    _fp = event.get("canonical_fingerprint", "")
    _ec = event.get("event_class", "")
    _host = event.get("host", "")
    with _SUPPRESS_LOCK:
        if (
            (_fp and _fp in _SUPPRESS_FP)
            or (_ec and _ec in _SUPPRESS_EC)
            or (_ec and _host and (_ec, _host) in _SUPPRESS_EC_HOST)
        ):
            return None

    now_iso = utcnow().isoformat()
    window_minutes = int(config.CONFIG.get("incidents", {}).get("open_window_minutes", 10))
    window_start = (utcnow() - timedelta(minutes=window_minutes)).isoformat()

    row = conn.execute(
        """
        SELECT id, affected_nodes, affected_services, event_count, root_cause_candidates, metadata
        FROM incidents
        WHERE status = 'open'
          AND primary_fingerprint = ?
          AND last_seen >= ?
        ORDER BY last_seen DESC
        LIMIT 1
        """,
        (event["canonical_fingerprint"], window_start),
    ).fetchone()

    event_node = event.get("host", "")
    event_service = event.get("service", "") or event.get("container", "")

    if row:
        affected_nodes = set(safe_json_loads(row[1], []))
        affected_services = set(safe_json_loads(row[2], []))
        root_causes = set(safe_json_loads(row[4], []))
        metadata = safe_json_loads(row[5], {})

        if event_node:
            affected_nodes.add(event_node)
        if event_service:
            affected_services.add(event_service)
        for item in root_cause_candidates_for_event(event):
            root_causes.add(item)

        metadata["last_event_class"] = event.get("event_class", "")
        metadata["last_severity_norm"] = event.get("severity_norm", "")
        metadata["last_source"] = event.get("source", "")

        conn.execute(
            """
            UPDATE incidents
            SET last_seen = ?, event_count = ?, affected_nodes = ?,
                affected_services = ?, root_cause_candidates = ?, metadata = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                event["ts"], int(row[3]) + 1,
                json.dumps(sorted(affected_nodes), ensure_ascii=False),
                json.dumps(sorted(affected_services), ensure_ascii=False),
                json.dumps(sorted(root_causes), ensure_ascii=False),
                json.dumps(metadata, ensure_ascii=False),
                now_iso, row[0],
            ),
        )
        return int(row[0])

    severity = event.get("severity_norm", "") or "info"
    new_affected_nodes = [event_node] if event_node else []
    new_affected_services = [event_service] if event_service else []
    root_causes = root_cause_candidates_for_event(event)
    metadata = {
        "source": event.get("source", ""),
        "container": event.get("container", ""),
        "dependency": event.get("dependency", ""),
    }

    cur = conn.execute(
        """
        INSERT INTO incidents (
            status, severity, title, event_class, primary_fingerprint,
            first_seen, last_seen, event_count, affected_nodes, affected_services,
            root_cause_candidates, summary, metadata, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "open", severity, incident_title_for_event(event),
            event.get("event_class", ""), event["canonical_fingerprint"],
            event["ts"], event["ts"], 1,
            json.dumps(new_affected_nodes, ensure_ascii=False),
            json.dumps(new_affected_services, ensure_ascii=False),
            json.dumps(root_causes, ensure_ascii=False),
            "", json.dumps(metadata, ensure_ascii=False),
            now_iso, now_iso,
        ),
    )
    return int(cur.lastrowid)


def close_stale_incidents() -> None:
    cfg = config.CONFIG.get("incidents", {})
    stale_minutes = int(cfg.get("close_after_minutes", 30))
    cutoff = (utcnow() - timedelta(minutes=stale_minutes)).isoformat()
    with db() as conn:
        conn.execute(
            "UPDATE incidents SET status = 'closed', updated_at = ? WHERE status = 'open' AND severity != 'critical' AND last_seen < ?",
            (utcnow().isoformat(), cutoff),
        )
        conn.commit()


def build_incident_context(
    incident_id: int,
    event_limit: int = 20,
    nearby_limit: int = 100,
    similar_limit: int = 5,
    minutes_before: int = 2,
    minutes_after: int = 10,
) -> dict[str, Any]:
    from datetime import datetime
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        incident = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        incident_obj = {
            "id": incident["id"], "status": incident["status"],
            "severity": incident["severity"], "title": incident["title"],
            "event_class": incident["event_class"],
            "primary_fingerprint": incident["primary_fingerprint"],
            "first_seen": incident["first_seen"], "last_seen": incident["last_seen"],
            "event_count": incident["event_count"],
            "affected_nodes": safe_json_loads(incident["affected_nodes"], []),
            "affected_services": safe_json_loads(incident["affected_services"], []),
            "root_cause_candidates": safe_json_loads(incident["root_cause_candidates"], []),
            "summary": incident["summary"] or "",
            "probable_root_cause": incident["probable_root_cause"] or "",
            "confidence": incident["confidence"] or "",
            "last_analyzed_at": incident["last_analyzed_at"] or "",
            "analysis_json": safe_json_loads(incident["analysis_json"], None),
            "metadata": safe_json_loads(incident["metadata"], {}),
        }

        representative_events = conn.execute(
            """
            SELECT id, ts, created_at, source, host, container, stream, level, severity_norm,
                   event_class, dependency, message, message_template, canonical_fingerprint, incident_id
            FROM events WHERE incident_id = ? ORDER BY ts ASC, id ASC LIMIT ?
            """,
            (incident_id, max(1, min(event_limit, 200))),
        ).fetchall()

        try:
            first_seen_dt = datetime.fromisoformat(incident["first_seen"].replace("Z", "+00:00"))
            last_seen_dt = datetime.fromisoformat(incident["last_seen"].replace("Z", "+00:00"))
        except Exception:
            first_seen_dt = utcnow()
            last_seen_dt = utcnow()

        window_start = (first_seen_dt - timedelta(minutes=max(0, minutes_before))).isoformat()
        window_end = (last_seen_dt + timedelta(minutes=max(0, minutes_after))).isoformat()

        nearby_events = conn.execute(
            """
            SELECT id, ts, created_at, source, host, container, stream, level, severity_norm,
                   event_class, dependency, message, message_template, canonical_fingerprint, incident_id
            FROM events WHERE ts >= ? AND ts <= ? ORDER BY ts ASC, id ASC LIMIT ?
            """,
            (window_start, window_end, max(1, min(nearby_limit, 500))),
        ).fetchall()

        similar_cutoff = (utcnow() - timedelta(days=90)).isoformat()
        similar_incidents = conn.execute(
            """
            SELECT * FROM incidents
            WHERE primary_fingerprint = ? AND id != ? AND last_seen >= ?
            ORDER BY last_seen DESC LIMIT ?
            """,
            (incident["primary_fingerprint"], incident_id, similar_cutoff, max(1, min(similar_limit, 50))),
        ).fetchall()

    return {
        "incident": incident_obj,
        "representative_events": [dict(row) for row in representative_events],
        "nearby_window": {"start": window_start, "end": window_end, "minutes_before": minutes_before, "minutes_after": minutes_after},
        "nearby_events": [dict(row) for row in nearby_events],
        "similar_incidents": [
            {
                "id": row["id"], "status": row["status"], "severity": row["severity"],
                "title": row["title"], "event_class": row["event_class"],
                "first_seen": row["first_seen"], "last_seen": row["last_seen"],
                "event_count": row["event_count"],
                "affected_nodes": safe_json_loads(row["affected_nodes"], []),
                "affected_services": safe_json_loads(row["affected_services"], []),
                "root_cause_candidates": safe_json_loads(row["root_cause_candidates"], []),
                "summary": row["summary"] or "",
                "probable_root_cause": row["probable_root_cause"] or "",
                "confidence": row["confidence"] or "",
                "last_analyzed_at": row["last_analyzed_at"] or "",
                "analysis_json": safe_json_loads(row["analysis_json"], None),
                "metadata": safe_json_loads(row["metadata"], {}),
            }
            for row in similar_incidents
        ],
    }


def _is_low_value_nearby_event(row: dict[str, Any]) -> bool:
    severity_norm = (row.get("severity_norm") or "").strip().lower()
    event_class = (row.get("event_class") or "").strip().lower()
    container = (row.get("container") or "").strip().lower()
    message = (row.get("message") or "").strip().lower()

    if severity_norm == "info" and event_class in {"", "unknown"}:
        return True
    if "autofan:" in message:
        return True
    if "monitor_nchan: stop running nchan processes" in message:
        return True
    if "logged into ups [ups]" in message:
        return True
    if container == "syslog" and severity_norm == "info" and event_class in {"", "unknown"}:
        return True
    return False


def build_incident_context_filtered(
    incident_id: int, event_limit: int = 20, nearby_limit: int = 100,
    similar_limit: int = 5, minutes_before: int = 2, minutes_after: int = 10,
    exclude_info: bool = True, exclude_unknown: bool = True,
    exclude_noise: bool = True, exclude_same_incident_from_nearby: bool = True,
) -> dict[str, Any]:
    base = build_incident_context(
        incident_id=incident_id, event_limit=event_limit, nearby_limit=nearby_limit,
        similar_limit=similar_limit, minutes_before=minutes_before, minutes_after=minutes_after,
    )

    filtered_nearby: list[dict[str, Any]] = []
    for item in base["nearby_events"]:
        severity_norm = (item.get("severity_norm") or "").strip().lower()
        event_class = (item.get("event_class") or "").strip().lower()
        if exclude_same_incident_from_nearby and item.get("incident_id") == incident_id:
            continue
        if exclude_info and severity_norm == "info":
            continue
        if exclude_unknown and event_class in {"", "unknown"}:
            continue
        if exclude_noise and _is_low_value_nearby_event(item):
            continue
        filtered_nearby.append(item)

    def summarize_dict_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
        by_host: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        by_event_class: dict[str, int] = {}
        by_source: dict[str, int] = {}
        for row in rows:
            by_host[row.get("host") or ""] = by_host.get(row.get("host") or "", 0) + 1
            by_severity[row.get("severity_norm") or ""] = by_severity.get(row.get("severity_norm") or "", 0) + 1
            by_event_class[row.get("event_class") or ""] = by_event_class.get(row.get("event_class") or "", 0) + 1
            by_source[row.get("source") or ""] = by_source.get(row.get("source") or "", 0) + 1
        def sort_dict(d: dict[str, int]) -> dict[str, int]:
            return dict(sorted(d.items(), key=lambda kv: (-kv[1], kv[0])))
        return {"total": len(rows), "by_host": sort_dict(by_host), "by_severity": sort_dict(by_severity), "by_event_class": sort_dict(by_event_class), "by_source": sort_dict(by_source)}

    base["nearby_events_filtered"] = filtered_nearby
    base["nearby_stats_raw"] = summarize_dict_rows(base["nearby_events"])
    base["nearby_stats_filtered"] = summarize_dict_rows(filtered_nearby)
    return base


def build_incident_llm_context(
    incident_id: int, event_limit: int = 12, nearby_limit: int = 60,
    similar_limit: int = 5, minutes_before: int = 2, minutes_after: int = 10,
) -> dict[str, Any]:
    ctx = build_incident_context_filtered(
        incident_id=incident_id, event_limit=event_limit, nearby_limit=nearby_limit,
        similar_limit=similar_limit, minutes_before=minutes_before, minutes_after=minutes_after,
        exclude_info=True, exclude_unknown=True, exclude_noise=True, exclude_same_incident_from_nearby=True,
    )
    incident = ctx["incident"]
    return {
        "incident": incident,
        "investigation_focus": {
            "primary_question": f"What is the likely root cause of incident {incident_id}?",
            "candidate_causes": incident.get("root_cause_candidates", []),
            "event_class": incident.get("event_class", ""),
            "severity": incident.get("severity", ""),
            "affected_nodes": incident.get("affected_nodes", []),
            "affected_services": incident.get("affected_services", []),
        },
        "representative_events": ctx["representative_events"],
        "nearby_window": ctx["nearby_window"],
        "nearby_events_filtered": ctx["nearby_events_filtered"],
        "nearby_stats_filtered": ctx["nearby_stats_filtered"],
        "similar_incidents": ctx["similar_incidents"],
    }


def build_incident_analysis_prompt(ctx: dict[str, Any]) -> str:
    payload = {
        "incident": ctx["incident"],
        "investigation_focus": ctx["investigation_focus"],
        "representative_events": ctx["representative_events"],
        "nearby_window": ctx["nearby_window"],
        "nearby_events_filtered": ctx["nearby_events_filtered"],
        "nearby_stats_filtered": ctx["nearby_stats_filtered"],
        "similar_incidents": ctx["similar_incidents"],
    }

    return f"""
You are a homelab SRE incident analyst.

Analyze the incident context below and determine the most likely root cause.
Be conservative. Do not invent facts not present in the data.
Distinguish between the target incident and merely nearby correlated events.
Use the candidate causes as hints, not as truth.

Return strict JSON only with this schema:

{{
  "summary": "string",
  "probable_root_cause": "string",
  "confidence": "low|medium|high",
  "is_false_positive": true|false,
  "evidence": ["string"],
  "next_checks": ["string"]
}}

Guidance:
- "summary" should be 1-3 sentences
- "probable_root_cause" should be a short machine-friendly label like:
  "service_unavailable", "routing_or_firewall_issue", "dns_failure", "storage_backpressure", "unknown",
  "false_positive" (use this when the incident is noise, benign, or was incorrectly escalated)
- "is_false_positive" must be true only when the incident is clearly noise, benign, or a misclassification — set false for any genuinely actionable issue regardless of severity
- "confidence" should reflect how directly the evidence supports the conclusion
- "evidence" should include 2-5 concise points grounded in the input
- "next_checks" should include 2-5 concrete operational checks

Incident context:
{json.dumps(payload, ensure_ascii=False, indent=2)}
""".strip()


def analyze_incident_with_ollama(
    incident_id: int, persist_summary: bool = False, include_raw_response: bool = False,
) -> dict[str, Any]:
    ctx = build_incident_llm_context(incident_id=incident_id)
    prompt = build_incident_analysis_prompt(ctx)
    result, raw_response = call_ollama(prompt)

    analysis = {
        "summary": str(result.get("summary") or "").strip(),
        "probable_root_cause": str(result.get("probable_root_cause") or "unknown").strip(),
        "confidence": str(result.get("confidence") or "low").strip().lower(),
        "is_false_positive": bool(result.get("is_false_positive", False)),
        "evidence": result.get("evidence") if isinstance(result.get("evidence"), list) else [],
        "next_checks": result.get("next_checks") if isinstance(result.get("next_checks"), list) else [],
    }

    if analysis["confidence"] not in {"low", "medium", "high"}:
        analysis["confidence"] = "low"
    analysis["evidence"] = [str(x).strip() for x in analysis["evidence"] if str(x).strip()][:5]
    analysis["next_checks"] = [str(x).strip() for x in analysis["next_checks"] if str(x).strip()][:5]

    if persist_summary:
        with db() as conn:
            conn.execute(
                """
                UPDATE incidents
                SET summary = ?, analysis_json = ?, probable_root_cause = ?,
                    confidence = ?, last_analyzed_at = ?, updated_at = ?
                WHERE id = ?
                """,
                (analysis["summary"], json.dumps(analysis, ensure_ascii=False),
                 analysis["probable_root_cause"], analysis["confidence"],
                 utcnow().isoformat(), utcnow().isoformat(), incident_id),
            )
            conn.commit()

    output: dict[str, Any] = {"incident_id": incident_id, "analysis": analysis, "llm_context": ctx}
    if include_raw_response:
        output["raw_response"] = raw_response
    return output


def fetch_open_incidents_for_digest(limit: int = 10) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 50))
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT * FROM incidents
            WHERE status = 'open'
              AND NOT (COALESCE(severity, '') = 'info' AND COALESCE(event_class, '') IN ('', 'unknown'))
            ORDER BY
                CASE severity WHEN 'critical' THEN 1 WHEN 'error' THEN 2 WHEN 'warning' THEN 3 ELSE 4 END,
                last_seen DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [
        {
            "id": row["id"], "status": row["status"], "severity": row["severity"],
            "title": row["title"], "event_class": row["event_class"],
            "first_seen": row["first_seen"], "last_seen": row["last_seen"],
            "event_count": row["event_count"],
            "affected_nodes": safe_json_loads(row["affected_nodes"], []),
            "affected_services": safe_json_loads(row["affected_services"], []),
            "root_cause_candidates": safe_json_loads(row["root_cause_candidates"], []),
            "summary": row["summary"] or "",
            "probable_root_cause": row["probable_root_cause"] or "",
            "confidence": row["confidence"] or "",
            "last_analyzed_at": row["last_analyzed_at"] or "",
            "metadata": safe_json_loads(row["metadata"], {}),
        }
        for row in rows
    ]


def dedupe_incidents_for_digest(incidents_list: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str, str]] = set()
    output: list[dict[str, Any]] = []
    for item in incidents_list:
        key = (
            str(item.get("title") or ""), str(item.get("event_class") or ""),
            str(item.get("severity") or ""),
            ",".join(sorted(item.get("affected_services") or [])),
        )
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
    return output


def build_open_incidents_digest_prompt(incidents_list: list[dict[str, Any]]) -> str:
    payload = {"open_incidents": incidents_list}
    return f"""
You are a homelab SRE generating a concise digest of currently open incidents.

Output strict JSON only with this schema:

{{
  "overall_status": "healthy|warning|critical",
  "summary": "string",
  "top_issues": [
    {{
      "incident_id": 0,
      "title": "string",
      "severity": "string",
      "assessment": "string"
    }}
  ],
  "recommended_actions": ["string"]
}}

Rules:
- Be concise and operationally useful
- Prioritize service-impacting issues
- Use existing incident summaries and probable root causes if present
- Do not invent facts
- If all open incidents are low-value or informational, reflect that in the summary
- Keep recommended_actions to 3-5 items max

Input:
{json.dumps(payload, ensure_ascii=False, indent=2)}
""".strip()


def generate_open_incidents_digest(limit: int = 10, include_raw_response: bool = False) -> dict[str, Any]:
    incidents_list = dedupe_incidents_for_digest(fetch_open_incidents_for_digest(limit=limit * 3))[:limit]
    prompt = build_open_incidents_digest_prompt(incidents_list)
    result, raw_response = call_ollama(prompt)

    digest: dict[str, Any] = {
        "overall_status": str(result.get("overall_status") or "warning").strip().lower(),
        "summary": str(result.get("summary") or "").strip(),
        "top_issues": result.get("top_issues") if isinstance(result.get("top_issues"), list) else [],
        "recommended_actions": result.get("recommended_actions") if isinstance(result.get("recommended_actions"), list) else [],
        "source_incident_count": len(incidents_list),
        "source_incidents": incidents_list,
    }

    if digest["overall_status"] not in {"healthy", "warning", "critical"}:
        digest["overall_status"] = "warning"

    cleaned_top_issues = []
    for item in digest["top_issues"][:10]:
        if not isinstance(item, dict):
            continue
        cleaned_top_issues.append({
            "incident_id": item.get("incident_id"),
            "title": str(item.get("title") or "").strip(),
            "severity": str(item.get("severity") or "").strip(),
            "assessment": str(item.get("assessment") or "").strip(),
        })
    digest["top_issues"] = cleaned_top_issues
    digest["recommended_actions"] = [str(x).strip() for x in digest["recommended_actions"] if str(x).strip()][:5]

    if include_raw_response:
        digest["raw_response"] = raw_response
    return digest


def auto_close_false_positive(incident_id: int, confidence: str) -> None:
    now_iso = utcnow().isoformat()
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        incident = conn.execute(
            "SELECT id, title, event_class, primary_fingerprint FROM incidents WHERE id = ?",
            (incident_id,),
        ).fetchone()
        if not incident:
            return

        row = conn.execute(
            """
            SELECT message_template FROM events
            WHERE incident_id = ? AND message_template != ''
            GROUP BY message_template ORDER BY COUNT(*) DESC LIMIT 1
            """,
            (incident_id,),
        ).fetchone()
        pattern = template_to_suppress_pattern(row["message_template"]) if row else ""

        conn.execute("UPDATE incidents SET status = 'closed', updated_at = ? WHERE id = ?", (now_iso, incident_id))
        if pattern:
            try:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO suppress_rules
                        (match_type, canonical_fingerprint, match_host, match_pattern,
                         incident_title, event_class, reason, created_at)
                    VALUES ('message_regex', ?, '', ?, ?, ?, ?, ?)
                    """,
                    (incident["primary_fingerprint"] or "", pattern,
                     incident["title"] or "", incident["event_class"] or "",
                     f"auto: false_positive (confidence={confidence})", now_iso),
                )
            except sqlite3.IntegrityError:
                pass
        conn.commit()

    load_suppressed_fingerprints()
    print(
        f"[auto-close] incident #{incident_id} closed as false_positive"
        + (f", suppress rule created: {pattern!r}" if pattern else ""),
        flush=True,
    )


def analyze_missing_incidents(
    limit: int = 10, include_closed: bool = False, skip_info_unknown: bool = True,
) -> dict[str, Any]:
    limit = max(1, min(limit, 100))
    sql = "SELECT id, status, severity, event_class, title FROM incidents WHERE (last_analyzed_at IS NULL OR last_analyzed_at = '')"
    params: list[Any] = []

    if not include_closed:
        sql += " AND status = 'open'"
    if skip_info_unknown:
        sql += " AND NOT (COALESCE(severity, '') = 'info' AND COALESCE(event_class, '') IN ('', 'unknown'))"

    sql += " ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'error' THEN 2 WHEN 'warning' THEN 3 ELSE 4 END, last_seen DESC LIMIT ?"
    params.append(limit)

    with sqlite3.connect(config.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql, params).fetchall()

    processed = []
    errors = []

    for row in rows:
        incident_id = int(row["id"])
        try:
            result = analyze_incident_with_ollama(incident_id=incident_id, persist_summary=True, include_raw_response=False)
            root_cause = result["analysis"]["probable_root_cause"]
            confidence_val = result["analysis"]["confidence"]
            is_fp = result["analysis"].get("is_false_positive", False)

            if is_fp and root_cause in _FALSE_POSITIVE_LABELS and confidence_val in ("medium", "high"):
                if row["severity"] == "critical":
                    print(f"[auto-close] skipping critical incident #{incident_id}", flush=True)
                else:
                    try:
                        auto_close_false_positive(incident_id, confidence_val)
                    except Exception as e:
                        print(f"[auto-close] error for incident #{incident_id}: {e}", flush=True)

            processed.append({
                "incident_id": incident_id, "status": row["status"],
                "severity": row["severity"], "event_class": row["event_class"],
                "title": row["title"], "probable_root_cause": root_cause,
                "confidence": confidence_val,
            })
        except Exception as e:
            errors.append({"incident_id": incident_id, "title": row["title"], "error": str(e)})

    return {"ok": True, "processed_count": len(processed), "error_count": len(errors), "processed": processed, "errors": errors}
