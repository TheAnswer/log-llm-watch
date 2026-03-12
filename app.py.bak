#!/usr/bin/env python3
import asyncio
import hashlib
import json
import re
import sqlite3
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta, timezone
from functools import partial
from pathlib import Path
from typing import Any

import requests
import yaml
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Thread pool for offloading blocking DB/lock work from the async event loop
_THREAD_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="db")

BASE_DIR = Path("/opt/dozzle-llm-watch")
CONFIG_PATH = BASE_DIR / "config.yaml"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def load_config() -> dict[str, Any]:
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


CONFIG = load_config()
DB_PATH = CONFIG["storage"]["db_path"]

NODE_METADATA = CONFIG.get("node_metadata", {})
SERVICE_METADATA = CONFIG.get("service_metadata", {})

# Pre-compile ignore patterns once at startup
_IGNORE_PATTERNS: list[re.Pattern] = [
    re.compile(p) for p in CONFIG["filters"]["ignore_message_regex"]
]

# Serialise all Ollama calls — prevents concurrent requests to the local model
_OLLAMA_LOCK = threading.Lock()

# LLM call statistics — protected by _OLLAMA_LOCK (only mutated inside call_ollama*)
_LLM_STATS: dict[str, float | int] = {
    "total_calls": 0,
    "total_errors": 0,
    "total_seconds": 0.0,
    "last_call_at": "",
    "last_duration_seconds": 0.0,
}

# Serialise incident SELECT+INSERT to prevent duplicate creation under concurrent ingest
_INCIDENT_LOCK = threading.Lock()

# In-memory suppression caches — all O(1) or O(n-patterns) lookup per event
_SUPPRESS_FP: set[str] = set()                  # match_type='fingerprint'
_SUPPRESS_EC: set[str] = set()                  # match_type='event_class'
_SUPPRESS_EC_HOST: set[tuple[str, str]] = set() # match_type='event_class_host'
_SUPPRESS_REGEX: list[tuple[int, re.Pattern]] = []  # (rule_id, compiled pattern)
_SUPPRESS_HITS: dict[int, int] = {}               # rule_id → in-memory hit count delta
_SUPPRESS_LOCK = threading.Lock()

# Cooldown cache for ignore logging — avoid flooding the journal
_IGNORE_LOG_SEEN: dict[str, float] = {}
_IGNORE_LOG_LOCK = threading.Lock()
_IGNORE_LOG_COOLDOWN_SECS = 60


def _log_ignored(container: str, host: str, message: str, reason: str, elapsed_ms: float = 0.0) -> None:
    key = f"{container}|{host}|{message[:80]}"
    now = time.monotonic()
    with _IGNORE_LOG_LOCK:
        if now - _IGNORE_LOG_SEEN.get(key, 0) < _IGNORE_LOG_COOLDOWN_SECS:
            return
        _IGNORE_LOG_SEEN[key] = now
    print(f"[ignore] {reason} host={host!r} container={container!r} elapsed={elapsed_ms:.1f}ms msg={message[:120]!r}", flush=True)


def _load_suppressed_fingerprints() -> None:
    """Reload all in-memory suppression caches from the DB."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT id, match_type, canonical_fingerprint, event_class, match_host, match_pattern FROM suppress_rules"
            ).fetchall()
        fp: set[str] = set()
        ec: set[str] = set()
        ec_host: set[tuple[str, str]] = set()
        regex: list[tuple[int, re.Pattern]] = []
        for row in rows:
            mt = row["match_type"]
            if mt == "fingerprint":
                fp.add(row["canonical_fingerprint"])
            elif mt == "event_class":
                ec.add(row["event_class"])
            elif mt == "event_class_host":
                ec_host.add((row["event_class"], row["match_host"]))
            elif mt == "message_regex":
                try:
                    regex.append((row["id"], re.compile(row["match_pattern"])))
                except re.error as e:
                    print(f"[suppress] Invalid regex in rule: {row['match_pattern']!r}: {e}", flush=True)
        with _SUPPRESS_LOCK:
            _SUPPRESS_FP.clear(); _SUPPRESS_FP.update(fp)
            _SUPPRESS_EC.clear(); _SUPPRESS_EC.update(ec)
            _SUPPRESS_EC_HOST.clear(); _SUPPRESS_EC_HOST.update(ec_host)
            _SUPPRESS_REGEX.clear(); _SUPPRESS_REGEX.extend(regex)
    except Exception as e:
        print(f"[suppress] Failed to load suppress rules: {e}", flush=True)


def _flush_suppress_hits() -> None:
    """Flush in-memory hit count deltas to the DB."""
    with _SUPPRESS_LOCK:
        if not _SUPPRESS_HITS:
            return
        deltas = dict(_SUPPRESS_HITS)
        _SUPPRESS_HITS.clear()
    try:
        with sqlite3.connect(DB_PATH) as conn:
            for rule_id, count in deltas.items():
                conn.execute(
                    "UPDATE suppress_rules SET hit_count = hit_count + ? WHERE id = ?",
                    (count, rule_id),
                )
            conn.commit()
    except Exception as e:
        print(f"[suppress] Failed to flush hit counts: {e}", flush=True)


def extract_inner_message(raw: str) -> str:
    """If raw looks like an nxlog JSON wrapper, extract just the inner 'message' field value.
    Works on both raw messages (valid JSON) and templates (with <placeholder> tokens)."""
    trimmed = raw.strip()
    if not trimmed.startswith("{"):
        return trimmed
    # Try JSON parse first (works on raw messages)
    try:
        parsed = json.loads(trimmed)
        if isinstance(parsed.get("message"), str) and parsed["message"]:
            return parsed["message"]
    except Exception:
        pass
    # Fall back to regex extraction (works on templates with <placeholder> tokens)
    m = re.search(r'"message":"([\s\S]+?)","(?:source|host|container|stream|level)"', trimmed)
    if m:
        return m.group(1)
    return trimmed


def template_to_suppress_pattern(template: str) -> str:
    """Convert a normalize_message() template to a (?i) regex, same logic as the dashboard.
    Extracts inner message content from nxlog JSON wrappers first for simpler patterns."""
    content = extract_inner_message(template)
    parts = re.split(r"(<[^>]+>)", content)
    result = []
    for part in parts:
        if re.match(r"^<[^>]+>$", part):
            result.append(r"\S+")
        else:
            result.append(re.escape(part))
    return "(?i)" + "".join(result)


def _llm_generate_suppress_regex(groups: list[dict[str, Any]]) -> dict[str, str]:
    """Ask the LLM to generate a regex for each ignored group.

    Returns a dict mapping fingerprint -> regex pattern string.
    Falls back to empty dict on error (callers use template_to_suppress_pattern).
    """
    if not groups:
        return {}

    payload = []
    for g in groups:
        examples = g.get("examples", [])
        inner_examples = [extract_inner_message(e) for e in examples[:5]]
        payload.append({
            "fingerprint": g["fingerprint"],
            "container": g.get("container", ""),
            "template": g.get("message_template", ""),
            "example_messages": inner_examples,
        })

    prompt = f"""Generate a case-insensitive Python regex for each log message group below.
The regex will be tested against the inner message content (not the JSON wrapper).
Whitespace in the message is normalized to single spaces before matching.

Rules:
- The regex must match ALL example messages in the group and future similar messages.
- Use \\S+ for variable tokens (timestamps, IPs, PIDs, hex IDs, UUIDs, numbers, ports).
- Use literal text for the fixed parts of the message.
- Do NOT use .* or .+? — these cause catastrophic backtracking. Use \\S+ instead.
- Do NOT anchor with ^ or $ — the regex is used with re.search().
- Keep the pattern as simple and short as possible.
- Prefix each pattern with (?i) for case-insensitive matching.
- Return strict JSON only: a list of objects with "fingerprint" and "regex" keys.

Input groups:
{json.dumps(payload, ensure_ascii=False, indent=2)}

Output format:
[
  {{"fingerprint": "abc123", "regex": "(?i)example \\\\S+ pattern"}}
]
"""

    try:
        result, _ = call_ollama(prompt)
        # result should be a list or dict with a list
        items = result if isinstance(result, list) else result.get("items", result.get("patterns", []))
        return {
            item["fingerprint"]: item["regex"]
            for item in items
            if isinstance(item, dict) and "fingerprint" in item and "regex" in item
        }
    except Exception as e:
        print(f"[auto-suppress] LLM regex generation failed, falling back to template: {e}", flush=True)
        return {}


def _validate_suppress_regex(pattern: str, examples: list[str]) -> bool:
    """Check that a regex compiles and matches all provided examples."""
    try:
        compiled = re.compile(pattern)
    except re.error:
        return False
    for ex in examples:
        normalized = re.sub(r"\s+", " ", extract_inner_message(ex))
        if not compiled.search(normalized):
            return False
    return True


def _auto_suppress_ignored(groups_by_fp: dict[str, dict[str, Any]], ignored_fps: list[str]) -> None:
    """Create message_regex suppress rules for groups the LLM rated as ignore."""
    if not ignored_fps:
        return

    # Collect groups that need regex patterns
    groups_to_suppress = []
    for fp in ignored_fps:
        g = groups_by_fp.get(fp)
        if g and (g.get("message_template") or g.get("examples")):
            groups_to_suppress.append(g)

    if not groups_to_suppress:
        return

    # Ask the LLM to generate regexes for all groups in one call
    llm_patterns = _llm_generate_suppress_regex(groups_to_suppress)

    now_iso = utcnow().isoformat()
    created = 0
    for fp in ignored_fps:
        g = groups_by_fp.get(fp)
        if not g:
            continue
        template = g.get("message_template") or ""
        examples = g.get("examples", [])
        if not template and not examples:
            continue

        # Try LLM-generated pattern first, validate it against examples
        pattern = llm_patterns.get(fp, "")
        source = "llm"
        if pattern and examples:
            if not _validate_suppress_regex(pattern, examples):
                print(
                    f"[auto-suppress] LLM regex failed validation for fp={fp!r}, "
                    f"falling back to template. Pattern: {pattern!r}",
                    flush=True,
                )
                pattern = ""

        # Fall back to mechanical template conversion
        if not pattern and template:
            pattern = template_to_suppress_pattern(template)
            source = "template"

        if not pattern:
            continue

        try:
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO suppress_rules
                        (match_type, canonical_fingerprint, match_host, match_pattern,
                         incident_title, event_class, reason, created_at)
                    VALUES (?, ?, '', ?, ?, ?, ?, ?)
                    """,
                    (
                        "message_regex",
                        fp,
                        pattern,
                        g.get("container", ""),
                        g.get("event_class", ""),
                        f"auto: llm-ignore ({source})",
                        now_iso,
                    ),
                )
                conn.commit()
            created += 1
            print(
                f"[auto-suppress] message_regex ({source}) for container={g.get('container')!r}"
                f" pattern={pattern!r}",
                flush=True,
            )
        except Exception as e:
            print(f"[auto-suppress] failed to insert rule for fp={fp!r}: {e}", flush=True)
    if created:
        _load_suppressed_fingerprints()


def _run_backfill() -> None:
    try:
        while True:
            n = backfill_existing_events(limit=500)
            if n == 0:
                break
            print(f"[startup] backfilled {n} historical events", flush=True)
    except Exception as e:
        print(f"[startup] backfill error: {e}", flush=True)


def _check_ollama_health() -> None:
    ollama_url = CONFIG["ollama"]["url"]
    try:
        resp = requests.get(f"{ollama_url}/api/tags", timeout=5)
        if resp.status_code == 200:
            print(f"[startup] Ollama OK at {ollama_url}", flush=True)
        else:
            print(f"[startup] WARNING: Ollama at {ollama_url} returned HTTP {resp.status_code}", flush=True)
    except Exception as e:
        print(f"[startup] WARNING: Ollama unreachable at {ollama_url}: {e}", flush=True)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    _load_suppressed_fingerprints()
    _check_ollama_health()
    threading.Thread(target=_run_backfill, daemon=True).start()
    threading.Thread(target=analysis_loop, daemon=True).start()
    yield


app = FastAPI(title="Homelab LLM Watch", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    t0 = time.monotonic()
    response = await call_next(request)
    elapsed_ms = (time.monotonic() - t0) * 1000
    print(
        f"[http] {request.method} {request.url.path} -> {response.status_code} ({elapsed_ms:.1f}ms)",
        flush=True,
    )
    return response

def init_db() -> None:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA busy_timeout=5000;")

        def column_exists(table: str, column: str) -> bool:
            rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
            return any(row[1] == column for row in rows)

        def add_column_if_missing(table: str, column: str, col_type_sql: str) -> None:
            if not column_exists(table, column):
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type_sql}")

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

        add_column_if_missing("events", "ts", "TEXT")
        add_column_if_missing("events", "host_type", "TEXT")
        add_column_if_missing("events", "service", "TEXT")
        add_column_if_missing("events", "app_stack", "TEXT")
        add_column_if_missing("events", "event_class", "TEXT")
        add_column_if_missing("events", "dependency", "TEXT")
        add_column_if_missing("events", "canonical_fingerprint", "TEXT")
        add_column_if_missing("events", "incident_id", "INTEGER")
        add_column_if_missing("events", "noise_score", "REAL DEFAULT 0")
        add_column_if_missing("events", "severity_norm", "TEXT")
        add_column_if_missing("events", "message_template", "TEXT")
        add_column_if_missing("events", "labels", "TEXT DEFAULT '{}'")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                status TEXT NOT NULL DEFAULT 'open',
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                event_class TEXT,
                primary_fingerprint TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                event_count INTEGER NOT NULL DEFAULT 0,
                affected_nodes TEXT NOT NULL DEFAULT '[]',
                affected_services TEXT NOT NULL DEFAULT '[]',
                root_cause_candidates TEXT NOT NULL DEFAULT '[]',
                summary TEXT,
                metadata TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )

        add_column_if_missing("incidents", "analysis_json", "TEXT")
        add_column_if_missing("incidents", "probable_root_cause", "TEXT")
        add_column_if_missing("incidents", "confidence", "TEXT")
        add_column_if_missing("incidents", "last_analyzed_at", "TEXT")

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_processed_created ON events(processed, created_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_fingerprint ON events(fingerprint)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_canonical_fp ON events(canonical_fingerprint)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_event_class_ts ON events(event_class, ts)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_host_ts ON events(host, ts)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_container_ts ON events(container, ts)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_incident_id ON events(incident_id)"
        )

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_incidents_status_last_seen ON incidents(status, last_seen)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_incidents_primary_fp ON incidents(primary_fingerprint)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_incidents_event_class_last_seen ON incidents(event_class, last_seen)"
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

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ntfy_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sent_at TEXT NOT NULL,
                title TEXT NOT NULL DEFAULT '',
                priority TEXT NOT NULL DEFAULT 'default',
                source TEXT NOT NULL DEFAULT '',
                message TEXT NOT NULL DEFAULT ''
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS llm_call_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                called_at TEXT NOT NULL,
                duration_seconds REAL NOT NULL,
                error INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_llm_call_log_called_at ON llm_call_log(called_at)"
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS suppress_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                match_type TEXT NOT NULL DEFAULT 'fingerprint',
                canonical_fingerprint TEXT NOT NULL DEFAULT '',
                match_host TEXT NOT NULL DEFAULT '',
                incident_title TEXT NOT NULL DEFAULT '',
                event_class TEXT NOT NULL DEFAULT '',
                reason TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            )
            """
        )
        add_column_if_missing("suppress_rules", "match_type", "TEXT NOT NULL DEFAULT 'fingerprint'")
        add_column_if_missing("suppress_rules", "match_host", "TEXT NOT NULL DEFAULT ''")
        add_column_if_missing("suppress_rules", "match_pattern", "TEXT NOT NULL DEFAULT ''")
        add_column_if_missing("suppress_rules", "hit_count", "INTEGER NOT NULL DEFAULT 0")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS llm_noise_fingerprints (
                fingerprint TEXT PRIMARY KEY,
                suppressed_until TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("PRAGMA busy_timeout=5000;")
        yield conn
    finally:
        conn.close()


def current_system_time_str() -> str:
    return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def normalize_message(msg: str) -> str:
    msg = re.sub(r"\b\d{4}-\d{2}-\d{2}[T ][0-9:\.\+\-Z]+\b", "<ts>", msg)
    msg = re.sub(r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\b", "<month>", msg)
    msg = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<ip>", msg)
    msg = re.sub(r":\d{2,5}\b", ":<port>", msg)
    msg = re.sub(r"\b[0-9a-f]{8}-[0-9a-f-]{27,}\b", "<uuid>", msg, flags=re.IGNORECASE)
    msg = re.sub(r"\b[0-9a-f]{8,}\b", "<hex>", msg, flags=re.IGNORECASE)
    msg = re.sub(r"\b\d+(ms|s|m|h)\b", "<duration>", msg, flags=re.IGNORECASE)
    msg = re.sub(r"\b\d+(\.\d+)?%\b", "<pct>", msg)
    msg = re.sub(r"\b\d+\b", "<num>", msg)
    msg = re.sub(r"\s+", " ", msg).strip()
    return msg[:500]


def stable_hash(text: str, length: int = 20) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:length]


def safe_json_loads(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except Exception:
        return default


def infer_host_type(host: str) -> str:
    meta = NODE_METADATA.get((host or "").lower(), {})
    return str(meta.get("host_type") or meta.get("type") or "")


def infer_service(container: str) -> str:
    return container or ""


def infer_app_stack(container: str) -> str:
    meta = SERVICE_METADATA.get(container or "", {})
    return str(meta.get("app_stack") or "")


def infer_labels(host: str, container: str) -> dict[str, Any]:
    labels: dict[str, Any] = {}
    node_meta = NODE_METADATA.get((host or "").lower(), {})
    svc_meta = SERVICE_METADATA.get(container or "")
    if node_meta:
        labels["node_meta"] = node_meta
    if svc_meta:
        labels["service_meta"] = svc_meta
    return labels


def normalize_severity(level: str, message: str) -> str:
    lvl = (level or "").strip().lower()
    m = message.lower()

    if lvl in {"critical", "crit", "fatal"}:
        return "critical"
    if lvl in {"error", "err"}:
        return "error"
    if lvl in {"warning", "warn"}:
        return "warning"
    if lvl in {"info", "information"}:
        return "info"

    if any(x in m for x in ["panic", "fatal", "segfault", "out of memory", "oom", "no space left"]):
        return "critical"
    if any(x in m for x in ["error", "exception", "traceback", "failed", "connection refused", "database is locked"]):
        return "error"
    if "warn" in m:
        return "warning"

    return "info"


def classify_event(message: str, source: str, container: str, stream: str) -> tuple[str, str]:
    m = message.lower()
    c = (container or "").lower()
    s = (stream or "").lower()
    src = (source or "").lower()

    if "usbhid-ups" in m and "input/output error" in m:
        return "ups_usb_comm_error", "ups"
    if "temporary failure in name resolution" in m or "no such host" in m:
        return "dns_failure", "dns"
    if "connection refused" in m:
        return "connect_refused", "network"
    if "no route to host" in m:
        return "routing_failure", "network"
    if "tls" in m or "x509" in m or "certificate" in m:
        return "tls_or_cert_issue", "tls"
    if "database is locked" in m:
        return "database_locked", "storage"
    if "no space left" in m:
        return "no_space_left", "storage"
    if "out of memory" in m or "killed process" in m or re.search(r"\boom\b", m):
        return "oom_kill", "memory"
    if "bad gateway" in m or ("upstream" in m and "failed" in m):
        return "proxy_upstream_failure", "proxy"
    if src == "windows-event" and "security" in c and "4625" in s:
        return "failed_logon", "auth"
    if "failed password" in m or "authentication failed" in m:
        return "auth_failure", "auth"
    if "timeout" in m:
        return "timeout", "network"
    if src == "windows-event" and "eventid=4266" in s:
        return "windows_udp_ephemeral_port_exhaustion", "network"

    return "unknown", ""


def fingerprint_for_event(event: dict[str, str]) -> str:
    source = event.get("source", "")
    host = event.get("host", "")
    container = event.get("container", "")
    stream = event.get("stream", "")
    message = event.get("message", "")
    return stable_hash(f"{source}::{host}::{container}::{stream}::{normalize_message(message)}")


def canonical_fingerprint_for_event(event: dict[str, str]) -> str:
    event_class = event.get("event_class", "") or "unknown"
    dependency = event.get("dependency", "") or ""
    template = event.get("message_template", "") or normalize_message(event.get("message", ""))
    return stable_hash(f"{event_class}::{dependency}::{template}")


def enrich_event(event: dict[str, str]) -> dict[str, str]:
    enriched = dict(event)
    enriched["host"] = (enriched.get("host", "") or "").strip().lower()
    enriched["ts"] = utcnow().isoformat()
    enriched["service"] = infer_service(enriched.get("container", ""))
    enriched["host_type"] = infer_host_type(enriched.get("host", ""))
    enriched["app_stack"] = infer_app_stack(enriched.get("container", ""))
    enriched["message_template"] = normalize_message(enriched.get("message", ""))

    event_class, dependency = classify_event(
        enriched.get("message", ""),
        enriched.get("source", ""),
        enriched.get("container", ""),
        enriched.get("stream", ""),
    )
    enriched["event_class"] = event_class
    enriched["dependency"] = dependency
    enriched["severity_norm"] = normalize_severity(
        enriched.get("level", ""),
        enriched.get("message", ""),
    )
    enriched["labels"] = json.dumps(
        infer_labels(enriched.get("host", ""), enriched.get("container", "")),
        ensure_ascii=False,
    )
    enriched["fingerprint"] = fingerprint_for_event(enriched)
    enriched["canonical_fingerprint"] = canonical_fingerprint_for_event(enriched)
    return enriched


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
        "udp_port_exhaustion",
        "socket_leak_or_high_udp_churn",
        "application_network_burst",
        ],
        "unknown": [],
    }
    return mapping.get(event_class, [])


def attach_or_create_incident(conn: sqlite3.Connection, event: dict[str, str]) -> int | None:
    # Skip incident creation/update for suppressed events
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
    window_minutes = int(CONFIG.get("incidents", {}).get("open_window_minutes", 10))
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
            SET last_seen = ?,
                event_count = ?,
                affected_nodes = ?,
                affected_services = ?,
                root_cause_candidates = ?,
                metadata = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                event["ts"],
                int(row[3]) + 1,
                json.dumps(sorted(affected_nodes), ensure_ascii=False),
                json.dumps(sorted(affected_services), ensure_ascii=False),
                json.dumps(sorted(root_causes), ensure_ascii=False),
                json.dumps(metadata, ensure_ascii=False),
                now_iso,
                row[0],
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
            status,
            severity,
            title,
            event_class,
            primary_fingerprint,
            first_seen,
            last_seen,
            event_count,
            affected_nodes,
            affected_services,
            root_cause_candidates,
            summary,
            metadata,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "open",
            severity,
            incident_title_for_event(event),
            event.get("event_class", ""),
            event["canonical_fingerprint"],
            event["ts"],
            event["ts"],
            1,
            json.dumps(new_affected_nodes, ensure_ascii=False),
            json.dumps(new_affected_services, ensure_ascii=False),
            json.dumps(root_causes, ensure_ascii=False),
            "",
            json.dumps(metadata, ensure_ascii=False),
            now_iso,
            now_iso,
        ),
    )
    return int(cur.lastrowid)


def close_stale_incidents() -> None:
    cfg = CONFIG.get("incidents", {})
    stale_minutes = int(cfg.get("close_after_minutes", 30))
    cutoff = (utcnow() - timedelta(minutes=stale_minutes)).isoformat()
    with db() as conn:
        conn.execute(
            """
            UPDATE incidents
            SET status = 'closed',
                updated_at = ?
            WHERE status = 'open'
              AND last_seen < ?
            """,
            (utcnow().isoformat(), cutoff),
        )
        conn.commit()


def should_ignore(message: str) -> bool:
    if any(p.search(message) for p in _IGNORE_PATTERNS):
        return True
    # Normalize whitespace before testing suppress patterns —
    # normalize_message() collapses multi-space but raw messages may have extra whitespace.
    normalized = re.sub(r"\s+", " ", message)
    with _SUPPRESS_LOCK:
        for rule_id, pat in _SUPPRESS_REGEX:
            if pat.search(normalized):
                _SUPPRESS_HITS[rule_id] = _SUPPRESS_HITS.get(rule_id, 0) + 1
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
                        host = m.group(1).strip().lower()

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


def extract_syslog_event(payload: Any) -> dict[str, str]:
    source = "syslog"
    host = ""
    container = "syslog"
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

    host = str(payload.get("host") or payload.get("hostname") or "").lower()
    program = payload.get("program") or payload.get("appname") or payload.get("tag") or "syslog"
    container = str(program)
    message = str(payload.get("message") or payload.get("msg") or "").strip()
    lowered = message.lower()

    if any(x in lowered for x in ["panic", "fatal", "segfault", "oom", "out of memory"]):
        level = "critical"
    elif any(x in lowered for x in ["error", "failed", "exception"]):
        level = "error"
    elif "warn" in lowered:
        level = "warning"

    return {
        "source": source,
        "host": host,
        "container": container,
        "stream": "",
        "level": level,
        "message": message,
    }


def store_event(payload: Any, event: dict[str, str]) -> str:
    enriched = enrich_event(event)

    with _INCIDENT_LOCK, db() as conn:
        incident_id = attach_or_create_incident(conn, enriched)
        conn.execute(
            """
            INSERT INTO events (
                created_at,
                processed,
                source,
                host,
                container,
                stream,
                level,
                message,
                raw_json,
                fingerprint,
                ts,
                host_type,
                service,
                app_stack,
                event_class,
                dependency,
                canonical_fingerprint,
                incident_id,
                severity_norm,
                message_template,
                labels
            )
            VALUES (?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                utcnow().isoformat(),
                enriched["source"],
                enriched["host"],
                enriched["container"],
                enriched["stream"],
                enriched["level"],
                enriched["message"],
                json.dumps(payload, ensure_ascii=False),
                enriched["fingerprint"],
                enriched["ts"],
                enriched["host_type"],
                enriched["service"],
                enriched["app_stack"],
                enriched["event_class"],
                enriched["dependency"],
                enriched["canonical_fingerprint"],
                incident_id,
                enriched["severity_norm"],
                enriched["message_template"],
                enriched["labels"],
            ),
        )
        conn.commit()

    return enriched["fingerprint"]


def backfill_existing_events(limit: int = 500) -> int:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5000;")
        rows = conn.execute(
            """
            SELECT *
            FROM events
            WHERE canonical_fingerprint IS NULL
               OR canonical_fingerprint = ''
               OR event_class IS NULL
               OR event_class = ''
               OR message_template IS NULL
               OR message_template = ''
            ORDER BY id ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        if not rows:
            return 0

        updated = 0
        for row in rows:
            event = {
                "source": row["source"] or "",
                "host": row["host"] or "",
                "container": row["container"] or "",
                "stream": row["stream"] or "",
                "level": row["level"] or "",
                "message": row["message"] or "",
            }
            enriched = enrich_event(event)
            enriched["ts"] = row["ts"] or row["created_at"] or enriched["ts"]
            incident_id = attach_or_create_incident(conn, enriched)

            conn.execute(
                """
                UPDATE events
                SET ts = ?,
                    host_type = ?,
                    service = ?,
                    app_stack = ?,
                    event_class = ?,
                    dependency = ?,
                    canonical_fingerprint = ?,
                    incident_id = ?,
                    severity_norm = ?,
                    message_template = ?,
                    labels = ?,
                    fingerprint = ?
                WHERE id = ?
                """,
                (
                    enriched["ts"],
                    enriched["host_type"],
                    enriched["service"],
                    enriched["app_stack"],
                    enriched["event_class"],
                    enriched["dependency"],
                    enriched["canonical_fingerprint"],
                    incident_id,
                    enriched["severity_norm"],
                    enriched["message_template"],
                    enriched["labels"],
                    row["fingerprint"] or enriched["fingerprint"],
                    row["id"],
                ),
            )
            updated += 1

        conn.commit()
        return updated


@app.get("/healthz")
def healthz():
    return {"ok": True}


def _ingest_event(payload: Any, event: dict[str, str]) -> dict[str, Any]:
    """Run all blocking work (ignore check, DB write) off the async event loop."""
    t0 = time.monotonic()
    if should_ignore(event["message"]):
        _log_ignored(event["container"], event["host"], event["message"],
                     "regex/suppress", (time.monotonic() - t0) * 1000)
        return {"stored": False, "reason": "ignored"}

    fp = store_event(payload, event)
    return {
        "stored": True,
        "source": event["source"],
        "container": event["container"],
        "fingerprint": fp,
    }


@app.post("/dozzle")
async def dozzle_webhook(request: Request):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Expected JSON body")

    event = extract_dozzle_event(payload)
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(_THREAD_POOL, partial(_ingest_event, payload, event))
    return JSONResponse(result)


@app.post("/windows")
async def windows_webhook(request: Request):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Expected JSON body")

    event = extract_windows_event(payload)
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(_THREAD_POOL, partial(_ingest_event, payload, event))
    return JSONResponse(result)


@app.post("/syslog")
async def syslog_webhook(request: Request):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Expected JSON body")

    event = extract_syslog_event(payload)
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(_THREAD_POOL, partial(_ingest_event, payload, event))
    return JSONResponse(result, headers={"Connection": "close"})


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
            "message_template": "",
            "event_class": "",
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


def _record_llm_call(duration: float, error: bool = False) -> None:
    """Update in-memory LLM stats and persist to DB."""
    _LLM_STATS["total_calls"] += 1
    if error:
        _LLM_STATS["total_errors"] += 1
    _LLM_STATS["total_seconds"] += duration
    _LLM_STATS["last_call_at"] = utcnow().isoformat()
    _LLM_STATS["last_duration_seconds"] = duration
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO llm_call_log (called_at, duration_seconds, error) VALUES (?, ?, ?)",
                (utcnow().isoformat(), round(duration, 3), 1 if error else 0),
            )
            conn.commit()
    except Exception as e:
        print(f"[llm_stats] Failed to log call: {e}", flush=True)


def call_ollama(prompt: str) -> tuple[dict[str, Any], str]:
    url = CONFIG["ollama"]["url"].rstrip("/") + "/api/generate"
    body = {
        "model": CONFIG["ollama"]["model"],
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.1,
            "num_ctx": 32768,
        },
    }

    t0 = time.monotonic()
    try:
        with _OLLAMA_LOCK:
            r = requests.post(url, json=body, timeout=CONFIG["ollama"]["timeout_seconds"])
        r.raise_for_status()
        data = r.json()

        if data.get("done_reason") == "length":
            raise ValueError("Ollama response truncated (hit context limit). Consider reducing prompt size or increasing num_ctx.")

        raw_response = (data.get("response") or "").strip()
        raw_thinking = (data.get("thinking") or "").strip()

        candidate = raw_response or raw_thinking

        if not candidate:
            raise ValueError(f"Ollama returned empty response and empty thinking. Full payload: {data!r}")

        cleaned = candidate

        try:
            result = json.loads(cleaned), cleaned
            _record_llm_call(time.monotonic() - t0)
            return result
        except json.JSONDecodeError:
            pass

        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```[a-zA-Z0-9_-]*\n?", "", cleaned)
            cleaned = re.sub(r"\n?```$", "", cleaned).strip()

        try:
            result = json.loads(cleaned), candidate
            _record_llm_call(time.monotonic() - t0)
            return result
        except json.JSONDecodeError:
            pass

        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start != -1 and end != -1 and end > start:
            extracted = cleaned[start:end + 1]
            try:
                result = json.loads(extracted), candidate
                _record_llm_call(time.monotonic() - t0)
                return result
            except json.JSONDecodeError:
                pass

        raise ValueError(f"Could not parse Ollama JSON response. Candidate: {candidate!r}")
    except Exception:
        _record_llm_call(time.monotonic() - t0, error=True)
        raise


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

    t0 = time.monotonic()
    try:
        with _OLLAMA_LOCK:
            r = requests.post(url, json=body, timeout=CONFIG["ollama"]["timeout_seconds"])
        r.raise_for_status()
        data = r.json()

        raw_response = (data.get("response") or "").strip()
        raw_thinking = (data.get("thinking") or "").strip()

        text = raw_response or raw_thinking
        if not text:
            raise ValueError(f"Ollama returned empty response and empty thinking. Full payload: {data!r}")

        _record_llm_call(time.monotonic() - t0)
        return text
    except Exception:
        _record_llm_call(time.monotonic() - t0, error=True)
        raise


def send_ntfy(message: str, priority: str = "default", source: str = "analysis") -> None:
    url = CONFIG["notify"]["ntfy_url"]
    title = CONFIG["notify"]["title"]
    headers = {
        "Title": title,
        "Priority": priority,
        "Tags": "warning,robot_face",
    }
    r = requests.post(url, data=message.encode("utf-8"), headers=headers, timeout=30)
    if not r.ok:
        raise RuntimeError(f"ntfy error {r.status_code}: {r.text}")
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO ntfy_log (sent_at, title, priority, source, message) VALUES (?, ?, ?, ?, ?)",
                (utcnow().isoformat(), title, priority, source, message[:4000]),
            )
            conn.commit()
    except Exception as e:
        print(f"[ntfy] Failed to log notification: {e}", flush=True)


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

    all_ids = [row["id"] for row in rows]
    groups = group_events(rows)
    groups_by_fp = {g["fingerprint"]: g for g in groups}
    prompt = build_prompt(groups)

    try:
        result, raw_response = call_ollama(prompt)
        store_analysis_run(
            prompt=prompt,
            raw_response=raw_response,
            parsed_result=result,
            event_count=len(all_ids),
        )
    except Exception as e:
        store_analysis_run(
            prompt=prompt,
            raw_response=f"ERROR: {e}",
            parsed_result=None,
            event_count=len(all_ids),
        )
        raise

    all_findings = result.get("findings", [])
    findings = [f for f in all_findings if f.get("severity") in {"low", "medium", "high"}]

    # Auto-create message_regex suppress rules for groups the LLM rated as ignore
    ignored_fps = [f["fingerprint"] for f in all_findings if f.get("severity") == "ignore" and f.get("fingerprint")]
    _auto_suppress_ignored(groups_by_fp, ignored_fps)

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
            _flush_suppress_hits()
        except Exception as e:
            print(f"[analysis_loop] flush suppress hits error: {e}", flush=True)

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

    send_ntfy(message, priority=priority, source="daily_report")
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
        send_ntfy(message, priority="default", source="weekly_report")
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
    send_ntfy(message, priority=priority, source="weekly_report")

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

        cur.execute("DELETE FROM llm_call_log WHERE called_at < ?", (analysis_runs_cutoff,))
        deleted_llm_calls = cur.rowcount

        conn.commit()

    print(
        "[cleanup] deleted "
        f"events={deleted_events} "
        f"daily_runs={deleted_daily} "
        f"weekly_runs={deleted_weekly} "
        f"housekeeping_runs={deleted_housekeeping} "
        f"analysis_runs={deleted_analysis_runs} "
        f"llm_calls={deleted_llm_calls}",
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


def build_incident_context(
    incident_id: int,
    event_limit: int = 20,
    nearby_limit: int = 100,
    similar_limit: int = 5,
    minutes_before: int = 2,
    minutes_after: int = 10,
) -> dict[str, Any]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        incident = conn.execute(
            "SELECT * FROM incidents WHERE id = ?",
            (incident_id,),
        ).fetchone()
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        incident_obj = {
            "id": incident["id"],
            "status": incident["status"],
            "severity": incident["severity"],
            "title": incident["title"],
            "event_class": incident["event_class"],
            "primary_fingerprint": incident["primary_fingerprint"],
            "first_seen": incident["first_seen"],
            "last_seen": incident["last_seen"],
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
            FROM events
            WHERE incident_id = ?
            ORDER BY ts ASC, id ASC
            LIMIT ?
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
            FROM events
            WHERE ts >= ? AND ts <= ?
            ORDER BY ts ASC, id ASC
            LIMIT ?
            """,
            (window_start, window_end, max(1, min(nearby_limit, 500))),
        ).fetchall()

        similar_cutoff = (utcnow() - timedelta(days=90)).isoformat()
        similar_incidents = conn.execute(
            """
            SELECT *
            FROM incidents
            WHERE primary_fingerprint = ?
              AND id != ?
              AND last_seen >= ?
            ORDER BY last_seen DESC
            LIMIT ?
            """,
            (
                incident["primary_fingerprint"],
                incident_id,
                similar_cutoff,
                max(1, min(similar_limit, 50)),
            ),
        ).fetchall()

    return {
        "incident": incident_obj,
        "representative_events": [dict(row) for row in representative_events],
        "nearby_window": {
            "start": window_start,
            "end": window_end,
            "minutes_before": minutes_before,
            "minutes_after": minutes_after,
        },
        "nearby_events": [dict(row) for row in nearby_events],
        "similar_incidents": [
            {
                "id": row["id"],
                "status": row["status"],
                "severity": row["severity"],
                "title": row["title"],
                "event_class": row["event_class"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
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
    incident_id: int,
    event_limit: int = 20,
    nearby_limit: int = 100,
    similar_limit: int = 5,
    minutes_before: int = 2,
    minutes_after: int = 10,
    exclude_info: bool = True,
    exclude_unknown: bool = True,
    exclude_noise: bool = True,
    exclude_same_incident_from_nearby: bool = True,
) -> dict[str, Any]:
    base = build_incident_context(
        incident_id=incident_id,
        event_limit=event_limit,
        nearby_limit=nearby_limit,
        similar_limit=similar_limit,
        minutes_before=minutes_before,
        minutes_after=minutes_after,
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
            host = row.get("host") or ""
            severity = row.get("severity_norm") or ""
            event_class = row.get("event_class") or ""
            source = row.get("source") or ""

            by_host[host] = by_host.get(host, 0) + 1
            by_severity[severity] = by_severity.get(severity, 0) + 1
            by_event_class[event_class] = by_event_class.get(event_class, 0) + 1
            by_source[source] = by_source.get(source, 0) + 1

        def sort_dict(d: dict[str, int]) -> dict[str, int]:
            return dict(sorted(d.items(), key=lambda kv: (-kv[1], kv[0])))

        return {
            "total": len(rows),
            "by_host": sort_dict(by_host),
            "by_severity": sort_dict(by_severity),
            "by_event_class": sort_dict(by_event_class),
            "by_source": sort_dict(by_source),
        }

    base["nearby_events_filtered"] = filtered_nearby
    base["nearby_stats_raw"] = summarize_dict_rows(base["nearby_events"])
    base["nearby_stats_filtered"] = summarize_dict_rows(filtered_nearby)

    return base


def build_incident_llm_context(
    incident_id: int,
    event_limit: int = 12,
    nearby_limit: int = 60,
    similar_limit: int = 5,
    minutes_before: int = 2,
    minutes_after: int = 10,
) -> dict[str, Any]:
    ctx = build_incident_context_filtered(
        incident_id=incident_id,
        event_limit=event_limit,
        nearby_limit=nearby_limit,
        similar_limit=similar_limit,
        minutes_before=minutes_before,
        minutes_after=minutes_after,
        exclude_info=True,
        exclude_unknown=True,
        exclude_noise=True,
        exclude_same_incident_from_nearby=True,
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
    incident_id: int,
    persist_summary: bool = False,
    include_raw_response: bool = False,
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
                SET summary = ?,
                    analysis_json = ?,
                    probable_root_cause = ?,
                    confidence = ?,
                    last_analyzed_at = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    analysis["summary"],
                    json.dumps(analysis, ensure_ascii=False),
                    analysis["probable_root_cause"],
                    analysis["confidence"],
                    utcnow().isoformat(),
                    utcnow().isoformat(),
                    incident_id,
                ),
            )
            conn.commit()

    output = {
        "incident_id": incident_id,
        "analysis": analysis,
        "llm_context": ctx,
    }

    if include_raw_response:
        output["raw_response"] = raw_response

    return output


def fetch_open_incidents_for_digest(limit: int = 10) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 50))

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT *
            FROM incidents
            WHERE status = 'open'
              AND NOT (
                COALESCE(severity, '') = 'info'
                AND COALESCE(event_class, '') IN ('', 'unknown')
              )
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'error' THEN 2
                    WHEN 'warning' THEN 3
                    ELSE 4
                END,
                last_seen DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    items: list[dict[str, Any]] = []
    for row in rows:
        items.append(
            {
                "id": row["id"],
                "status": row["status"],
                "severity": row["severity"],
                "title": row["title"],
                "event_class": row["event_class"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
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
        )
    return items


def dedupe_incidents_for_digest(incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str, str]] = set()
    output: list[dict[str, Any]] = []

    for item in incidents:
        key = (
            str(item.get("title") or ""),
            str(item.get("event_class") or ""),
            str(item.get("severity") or ""),
            ",".join(sorted(item.get("affected_services") or [])),
        )
        if key in seen:
            continue
        seen.add(key)
        output.append(item)

    return output


def build_open_incidents_digest_prompt(incidents: list[dict[str, Any]]) -> str:
    payload = {"open_incidents": incidents}

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
    incidents = dedupe_incidents_for_digest(fetch_open_incidents_for_digest(limit=limit * 3))[:limit]
    prompt = build_open_incidents_digest_prompt(incidents)
    result, raw_response = call_ollama(prompt)

    digest = {
        "overall_status": str(result.get("overall_status") or "warning").strip().lower(),
        "summary": str(result.get("summary") or "").strip(),
        "top_issues": result.get("top_issues") if isinstance(result.get("top_issues"), list) else [],
        "recommended_actions": result.get("recommended_actions") if isinstance(result.get("recommended_actions"), list) else [],
        "source_incident_count": len(incidents),
        "source_incidents": incidents,
    }

    if digest["overall_status"] not in {"healthy", "warning", "critical"}:
        digest["overall_status"] = "warning"

    cleaned_top_issues = []
    for item in digest["top_issues"][:10]:
        if not isinstance(item, dict):
            continue
        cleaned_top_issues.append(
            {
                "incident_id": item.get("incident_id"),
                "title": str(item.get("title") or "").strip(),
                "severity": str(item.get("severity") or "").strip(),
                "assessment": str(item.get("assessment") or "").strip(),
            }
        )
    digest["top_issues"] = cleaned_top_issues

    digest["recommended_actions"] = [
        str(x).strip() for x in digest["recommended_actions"] if str(x).strip()
    ][:5]

    if include_raw_response:
        digest["raw_response"] = raw_response

    return digest


@app.get("/api/incidents")
def api_incidents(status: str = "open", limit: int = 20, severity: str = "", offset: int = 0):
    limit = max(1, min(limit, 200))
    offset = max(0, offset)

    conditions: list[str] = []
    params: list[Any] = []

    if status != "all":
        conditions.append("status = ?")
        params.append(status)

    if severity:
        conditions.append("severity = ?")
        params.append(severity)

    where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        total: int = conn.execute(
            f"SELECT COUNT(*) FROM incidents {where_clause}", params
        ).fetchone()[0]

        rows = conn.execute(
            f"SELECT * FROM incidents {where_clause} ORDER BY last_seen DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()

    items = []
    for row in rows:
        items.append(
            {
                "id": row["id"],
                "status": row["status"],
                "severity": row["severity"],
                "title": row["title"],
                "event_class": row["event_class"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
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
        )

    return {"items": items, "total": total, "offset": offset, "limit": limit}


@app.patch("/api/incidents/{incident_id}")
def api_update_incident(incident_id: int, status: str):
    allowed = {"open", "closed"}
    if status not in allowed:
        raise HTTPException(status_code=400, detail=f"status must be one of {allowed}")

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        incident = conn.execute(
            "SELECT id FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        conn.execute(
            "UPDATE incidents SET status = ?, updated_at = ? WHERE id = ?",
            (status, utcnow().isoformat(), incident_id),
        )
        conn.commit()

    return {"ok": True, "incident_id": incident_id, "status": status}


@app.get("/api/incidents/{incident_id}")
def api_incident_detail(incident_id: int, event_limit: int = 50):
    event_limit = max(1, min(event_limit, 200))

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        incident = conn.execute(
            "SELECT * FROM incidents WHERE id = ?",
            (incident_id,),
        ).fetchone()

        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        events = conn.execute(
            """
            SELECT id, ts, created_at, source, host, container, stream, level, severity_norm,
                   event_class, dependency, message, message_template, canonical_fingerprint
            FROM events
            WHERE incident_id = ?
            ORDER BY ts ASC, id ASC
            LIMIT ?
            """,
            (incident_id, event_limit),
        ).fetchall()

    return {
        "incident": {
            "id": incident["id"],
            "status": incident["status"],
            "severity": incident["severity"],
            "title": incident["title"],
            "event_class": incident["event_class"],
            "primary_fingerprint": incident["primary_fingerprint"],
            "first_seen": incident["first_seen"],
            "last_seen": incident["last_seen"],
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
        },
        "events": [dict(row) for row in events],
    }


@app.get("/api/incidents/{incident_id}/context")
def api_incident_context(
    incident_id: int,
    event_limit: int = 20,
    nearby_limit: int = 100,
    similar_limit: int = 5,
    minutes_before: int = 2,
    minutes_after: int = 10,
):
    return build_incident_context(
        incident_id=incident_id,
        event_limit=event_limit,
        nearby_limit=nearby_limit,
        similar_limit=similar_limit,
        minutes_before=minutes_before,
        minutes_after=minutes_after,
    )


@app.get("/api/incidents/{incident_id}/context-filtered")
def api_incident_context_filtered(
    incident_id: int,
    event_limit: int = 20,
    nearby_limit: int = 100,
    similar_limit: int = 5,
    minutes_before: int = 2,
    minutes_after: int = 10,
    exclude_info: bool = True,
    exclude_unknown: bool = True,
    exclude_noise: bool = True,
    exclude_same_incident_from_nearby: bool = False,
):
    return build_incident_context_filtered(
        incident_id=incident_id,
        event_limit=event_limit,
        nearby_limit=nearby_limit,
        similar_limit=similar_limit,
        minutes_before=minutes_before,
        minutes_after=minutes_after,
        exclude_info=exclude_info,
        exclude_unknown=exclude_unknown,
        exclude_noise=exclude_noise,
        exclude_same_incident_from_nearby=exclude_same_incident_from_nearby,
    )


@app.get("/api/incidents/{incident_id}/llm-context")
def api_incident_llm_context(
    incident_id: int,
    event_limit: int = 12,
    nearby_limit: int = 60,
    similar_limit: int = 5,
    minutes_before: int = 2,
    minutes_after: int = 10,
):
    return build_incident_llm_context(
        incident_id=incident_id,
        event_limit=event_limit,
        nearby_limit=nearby_limit,
        similar_limit=similar_limit,
        minutes_before=minutes_before,
        minutes_after=minutes_after,
    )


@app.post("/api/incidents/{incident_id}/analyze")
def api_analyze_incident(
    incident_id: int,
    persist_summary: bool = True,
    include_raw_response: bool = False,
):
    try:
        return analyze_incident_with_ollama(
            incident_id=incident_id,
            persist_summary=persist_summary,
            include_raw_response=include_raw_response,
        )
    except HTTPException:
        raise
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "ok": False,
                "incident_id": incident_id,
                "error": str(e),
            },
        )


_DIGEST_CACHE: dict[str, Any] = {}
_DIGEST_CACHE_TTL_SECS = 300  # 5 minutes
_DIGEST_CACHE_LOCK = threading.Lock()


@app.get("/api/incidents/open/llm-digest")
def api_open_incidents_llm_digest(
    limit: int = 10,
    include_raw_response: bool = False,
    refresh: bool = False,
):
    with _DIGEST_CACHE_LOCK:
        cached = _DIGEST_CACHE.get("result")
        cached_at = _DIGEST_CACHE.get("cached_at", 0.0)
        age = time.monotonic() - cached_at
        if cached is not None and not refresh and age < _DIGEST_CACHE_TTL_SECS:
            return cached

    try:
        result = generate_open_incidents_digest(limit=limit, include_raw_response=include_raw_response)
        with _DIGEST_CACHE_LOCK:
            _DIGEST_CACHE["result"] = result
            _DIGEST_CACHE["cached_at"] = time.monotonic()
        return result
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})


@app.get("/api/events")
def api_events(
    q: str = "",
    host: str = "",
    container: str = "",
    hours: int = 24,
    limit: int = 100,
):
    limit = max(1, min(limit, 500))
    cutoff = (utcnow() - timedelta(hours=max(1, hours))).isoformat()

    sql = """
    SELECT id, ts, created_at, source, host, container, stream, level, severity_norm,
           event_class, dependency, message, incident_id
    FROM events
    WHERE created_at >= ?
    """
    params: list[Any] = [cutoff]

    if host:
        sql += " AND host = ?"
        params.append(host.lower())

    if container:
        sql += " AND container = ?"
        params.append(container)

    if q:
        sql += " AND (message LIKE ? OR message_template LIKE ? OR event_class LIKE ?)"
        like = f"%{q}%"
        params.extend([like, like, like])

    sql += " ORDER BY ts DESC, id DESC LIMIT ?"
    params.append(limit)

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql, params).fetchall()

    return {"items": [dict(row) for row in rows]}


@app.get("/api/timeline")
def api_timeline(ts: str, minutes_before: int = 2, minutes_after: int = 5, limit: int = 200):
    limit = max(1, min(limit, 500))

    try:
        center = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ts format")

    start = (center - timedelta(minutes=minutes_before)).isoformat()
    end = (center + timedelta(minutes=minutes_after)).isoformat()

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT id, ts, created_at, source, host, container, stream, level, severity_norm,
                   event_class, dependency, message, incident_id
            FROM events
            WHERE ts >= ? AND ts <= ?
            ORDER BY ts ASC, id ASC
            LIMIT ?
            """,
            (start, end, limit),
        ).fetchall()

    return {"items": [dict(row) for row in rows]}


@app.post("/admin/backfill-events")
def admin_backfill_events(limit: int = 1000):
    try:
        count = backfill_existing_events(limit=max(1, min(limit, 5000)))
        return {"ok": True, "updated": count}
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})

_FALSE_POSITIVE_LABELS = {"false_positive", "false_positive_severity", "false_positive_noise"}


def _auto_close_false_positive(incident_id: int, confidence: str) -> None:
    """Close a false-positive incident and create a message_regex suppress rule."""
    now_iso = utcnow().isoformat()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        incident = conn.execute(
            "SELECT id, title, event_class, primary_fingerprint FROM incidents WHERE id = ?",
            (incident_id,),
        ).fetchone()
        if not incident:
            return

        # Derive a message_regex from the most common message_template for this incident
        row = conn.execute(
            """
            SELECT message_template FROM events
            WHERE incident_id = ? AND message_template != ''
            GROUP BY message_template ORDER BY COUNT(*) DESC LIMIT 1
            """,
            (incident_id,),
        ).fetchone()
        pattern = template_to_suppress_pattern(row["message_template"]) if row else ""

        conn.execute(
            "UPDATE incidents SET status = 'closed', updated_at = ? WHERE id = ?",
            (now_iso, incident_id),
        )
        if pattern:
            try:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO suppress_rules
                        (match_type, canonical_fingerprint, match_host, match_pattern,
                         incident_title, event_class, reason, created_at)
                    VALUES ('message_regex', ?, '', ?, ?, ?, ?, ?)
                    """,
                    (
                        incident["primary_fingerprint"] or "",
                        pattern,
                        incident["title"] or "",
                        incident["event_class"] or "",
                        f"auto: false_positive (confidence={confidence})",
                        now_iso,
                    ),
                )
            except sqlite3.IntegrityError:
                pass
        conn.commit()

    _load_suppressed_fingerprints()
    print(
        f"[auto-close] incident #{incident_id} closed as false_positive"
        + (f", suppress rule created: {pattern!r}" if pattern else ""),
        flush=True,
    )


def analyze_missing_incidents(
    limit: int = 10,
    include_closed: bool = False,
    skip_info_unknown: bool = True,
) -> dict[str, Any]:
    limit = max(1, min(limit, 100))

    sql = """
    SELECT id, status, severity, event_class, title
    FROM incidents
    WHERE (last_analyzed_at IS NULL OR last_analyzed_at = '')
    """
    params: list[Any] = []

    if not include_closed:
        sql += " AND status = 'open'"

    if skip_info_unknown:
        sql += """
        AND NOT (
            COALESCE(severity, '') = 'info'
            AND COALESCE(event_class, '') IN ('', 'unknown')
        )
        """

    sql += """
    ORDER BY
        CASE severity
            WHEN 'critical' THEN 1
            WHEN 'error' THEN 2
            WHEN 'warning' THEN 3
            ELSE 4
        END,
        last_seen DESC
    LIMIT ?
    """
    params.append(limit)

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql, params).fetchall()

    processed = []
    errors = []

    for row in rows:
        incident_id = int(row["id"])
        try:
            result = analyze_incident_with_ollama(
                incident_id=incident_id,
                persist_summary=True,
                include_raw_response=False,
            )
            root_cause = result["analysis"]["probable_root_cause"]
            confidence = result["analysis"]["confidence"]
            is_fp = result["analysis"].get("is_false_positive", False)

            if is_fp and root_cause in _FALSE_POSITIVE_LABELS and confidence in ("medium", "high"):
                try:
                    _auto_close_false_positive(incident_id, confidence)
                except Exception as e:
                    print(f"[auto-close] error for incident #{incident_id}: {e}", flush=True)

            processed.append(
                {
                    "incident_id": incident_id,
                    "status": row["status"],
                    "severity": row["severity"],
                    "event_class": row["event_class"],
                    "title": row["title"],
                    "probable_root_cause": root_cause,
                    "confidence": confidence,
                }
            )
        except Exception as e:
            errors.append(
                {
                    "incident_id": incident_id,
                    "title": row["title"],
                    "error": str(e),
                }
            )

    return {
        "ok": True,
        "processed_count": len(processed),
        "error_count": len(errors),
        "processed": processed,
        "errors": errors,
    }

@app.post("/api/incidents/analyze-missing")
def api_analyze_missing_incidents(
    limit: int = 10,
    include_closed: bool = False,
    skip_info_unknown: bool = True,
):
    try:
        return analyze_missing_incidents(
            limit=limit,
            include_closed=include_closed,
            skip_info_unknown=skip_info_unknown,
        )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "ok": False,
                "error": str(e),
            },
        )

@app.get("/tool/health")
def tool_health():
    return generate_open_incidents_digest(limit=10, include_raw_response=False)


@app.get("/tool/open-incidents")
def tool_open_incidents(limit: int = 20):
    return api_incidents(status="open", limit=limit)


@app.get("/tool/incident/{incident_id}")
def tool_incident(incident_id: int):
    return api_incident_detail(incident_id=incident_id, event_limit=50)


@app.get("/tool/incident/{incident_id}/context")
def tool_incident_context(incident_id: int):
    return build_incident_llm_context(
        incident_id=incident_id,
        event_limit=12,
        nearby_limit=60,
        similar_limit=5,
        minutes_before=2,
        minutes_after=10,
    )


@app.post("/tool/incident/{incident_id}/analyze")
def tool_incident_analyze(incident_id: int):
    try:
        return analyze_incident_with_ollama(
            incident_id=incident_id,
            persist_summary=True,
            include_raw_response=False,
        )
    except HTTPException:
        raise
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "ok": False,
                "incident_id": incident_id,
                "error": str(e),
            },
        )


@app.post("/api/incidents/{incident_id}/suppress")
def api_suppress_incident(
    incident_id: int,
    scope: str = "fingerprint",
    reason: str = "",
    match_host: str = "",
    match_pattern: str = "",
):
    allowed_scopes = {"fingerprint", "event_class", "event_class_host", "message_regex"}
    if scope not in allowed_scopes:
        raise HTTPException(status_code=400, detail=f"scope must be one of {allowed_scopes}")

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        incident = conn.execute(
            "SELECT id, primary_fingerprint, title, event_class FROM incidents WHERE id = ?",
            (incident_id,),
        ).fetchone()
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        fingerprint = incident["primary_fingerprint"] or ""
        event_class = incident["event_class"] or ""

        if scope == "fingerprint" and not fingerprint:
            raise HTTPException(status_code=400, detail="Incident has no canonical fingerprint")
        if scope in ("event_class", "event_class_host") and not event_class:
            raise HTTPException(status_code=400, detail="Incident has no event_class")
        if scope == "event_class_host" and not match_host:
            raise HTTPException(status_code=400, detail="match_host is required for event_class_host scope")
        if scope == "message_regex":
            if not match_pattern:
                raise HTTPException(status_code=400, detail="match_pattern is required for message_regex scope")
            try:
                re.compile(match_pattern)
            except re.error as e:
                raise HTTPException(status_code=400, detail=f"Invalid regex: {e}")

        host_val = match_host if scope == "event_class_host" else ""
        pattern_val = match_pattern if scope == "message_regex" else ""

        try:
            conn.execute(
                """
                INSERT INTO suppress_rules
                    (match_type, canonical_fingerprint, match_host, match_pattern,
                     incident_title, event_class, reason, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (scope, fingerprint, host_val, pattern_val,
                 incident["title"], event_class, reason, utcnow().isoformat()),
            )
        except sqlite3.IntegrityError:
            pass  # already suppressed — idempotent

        conn.execute(
            "UPDATE incidents SET status = 'closed', updated_at = ? WHERE id = ?",
            (utcnow().isoformat(), incident_id),
        )
        conn.commit()

    _load_suppressed_fingerprints()
    return {"ok": True, "incident_id": incident_id, "scope": scope}


@app.get("/api/events")
def api_events(limit: int = 100, offset: int = 0, host: str = "", container: str = ""):
    clauses = []
    params: list[Any] = []
    if host:
        clauses.append("host = ?")
        params.append(host)
    if container:
        clauses.append("container = ?")
        params.append(container)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params += [limit, offset]
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            f"""
            SELECT id, ts, created_at, host, container, stream, level, severity_norm,
                   event_class, message, processed, fingerprint, incident_id
            FROM events
            {where}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            params,
        ).fetchall()
        total = conn.execute(
            f"SELECT COUNT(*) FROM events {where}",
            params[:-2],
        ).fetchone()[0]
    return {"items": [dict(r) for r in rows], "total": total}


@app.get("/api/suppress-rules")
def api_list_suppress_rules():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT id, match_type, canonical_fingerprint, match_host, match_pattern,
                   incident_title, event_class, reason, created_at, hit_count
            FROM suppress_rules ORDER BY created_at DESC
            """
        ).fetchall()
    items = []
    with _SUPPRESS_LOCK:
        pending = dict(_SUPPRESS_HITS)
    for row in rows:
        d = dict(row)
        d["hit_count"] = (d.get("hit_count") or 0) + pending.get(d["id"], 0)
        items.append(d)
    return {"items": items}


@app.delete("/api/suppress-rules/{rule_id}")
def api_delete_suppress_rule(rule_id: int):
    with sqlite3.connect(DB_PATH) as conn:
        result = conn.execute("DELETE FROM suppress_rules WHERE id = ?", (rule_id,))
        conn.commit()
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Rule not found")

    _load_suppressed_fingerprints()
    return {"ok": True, "rule_id": rule_id}


@app.get("/api/ntfy-log")
def api_ntfy_log(limit: int = 50):
    limit = max(1, min(limit, 200))
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, sent_at, title, priority, source, message FROM ntfy_log ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return {"items": [dict(row) for row in rows]}


@app.get("/api/llm-stats")
def api_llm_stats(days: int = 7):
    days = max(1, min(days, 90))
    cutoff = (utcnow() - timedelta(days=days)).isoformat()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        # Aggregates
        row = conn.execute(
            """
            SELECT COUNT(*) AS total_calls,
                   SUM(CASE WHEN error = 1 THEN 1 ELSE 0 END) AS total_errors,
                   COALESCE(SUM(duration_seconds), 0) AS total_seconds,
                   COALESCE(AVG(duration_seconds), 0) AS avg_seconds,
                   COALESCE(MIN(duration_seconds), 0) AS min_seconds,
                   COALESCE(MAX(duration_seconds), 0) AS max_seconds
            FROM llm_call_log WHERE called_at >= ?
            """,
            (cutoff,),
        ).fetchone()
        # Per-day breakdown
        daily = conn.execute(
            """
            SELECT DATE(called_at) AS day,
                   COUNT(*) AS calls,
                   SUM(CASE WHEN error = 1 THEN 1 ELSE 0 END) AS errors,
                   ROUND(SUM(duration_seconds), 1) AS total_sec,
                   ROUND(AVG(duration_seconds), 1) AS avg_sec
            FROM llm_call_log WHERE called_at >= ?
            GROUP BY DATE(called_at) ORDER BY day
            """,
            (cutoff,),
        ).fetchall()
        # Recent calls
        recent = conn.execute(
            """
            SELECT called_at, duration_seconds, error
            FROM llm_call_log ORDER BY id DESC LIMIT 20
            """,
        ).fetchall()
    return {
        "period_days": days,
        "total_calls": row["total_calls"],
        "total_errors": row["total_errors"],
        "total_seconds": round(row["total_seconds"], 1),
        "avg_seconds": round(row["avg_seconds"], 1),
        "min_seconds": round(row["min_seconds"], 1),
        "max_seconds": round(row["max_seconds"], 1),
        "daily": [dict(d) for d in daily],
        "recent": [dict(r) for r in recent],
        "session": dict(_LLM_STATS),
    }


@app.post("/admin/reload-config")
def admin_reload_config():
    global CONFIG, NODE_METADATA, SERVICE_METADATA, _IGNORE_PATTERNS
    CONFIG = load_config()
    NODE_METADATA = CONFIG.get("node_metadata", {})
    SERVICE_METADATA = CONFIG.get("service_metadata", {})
    _IGNORE_PATTERNS = [re.compile(p) for p in CONFIG["filters"]["ignore_message_regex"]]
    print("[admin] Config reloaded", flush=True)
    return {"ok": True, "message": "Config reloaded"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8088)
