"""Message normalization, fingerprinting, severity mapping, classification, and enrichment."""
import hashlib
import json
import re
from typing import Any

from core import config


def extract_inner_message(raw: str) -> str:
    """If raw looks like an nxlog JSON wrapper, extract just the inner 'message' field value."""
    trimmed = raw.strip()
    if not trimmed.startswith("{"):
        return trimmed
    try:
        parsed = json.loads(trimmed)
        if isinstance(parsed.get("message"), str) and parsed["message"]:
            return parsed["message"]
    except Exception:
        pass
    m = re.search(r'"message":"([\s\S]+?)","(?:source|host|container|stream|level)"', trimmed)
    if m:
        return m.group(1)
    return trimmed


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


def infer_host_type(host: str) -> str:
    meta = config.NODE_METADATA.get((host or "").lower(), {})
    return str(meta.get("host_type") or meta.get("type") or "")


def infer_service(container: str) -> str:
    return container or ""


def infer_app_stack(container: str) -> str:
    meta = config.SERVICE_METADATA.get(container or "", {})
    return str(meta.get("app_stack") or "")


def infer_labels(host: str, container: str) -> dict[str, Any]:
    labels: dict[str, Any] = {}
    node_meta = config.NODE_METADATA.get((host or "").lower(), {})
    svc_meta = config.SERVICE_METADATA.get(container or "")
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
    enriched["ts"] = config.utcnow().isoformat()
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
