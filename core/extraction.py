"""Event extraction from webhook payloads (Dozzle, Windows, Syslog)."""
import json
import re
from typing import Any


def extract_dozzle_event(payload: Any) -> dict[str, str]:
    source = "dozzle-webhook"
    host = ""
    container = "unknown"
    stream = ""
    level = ""
    message = ""

    if not isinstance(payload, dict):
        return {
            "source": source, "host": host, "container": container,
            "stream": stream, "level": level,
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
        "source": source, "host": host, "container": container,
        "stream": stream, "level": level, "message": message,
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
            "source": source, "host": host, "container": container,
            "stream": stream, "level": level,
            "message": json.dumps(payload, ensure_ascii=False),
        }

    host = str(
        payload.get("Hostname") or payload.get("Computer") or payload.get("host") or ""
    ).strip().lower()

    channel = str(
        payload.get("Channel") or payload.get("channel") or payload.get("EventChannel") or "Windows"
    ).strip()

    provider = str(
        payload.get("ProviderName") or payload.get("SourceName")
        or payload.get("Provider") or payload.get("provider") or ""
    ).strip()

    rendered_message = (
        payload.get("Message") or payload.get("message")
        or payload.get("EventData") or payload.get("RenderedMessage") or ""
    )

    if isinstance(rendered_message, (dict, list)):
        message = json.dumps(rendered_message, ensure_ascii=False)
    else:
        message = str(rendered_message).strip()

    event_id = payload.get("EventID") or payload.get("EventId") or payload.get("event_id")
    level_name = payload.get("LevelName") or payload.get("level_name")

    level = normalize_windows_level(
        payload.get("SeverityValue") or payload.get("LevelValue") or payload.get("Level"),
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
        "source": source, "host": host, "container": container,
        "stream": stream, "level": level, "message": message,
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
            "source": source, "host": host, "container": container,
            "stream": stream, "level": level,
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
        "source": source, "host": host, "container": container,
        "stream": "", "level": level, "message": message,
    }
