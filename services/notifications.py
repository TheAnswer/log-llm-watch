"""Notification sending (ntfy) and text helpers."""
import sqlite3

import requests

from core import config


def truncate_for_ntfy(text: str, max_chars: int = 3500) -> str:
    text = text.strip()
    if len(text) <= max_chars:
        return text
    truncated = text[:max_chars].rstrip()
    return truncated + "\n\n[message truncated]"


def send_ntfy(message: str, priority: str = "default", source: str = "analysis") -> None:
    url = config.CONFIG["notify"]["ntfy_url"]
    title = config.CONFIG["notify"]["title"]
    headers = {
        "Title": title,
        "Priority": priority,
        "Tags": "warning,robot_face",
    }
    r = requests.post(url, data=message.encode("utf-8"), headers=headers, timeout=30)
    if not r.ok:
        raise RuntimeError(f"ntfy error {r.status_code}: {r.text}")
    try:
        with sqlite3.connect(config.DB_PATH) as conn:
            conn.execute(
                "INSERT INTO ntfy_log (sent_at, title, priority, source, message) VALUES (?, ?, ?, ?, ?)",
                (config.utcnow().isoformat(), title, priority, source, message[:4000]),
            )
            conn.commit()
    except Exception as e:
        print(f"[ntfy] Failed to log notification: {e}", flush=True)
