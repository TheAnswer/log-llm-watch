"""Global configuration, constants, and simple utilities."""
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

BASE_DIR = Path("/opt/dozzle-llm-watch")
CONFIG_PATH = BASE_DIR / "config.yaml"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def load_config() -> dict[str, Any]:
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def current_system_time_str() -> str:
    return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def safe_json_loads(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        import json
        return json.loads(value)
    except Exception:
        return default


CONFIG = load_config()
DB_PATH: str = CONFIG["storage"]["db_path"]
NODE_METADATA: dict = CONFIG.get("node_metadata", {})
SERVICE_METADATA: dict = CONFIG.get("service_metadata", {})
_IGNORE_PATTERNS: list[re.Pattern] = [
    re.compile(p) for p in CONFIG["filters"]["ignore_message_regex"]
]


def reload() -> None:
    """Reload config from disk and update module-level globals."""
    global CONFIG, DB_PATH, NODE_METADATA, SERVICE_METADATA, _IGNORE_PATTERNS
    CONFIG = load_config()
    DB_PATH = CONFIG["storage"]["db_path"]
    NODE_METADATA = CONFIG.get("node_metadata", {})
    SERVICE_METADATA = CONFIG.get("service_metadata", {})
    _IGNORE_PATTERNS = [re.compile(p) for p in CONFIG["filters"]["ignore_message_regex"]]
