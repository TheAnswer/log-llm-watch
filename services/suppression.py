"""Suppression rule caching, matching, regex generation, and auto-suppress logic."""
import json
import re
import sqlite3
import threading
import time
from typing import Any

from core import config
from core.normalize import extract_inner_message

# In-memory suppression caches
_SUPPRESS_FP: set[str] = set()
_SUPPRESS_EC: set[str] = set()
_SUPPRESS_EC_HOST: set[tuple[str, str]] = set()
_SUPPRESS_REGEX: list[tuple[int, re.Pattern]] = []
_SUPPRESS_HITS: dict[int, int] = {}
_SUPPRESS_LOCK = threading.Lock()

# Cooldown cache for ignore logging
_IGNORE_LOG_SEEN: dict[str, float] = {}
_IGNORE_LOG_LOCK = threading.Lock()
_IGNORE_LOG_COOLDOWN_SECS = 60


def log_ignored(container: str, host: str, message: str, reason: str, elapsed_ms: float = 0.0) -> None:
    key = f"{container}|{host}|{message[:80]}"
    now = time.monotonic()
    with _IGNORE_LOG_LOCK:
        if now - _IGNORE_LOG_SEEN.get(key, 0) < _IGNORE_LOG_COOLDOWN_SECS:
            return
        _IGNORE_LOG_SEEN[key] = now
    print(f"[ignore] {reason} host={host!r} container={container!r} elapsed={elapsed_ms:.1f}ms msg={message[:120]!r}", flush=True)


def load_suppressed_fingerprints() -> None:
    """Reload all in-memory suppression caches from the DB."""
    try:
        with sqlite3.connect(config.DB_PATH) as conn:
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


def flush_suppress_hits() -> None:
    """Flush in-memory hit count deltas to the DB."""
    with _SUPPRESS_LOCK:
        if not _SUPPRESS_HITS:
            return
        deltas = dict(_SUPPRESS_HITS)
        _SUPPRESS_HITS.clear()
    try:
        with sqlite3.connect(config.DB_PATH) as conn:
            for rule_id, count in deltas.items():
                conn.execute(
                    "UPDATE suppress_rules SET hit_count = hit_count + ?, last_hit_at = ? WHERE id = ?",
                    (count, config.utcnow().isoformat(), rule_id),
                )
            conn.commit()
    except Exception as e:
        print(f"[suppress] Failed to flush hit counts: {e}", flush=True)


def should_ignore(message: str) -> bool:
    if any(p.search(message) for p in config._IGNORE_PATTERNS):
        return True
    normalized = re.sub(r"\s+", " ", message)
    with _SUPPRESS_LOCK:
        for rule_id, pat in _SUPPRESS_REGEX:
            if pat.search(normalized):
                _SUPPRESS_HITS[rule_id] = _SUPPRESS_HITS.get(rule_id, 0) + 1
                return True
    return False


def template_to_suppress_pattern(template: str) -> str:
    """Convert a normalize_message() template to a (?i) regex."""
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
    """Ask the LLM to generate a regex for each ignored group."""
    # Import here to avoid circular dependency at module level
    from services.ollama import call_ollama

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


def auto_suppress_ignored(groups_by_fp: dict[str, dict[str, Any]], ignored_fps: list[str]) -> None:
    """Create message_regex suppress rules for groups the LLM rated as ignore."""
    if not ignored_fps:
        return

    groups_to_suppress = []
    for fp in ignored_fps:
        g = groups_by_fp.get(fp)
        if g and (g.get("message_template") or g.get("examples")):
            groups_to_suppress.append(g)

    if not groups_to_suppress:
        return

    llm_patterns = _llm_generate_suppress_regex(groups_to_suppress)

    now_iso = config.utcnow().isoformat()
    created = 0
    for fp in ignored_fps:
        g = groups_by_fp.get(fp)
        if not g:
            continue
        template = g.get("message_template") or ""
        examples = g.get("examples", [])
        if not template and not examples:
            continue

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

        if not pattern and template:
            pattern = template_to_suppress_pattern(template)
            source = "template"

        if not pattern:
            continue

        try:
            with sqlite3.connect(config.DB_PATH) as conn:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO suppress_rules
                        (match_type, canonical_fingerprint, match_host, match_pattern,
                         incident_title, event_class, reason, created_at)
                    VALUES (?, ?, '', ?, ?, ?, ?, ?)
                    """,
                    (
                        "message_regex", fp, pattern,
                        g.get("container", ""), g.get("event_class", ""),
                        f"auto: llm-ignore ({source})", now_iso,
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
        load_suppressed_fingerprints()
