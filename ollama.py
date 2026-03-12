"""Ollama LLM client with call tracking."""
import json
import re
import sqlite3
import threading
import time
from typing import Any

import requests

import config

_OLLAMA_LOCK = threading.Lock()

_LLM_STATS: dict[str, float | int] = {
    "total_calls": 0,
    "total_errors": 0,
    "total_seconds": 0.0,
    "last_call_at": "",
    "last_duration_seconds": 0.0,
}


def _record_llm_call(duration: float, error: bool = False) -> None:
    _LLM_STATS["total_calls"] += 1
    if error:
        _LLM_STATS["total_errors"] += 1
    _LLM_STATS["total_seconds"] += duration
    _LLM_STATS["last_call_at"] = config.utcnow().isoformat()
    _LLM_STATS["last_duration_seconds"] = duration
    try:
        with sqlite3.connect(config.DB_PATH) as conn:
            conn.execute(
                "INSERT INTO llm_call_log (called_at, duration_seconds, error) VALUES (?, ?, ?)",
                (config.utcnow().isoformat(), round(duration, 3), 1 if error else 0),
            )
            conn.commit()
    except Exception as e:
        print(f"[llm_stats] Failed to log call: {e}", flush=True)


def call_ollama(prompt: str) -> tuple[dict[str, Any], str]:
    url = config.CONFIG["ollama"]["url"].rstrip("/") + "/api/generate"
    body = {
        "model": config.CONFIG["ollama"]["model"],
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
            r = requests.post(url, json=body, timeout=config.CONFIG["ollama"]["timeout_seconds"])
        r.raise_for_status()
        data = r.json()

        if data.get("done_reason") == "length":
            raise ValueError("Ollama response truncated (hit context limit).")

        raw_response = (data.get("response") or "").strip()
        raw_thinking = (data.get("thinking") or "").strip()
        candidate = raw_response or raw_thinking

        if not candidate:
            raise ValueError(f"Ollama returned empty response. Full payload: {data!r}")

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
    url = config.CONFIG["ollama"]["url"].rstrip("/") + "/api/generate"
    body = {
        "model": config.CONFIG["ollama"]["model"],
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2,
        },
    }

    t0 = time.monotonic()
    try:
        with _OLLAMA_LOCK:
            r = requests.post(url, json=body, timeout=config.CONFIG["ollama"]["timeout_seconds"])
        r.raise_for_status()
        data = r.json()

        raw_response = (data.get("response") or "").strip()
        raw_thinking = (data.get("thinking") or "").strip()
        text = raw_response or raw_thinking
        if not text:
            raise ValueError(f"Ollama returned empty response. Full payload: {data!r}")

        _record_llm_call(time.monotonic() - t0)
        return text
    except Exception:
        _record_llm_call(time.monotonic() - t0, error=True)
        raise
