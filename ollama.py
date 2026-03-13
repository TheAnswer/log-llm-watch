"""Ollama LLM client with call tracking."""
import inspect
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
    "total_prompt_tokens": 0,
    "total_completion_tokens": 0,
    "last_call_at": "",
    "last_duration_seconds": 0.0,
}


def _infer_caller() -> str:
    """Walk the stack to find the meaningful caller outside ollama.py."""
    for frame_info in inspect.stack()[2:6]:
        module = inspect.getmodule(frame_info.frame)
        mod_name = module.__name__ if module else ""
        if mod_name and mod_name != __name__:
            return f"{mod_name}.{frame_info.function}"
    return "unknown"


def _record_llm_call(
    duration: float,
    error: bool = False,
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    model: str = "",
    caller: str = "",
    response_preview: str = "",
) -> None:
    _LLM_STATS["total_calls"] += 1
    if error:
        _LLM_STATS["total_errors"] += 1
    _LLM_STATS["total_seconds"] += duration
    _LLM_STATS["total_prompt_tokens"] += prompt_tokens
    _LLM_STATS["total_completion_tokens"] += completion_tokens
    _LLM_STATS["last_call_at"] = config.utcnow().isoformat()
    _LLM_STATS["last_duration_seconds"] = duration
    try:
        with sqlite3.connect(config.DB_PATH) as conn:
            conn.execute(
                """INSERT INTO llm_call_log
                   (called_at, duration_seconds, error, prompt_tokens, completion_tokens, model, caller, response_preview)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (config.utcnow().isoformat(), round(duration, 3), 1 if error else 0,
                 prompt_tokens, completion_tokens, model, caller, response_preview[:1000]),
            )
            conn.commit()
    except Exception as e:
        print(f"[llm_stats] Failed to log call: {e}", flush=True)


def _extract_token_stats(data: dict) -> dict[str, Any]:
    """Extract token counts and model from an Ollama response."""
    return {
        "prompt_tokens": int(data.get("prompt_eval_count") or 0),
        "completion_tokens": int(data.get("eval_count") or 0),
        "model": str(data.get("model") or ""),
    }


def _check_context_limit(data: dict, num_ctx: int) -> None:
    """Warn if token usage is near the context window limit."""
    prompt_tokens = int(data.get("prompt_eval_count") or 0)
    completion_tokens = int(data.get("eval_count") or 0)
    if num_ctx and prompt_tokens + completion_tokens >= num_ctx * 0.95:
        print(
            f"[ollama] WARNING: near context limit — prompt={prompt_tokens} + completion={completion_tokens}"
            f" = {prompt_tokens + completion_tokens} tokens vs num_ctx={num_ctx}",
            flush=True,
        )


def call_ollama(prompt: str) -> tuple[dict[str, Any], str]:
    url = config.CONFIG["ollama"]["url"].rstrip("/") + "/api/generate"
    num_ctx = int(config.CONFIG["ollama"].get("num_ctx", 32768))
    body = {
        "model": config.CONFIG["ollama"]["model"],
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.1,
            "num_ctx": num_ctx,
        },
    }

    caller = _infer_caller()
    t0 = time.monotonic()
    token_stats: dict[str, Any] = {}
    response_text = ""
    try:
        with _OLLAMA_LOCK:
            r = requests.post(url, json=body, timeout=config.CONFIG["ollama"]["timeout_seconds"])
        r.raise_for_status()
        data = r.json()
        token_stats = _extract_token_stats(data)

        if data.get("done_reason") == "length":
            raise ValueError("Ollama response truncated (hit context limit).")

        _check_context_limit(data, num_ctx)

        raw_response = (data.get("response") or "").strip()
        raw_thinking = (data.get("thinking") or "").strip()
        candidate = raw_response or raw_thinking
        response_text = candidate

        if not candidate:
            raise ValueError(f"Ollama returned empty response. Full payload: {data!r}")

        cleaned = candidate

        try:
            result = json.loads(cleaned), cleaned
            _record_llm_call(time.monotonic() - t0, caller=caller, response_preview=response_text, **token_stats)
            return result
        except json.JSONDecodeError:
            pass

        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```[a-zA-Z0-9_-]*\n?", "", cleaned)
            cleaned = re.sub(r"\n?```$", "", cleaned).strip()

        try:
            result = json.loads(cleaned), candidate
            _record_llm_call(time.monotonic() - t0, caller=caller, response_preview=response_text, **token_stats)
            return result
        except json.JSONDecodeError:
            pass

        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start != -1 and end != -1 and end > start:
            extracted = cleaned[start:end + 1]
            try:
                result = json.loads(extracted), candidate
                _record_llm_call(time.monotonic() - t0, caller=caller, response_preview=response_text, **token_stats)
                return result
            except json.JSONDecodeError:
                pass

        raise ValueError(f"Could not parse Ollama JSON response. Candidate: {candidate!r}")
    except Exception:
        _record_llm_call(time.monotonic() - t0, error=True, caller=caller, response_preview=response_text, **token_stats)
        raise


def call_ollama_text(prompt: str) -> str:
    url = config.CONFIG["ollama"]["url"].rstrip("/") + "/api/generate"
    num_ctx = int(config.CONFIG["ollama"].get("num_ctx", 32768))
    body = {
        "model": config.CONFIG["ollama"]["model"],
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2,
            "num_ctx": num_ctx,
        },
    }

    caller = _infer_caller()
    t0 = time.monotonic()
    token_stats: dict[str, Any] = {}
    response_text = ""
    try:
        with _OLLAMA_LOCK:
            r = requests.post(url, json=body, timeout=config.CONFIG["ollama"]["timeout_seconds"])
        r.raise_for_status()
        data = r.json()
        token_stats = _extract_token_stats(data)

        _check_context_limit(data, num_ctx)

        raw_response = (data.get("response") or "").strip()
        raw_thinking = (data.get("thinking") or "").strip()
        text = raw_response or raw_thinking
        response_text = text
        if not text:
            raise ValueError(f"Ollama returned empty response. Full payload: {data!r}")

        _record_llm_call(time.monotonic() - t0, caller=caller, response_preview=response_text, **token_stats)
        return text
    except Exception:
        _record_llm_call(time.monotonic() - t0, error=True, caller=caller, response_preview=response_text, **token_stats)
        raise
