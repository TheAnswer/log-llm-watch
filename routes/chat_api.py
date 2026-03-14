"""Incident investigation chat endpoint."""
import json

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from services.incidents import build_incident_llm_context
from services.ollama import call_ollama_chat

router = APIRouter()


class ChatRequest(BaseModel):
    messages: list[dict[str, str]]


@router.post("/api/incidents/{incident_id}/chat")
def api_incident_chat(incident_id: int, body: ChatRequest):
    try:
        ctx = build_incident_llm_context(incident_id)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))

    incident = ctx["incident"]
    analysis = incident.get("analysis_json") or {}
    analysis_section = ""
    if analysis:
        analysis_section = f"""
## Existing Analysis
- Summary: {analysis.get('summary', 'N/A')}
- Root cause: {analysis.get('probable_root_cause', 'N/A')}
- Confidence: {analysis.get('confidence', 'N/A')}
- Evidence: {json.dumps(analysis.get('evidence', []))}
- Next checks: {json.dumps(analysis.get('next_checks', []))}
"""

    system_prompt = f"""You are a homelab SRE assistant helping investigate incident #{incident_id}: "{incident.get('title', 'Unknown')}".

Use the incident context below to ground your answers. Do not invent facts not present in the data.
Respond concisely in markdown. If you are unsure, say so.
{analysis_section}
## Incident Context
{json.dumps(ctx, indent=2, default=str)}"""

    full_messages = [{"role": "system", "content": system_prompt}]
    for msg in body.messages:
        role = msg.get("role", "user")
        if role not in ("user", "assistant"):
            continue
        full_messages.append({"role": role, "content": msg.get("content", "")})

    try:
        response = call_ollama_chat(full_messages)
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})

    return {"response": response, "incident_id": incident_id}
