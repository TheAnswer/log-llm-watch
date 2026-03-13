"""Tool endpoints for external integrations (e.g. OpenWebUI)."""
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from services.incidents import (
    analyze_incident_with_ollama,
    build_incident_llm_context,
    generate_open_incidents_digest,
)
from routes.incidents_api import api_incidents, api_incident_detail

router = APIRouter()


@router.get("/tool/health")
def tool_health():
    return generate_open_incidents_digest(limit=10, include_raw_response=False)


@router.get("/tool/open-incidents")
def tool_open_incidents(limit: int = 20):
    return api_incidents(status="open", limit=limit)


@router.get("/tool/incident/{incident_id}")
def tool_incident(incident_id: int):
    return api_incident_detail(incident_id=incident_id, event_limit=50)


@router.get("/tool/incident/{incident_id}/context")
def tool_incident_context(incident_id: int):
    return build_incident_llm_context(
        incident_id=incident_id, event_limit=12, nearby_limit=60,
        similar_limit=5, minutes_before=2, minutes_after=10)


@router.post("/tool/incident/{incident_id}/analyze")
def tool_incident_analyze(incident_id: int):
    try:
        return analyze_incident_with_ollama(
            incident_id=incident_id, persist_summary=True, include_raw_response=False)
    except HTTPException:
        raise
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "incident_id": incident_id, "error": str(e)})
