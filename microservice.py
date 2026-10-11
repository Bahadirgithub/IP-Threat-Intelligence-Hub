"""
ASN Research Microservice — FastAPI
Wraps the LangGraph agent as an HTTP service.

Run:
    uvicorn microservice:app --host 0.0.0.0 --port 8001 --reload

Endpoints:
    POST /research   { "asn": "9009" }  →  full research result
    GET  /health                        →  { "status": "ok" }
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
from provider_agent import research_asn

app = FastAPI(
    title="ASN and Hosting Provider Research Microservice",
    version="2.0",
    description="LangGraph-based ASN and hosting provider risk analysis",
)


class ASNRequest(BaseModel):
    asn: str
    ip: Optional[str] = None


@app.post("/research")
def research(req: ASNRequest):
    """Research an ASN and return the full analysis."""
    try:
        result = research_asn(req.asn, req.ip)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
def health():
    """Health check."""
    return {"status": "ok"}