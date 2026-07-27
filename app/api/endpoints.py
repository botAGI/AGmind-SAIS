"""
AGmind-SAIS API — FastAPI endpoints.
"""

from __future__ import annotations
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.core.agent import SecurityAgent
from app.core.analyzer import SecurityAnalyzer
from app.core.ledger import InvestigationLedger
from app.reactor.engine import ReactorEngine
from app.monitoring.collector import DataCollector
from app.ml_client.base import MLClient

logger = logging.getLogger("sais.api")


class ChatRequest(BaseModel):
    message: str


class ChatResponse(BaseModel):
    response: str
    model: str
    provider: str
    timestamp: str


class ReactorCommand(BaseModel):
    command: str  # enable | disable | set_auto
    value: Optional[bool] = None


def create_app(
    agent: SecurityAgent,
    collector: DataCollector,
    analyzer: SecurityAnalyzer,
    ledger: InvestigationLedger,
    reactor: ReactorEngine,
    ml_client: MLClient,
    config: dict,
) -> FastAPI:
    app = FastAPI(title="AGmind-SAIS", version="0.1.0", docs_url="/docs")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health")
    async def health():
        ml_healthy = False
        try:
            ml_healthy = await ml_client.check_health()
        except Exception:
            pass
        return {"status": "ok" if ml_healthy else "degraded", "ml_healthy": ml_healthy}

    @app.get("/api/status")
    async def get_status():
        return {
            "agent": await agent.get_status(),
            "reactor": reactor.get_status(),
            "ledger": ledger.get_stats(),
        }

    @app.post("/api/chat")
    async def chat(req: ChatRequest):
        try:
            response = await agent.chat(req.message)
            return ChatResponse(
                response=response,
                model=config["ml"]["model"],
                provider=config["ml"]["provider"],
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.websocket("/api/chat/ws")
    async def chat_websocket(ws: WebSocket):
        await ws.accept()
        try:
            while True:
                data = await ws.receive_json()
                msg = data.get("message", "")
                response = await agent.chat(msg)
                await ws.send_json({
                    "response": response,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
        except WebSocketDisconnect:
            pass

    @app.post("/api/analyze")
    async def trigger_analysis():
        try:
            snapshot = await collector.get_live_snapshot()
            log_lines = [e["content"] for e in snapshot["logs"].get("recent", [])]
            result = await analyzer.analyze_aggregate(
                system_data=snapshot["system"],
                network_data=snapshot["network"],
                log_data=snapshot["logs"],
                log_lines=log_lines,
            )
            return {
                "status": "completed" if result else "failed",
                "result": result.model_dump(mode="json") if result else None,
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/ledger")
    async def get_ledger(limit: int = 10):
        return {"entries": ledger.get_recent(limit=limit)}

    @app.get("/api/monitor/live")
    async def live_monitor():
        snapshot = await collector.get_live_snapshot()
        return snapshot

    @app.post("/api/reactor")
    async def control_reactor(cmd: ReactorCommand):
        if cmd.command == "enable":
            reactor.enable()
        elif cmd.command == "disable":
            reactor.disable()
        elif cmd.command == "set_auto" and cmd.value is not None:
            reactor.auto_mode = cmd.value
        else:
            raise HTTPException(status_code=400, detail=f"Unknown command: {cmd.command}")
        return {"status": "ok"}

    return app
