#!/usr/bin/env python3
"""
AGmind-SAIS — Security AI Sensor
Entrypoint
"""

import asyncio
import logging
import os
import signal
import sys
from pathlib import Path

import yaml

from app.api.endpoints import create_app
from app.core.agent import SecurityAgent
from app.core.analyzer import SecurityAnalyzer
from app.core.ledger import InvestigationLedger
from app.core.alerts import Alerter
from app.ml_client.base import MLClient
from app.monitoring.collector import DataCollector
from app.reactor.engine import ReactorEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("sais")


class SAISApp:
    def __init__(self, config_path: str = "config/config.yaml"):
        self.config_path = config_path
        self.config: dict = {}
        self.app = None
        self._server = None
        self._agent_task = None

    def load_config(self) -> dict:
        path = Path(self.config_path)
        if not path.exists():
            logger.warning("Config %s not found, using defaults", self.config_path)
            return {}
        with open(path) as f:
            self.config = yaml.safe_load(f) or {}
        return self.config

    async def initialize(self):
        self.load_config()
        os.makedirs("/var/log/sais/ledger", exist_ok=True)

        ml_client = MLClient.create(self.config)
        collector = DataCollector(self.config)
        analyzer = SecurityAnalyzer(ml_client)
        ledger = InvestigationLedger()
        reactor = ReactorEngine(self.config)
        alerter = Alerter(self.config)
        agent = SecurityAgent(self.config, ml_client, analyzer, collector, reactor, alerter)

        self.app = create_app(agent, collector, analyzer, ledger, reactor, ml_client, self.config)
        self._agent = agent

    async def start(self):
        await self.initialize()
        self._agent_task = asyncio.create_task(self._agent.start())

        import uvicorn
        host = self.config.get("server", {}).get("host", "0.0.0.0")
        port = self.config.get("server", {}).get("port", 8080)
        config = uvicorn.Config(app=self.app, host=host, port=port, log_level="info")
        self._server = uvicorn.Server(config)
        await self._server.serve()

    async def stop(self):
        if self._agent:
            await self._agent.stop()
        if self._server:
            self._server.should_exit = True


async def main():
    app = SAISApp(os.environ.get("SAIS_CONFIG", "config/config.yaml"))
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(app.stop()))
    try:
        await app.start()
    except KeyboardInterrupt:
        await app.stop()


if __name__ == "__main__":
    asyncio.run(main())
