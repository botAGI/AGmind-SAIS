"""
Alerter — отправка уведомлений об угрозах.
Формат алертов на основе LogSentinelAI: эмодзи-приоритеты, статистика, recommended actions.
Поддержка: Telegram, webhook, локальный лог.
"""

from __future__ import annotations
import json
import logging
from datetime import datetime, timezone
from typing import Optional

import aiohttp

from app.core.schemas import (
    SystemEvent,
    NetworkEvent,
    LogSecurityEvent,
    SeverityLevel,
    AggregateAnalysis,
)

logger = logging.getLogger("sais.alerts")

_SEVERITY_ICONS = {
    SeverityLevel.CRITICAL: "🔴",
    SeverityLevel.HIGH: "🟠",
    SeverityLevel.MEDIUM: "🟡",
    SeverityLevel.LOW: "🔵",
    SeverityLevel.INFO: "⚪",
}


def _count_severities(events: list, severity_attr: str = "severity") -> dict[str, int]:
    """Подсчёт событий по severity (как LogSentinelAI statistics)."""
    counts = {}
    for e in events:
        sev = getattr(e, severity_attr, None)
        if sev:
            s = sev.value if hasattr(sev, 'value') else str(sev)
            counts[s] = counts.get(s, 0) + 1
    return counts


class AlertBuilder:
    """Построитель сообщений (формат LogSentinelAI)."""

    @staticmethod
    def build_telegram(result: AggregateAnalysis) -> str:
        """Telegram-сообщение (как LogSentinelAI формат)."""
        sev = result.overall_severity
        icon = _SEVERITY_ICONS.get(sev, "⚪")
        lines = []

        # Заголовок (как LogSentinelAI: 🚨 [SEVERITY EVENTS] 🚨)
        lines.append(f"{icon} *AGmind-SAIS Alert* {icon}")
        lines.append(f"Severity: *{sev.value if hasattr(sev, 'value') else sev}* | Risk: *{result.overall_risk_score:.2f}*")
        lines.append(f"Immediate attention: {'✅ YES' if result.requires_immediate_attention else '❌ No'}")
        lines.append("")

        # Системные события
        all_sys_events = result.system.events if hasattr(result, 'system') and hasattr(result.system, 'events') else []
        counts = _count_severities(all_sys_events)
        if counts:
            lines.append("📊 *System Events Summary*")
            for sev_name, cnt in counts.items():
                s_icon = _SEVERITY_ICONS.get(SeverityLevel(sev_name), "⚪")
                lines.append(f"  {s_icon} {sev_name}: {cnt}")
            lines.append("")

            for e in all_sys_events:
                if e.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH):
                    s_icon = _SEVERITY_ICONS.get(e.severity, "⚪")
                    lines.append(f"{s_icon} *[{e.event_type.value if hasattr(e.event_type, 'value') else e.event_type}]*")
                    lines.append(f"   {e.description[:200]}")
                    if e.process_name:
                        lines.append(f"   Process: `{e.process_name}` (PID: {e.pid})")
                    lines.append(f"   Confidence: {e.confidence_score:.0%}")
                    lines.append("")

        # Сетевые события
        all_net_events = result.network.events if hasattr(result, 'network') and hasattr(result.network, 'events') else []
        for e in all_net_events:
            if e.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH):
                s_icon = _SEVERITY_ICONS.get(e.severity, "⚪")
                lines.append(f"{s_icon} *[{e.event_type.value if hasattr(e.event_type, 'value') else e.event_type}]*")
                lines.append(f"   {e.description[:200]}")
                if e.source_ip:
                    lines.append(f"   `{e.source_ip}` → `{e.dest_ip or '*'}` :{e.dest_port or '*'}")
                lines.append(f"   Confidence: {e.confidence_score:.0%}")
                lines.append("")

        # Лог-события
        all_log_events = result.logs.events if hasattr(result, 'logs') and hasattr(result.logs, 'events') else []
        for e in all_log_events:
            if e.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH):
                s_icon = _SEVERITY_ICONS.get(e.severity, "⚪")
                lines.append(f"{s_icon} *[{e.event_type.value if hasattr(e.event_type, 'value') else e.event_type}]*")
                lines.append(f"   {e.description[:200]}")
                if e.username:
                    lines.append(f"   User: `{e.username}`")
                if e.source_ips:
                    lines.append(f"   IPs: `{', '.join(e.source_ips[:3])}`")
                lines.append(f"   Confidence: {e.confidence_score:.0%}")
                if e.recommended_actions:
                    lines.append(f"   Action: {e.recommended_actions[0][:100]}")
                lines.append("")

        # Если нет CRITICAL/HIGH событий
        if not any(e for e in all_sys_events + all_net_events + all_log_events
                   if e.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH)):
            lines.append("✅ *No critical or high-severity events detected*")
            lines.append(f"   {result.logs.summary[:200]}")
            lines.append("")

        lines.append(f"🕐 {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")

        return "\n".join(lines)

    @staticmethod
    def build_webhook(result: AggregateAnalysis) -> dict:
        """Webhook payload."""
        return {
            "event": "sais.alert",
            "severity": result.overall_severity.value if hasattr(result.overall_severity, 'value') else str(result.overall_severity),
            "risk_score": result.overall_risk_score,
            "summary": result.logs.summary if hasattr(result, 'logs') and hasattr(result.logs, 'summary') else "",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


class Alerter:
    """Отправщик уведомлений (Telegram / webhook / log)."""

    def __init__(self, config: dict):
        self.config = config
        alerts_cfg = config.get("alerts", {})
        telegram_cfg = alerts_cfg.get("telegram", {})
        webhook_cfg = alerts_cfg.get("webhook", {})
        self.telegram_enabled = telegram_cfg.get("enabled", False)
        self.telegram_token = telegram_cfg.get("bot_token", "")
        self.telegram_chat = telegram_cfg.get("chat_id", "")
        self.webhook_enabled = webhook_cfg.get("enabled", False)
        self.webhook_url = webhook_cfg.get("url", "")
        self.log_alerts = alerts_cfg.get("log", {}).get("enabled", True)

    async def send(self, result: AggregateAnalysis):
        """Отправить по всем каналам."""
        if self.log_alerts:
            self._log_alert(result)

        if self.telegram_enabled and self.telegram_token:
            await self._send_telegram(result)

        if self.webhook_enabled and self.webhook_url:
            await self._send_webhook(result)

    def _log_alert(self, result: AggregateAnalysis):
        logger.info(
            "ALERT: severity=%s, risk=%.2f, attention=%s",
            result.overall_severity, result.overall_risk_score,
            result.requires_immediate_attention,
        )

    async def _send_telegram(self, result: AggregateAnalysis):
        text = AlertBuilder.build_telegram(result)
        if not text:
            return

        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        payload = {
            "chat_id": self.telegram_chat,
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status != 200:
                        logger.error("Telegram error %d: %s", resp.status, await resp.text())
                    else:
                        logger.info("Telegram alert sent to %s", self.telegram_chat)
        except Exception as e:
            logger.error("Telegram send failed: %s", e)

    async def _send_webhook(self, result: AggregateAnalysis):
        payload = AlertBuilder.build_webhook(result)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status in (200, 201, 202, 204):
                        logger.info("Webhook sent to %s", self.webhook_url)
                    else:
                        logger.warning("Webhook responded %d", resp.status)
        except Exception as e:
            logger.error("Webhook error: %s", e)
