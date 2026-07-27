"""
Pydantic-модели для декларативной экстракции AGmind-SAIS.
Основано на LogSentinelAI: каждая модель под конкретный тип анализа,
Statistics — отдельная Pydantic-модель.
"""

from __future__ import annotations
from pydantic import BaseModel, Field
from enum import Enum
from typing import Optional


# ═══════════════════════════════════════════════
# SeverityLevel (из LogSentinelAI linux_system.py)
# ═══════════════════════════════════════════════

class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# ═══════════════════════════════════════════════
# Statistics (из LogSentinelAI linux_system.py)
# ═══════════════════════════════════════════════

class Statistics(BaseModel):
    """Статистика анализа (как у LogSentinelAI)."""
    total_events: int = Field(..., description="Total number of events")
    auth_failures: int = Field(0, description="Number of authentication failures")
    unique_ips: int = Field(0, description="Number of unique IPs")
    unique_users: int = Field(0, description="Number of unique users")
    event_by_type: list[str] = Field(
        default_factory=list,
        description='Events by type as "TYPE:COUNT" pairs'
    )


# ═══════════════════════════════════════════════
# Анализ логов (на основе LogSentinelAI SecurityEvent / LogAnalysis)
# ═══════════════════════════════════════════════

class LogEventType(str, Enum):
    AUTH_FAILURE = "AUTH_FAILURE"
    AUTH_SUCCESS = "AUTH_SUCCESS"
    PRIV_ESCALATION = "PRIV_ESCALATION"
    SUSPICIOUS_COMMAND = "SUSPICIOUS_COMMAND"
    UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS"
    MALWARE_ACTIVITY = "MALWARE_ACTIVITY"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    SESSION_EVENT = "SESSION_EVENT"
    SYSTEM_EVENT = "SYSTEM_EVENT"
    ANOMALY = "ANOMALY"
    UNKNOWN = "UNKNOWN"


class LogSecurityEvent(BaseModel):
    """Событие безопасности из логов (SecurityEvent в LogSentinelAI linux_system.py)."""
    event_type: LogEventType
    severity: SeverityLevel
    related_logs: list[str] = Field(
        min_length=1,
        description="Original log lines that triggered this event — include exact unmodified log entries"
    )
    description: str = Field(..., description="Detailed event description")
    confidence_score: float = Field(ge=0.0, le=1.0, description="Confidence level (0.0-1.0)")
    source_ips: Optional[list[str]] = Field(None, description="Source IP address list")
    username: Optional[str] = Field(None, description="Username")
    process: Optional[str] = Field(None, description="Related process")
    service: Optional[str] = Field(None, description="Related service")
    recommended_actions: list[str] = Field(default_factory=list, description="Recommended actions")
    requires_human_review: bool = Field(default=False, description="Whether human review is required")


class LogAnalysis(BaseModel):
    """Результат анализа логов (LogAnalysis в LogSentinelAI linux_system.py)."""
    summary: str = Field(..., description="Analysis summary")
    events: list[LogSecurityEvent] = Field(
        min_length=1,
        description="List of events — MUST NEVER BE EMPTY. Always create at least one INFO event"
    )
    statistics: Statistics = Field(default_factory=Statistics, description="Statistics about the analysis")
    highest_severity: Optional[SeverityLevel] = Field(None, description="Highest severity level")
    requires_immediate_attention: bool = Field(default=False, description="Requires immediate attention")


# ═══════════════════════════════════════════════
# Анализ системы (адаптация LogSentinelAI под системные метрики)
# ═══════════════════════════════════════════════

class SystemEventType(str, Enum):
    CPU_OVERLOAD = "CPU_OVERLOAD"
    MEMORY_PRESSURE = "MEMORY_PRESSURE"
    DISK_SPACE = "DISK_SPACE"
    SUSPICIOUS_PROCESS = "SUSPICIOUS_PROCESS"
    ABNORMAL_USER = "ABNORMAL_USER"
    SYSTEM_EVENT = "SYSTEM_EVENT"
    ANOMALY = "ANOMALY"
    INFO = "INFO"


class SystemEvent(BaseModel):
    """Событие системного мониторинга."""
    event_type: SystemEventType
    severity: SeverityLevel
    description: str = Field(..., description="Описание события")
    confidence_score: float = Field(ge=0.0, le=1.0, description="Уверенность (0.0–1.0)")
    process_name: Optional[str] = Field(None, description="Имя процесса")
    pid: Optional[int] = Field(None, description="PID процесса")
    metric_value: Optional[float] = Field(None, description="Значение метрики")
    metric_threshold: Optional[float] = Field(None, description="Порог метрики")
    recommended_actions: list[str] = Field(default_factory=list, description="Рекомендации")
    requires_human_review: bool = Field(default=False, description="Требует проверки человеком")


class SystemAnalysis(BaseModel):
    """Результат анализа системы."""
    summary: str = Field(..., description="Сводка")
    events: list[SystemEvent] = Field(..., min_length=1, description="События — минимум 1 (INFO если нет проблем)")
    highest_severity: Optional[SeverityLevel] = Field(None, description="Максимальный уровень severity")
    requires_immediate_attention: bool = Field(default=False)


# ═══════════════════════════════════════════════
# Анализ сети
# ═══════════════════════════════════════════════

class NetworkEventType(str, Enum):
    PORT_SCAN = "PORT_SCAN"
    SUSPICIOUS_CONNECTION = "SUSPICIOUS_CONNECTION"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    UNUSUAL_PORT = "UNUSUAL_PORT"
    CONNECTION_ANOMALY = "CONNECTION_ANOMALY"
    INFO = "INFO"


class NetworkEvent(BaseModel):
    """Событие сетевого мониторинга."""
    event_type: NetworkEventType
    severity: SeverityLevel
    description: str
    confidence_score: float = Field(ge=0.0, le=1.0)
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    process_name: Optional[str] = None
    recommended_actions: list[str] = Field(default_factory=list)
    requires_human_review: bool = False


class NetworkAnalysis(BaseModel):
    """Результат анализа сети."""
    summary: str
    events: list[NetworkEvent] = Field(..., min_length=1)
    highest_severity: Optional[SeverityLevel] = None
    requires_immediate_attention: bool = False


# ═══════════════════════════════════════════════
# Агрегированный результат
# ═══════════════════════════════════════════════

class AggregateAnalysis(BaseModel):
    """Агрегированный результат по системе + сети + логам."""
    system: SystemAnalysis
    network: NetworkAnalysis
    logs: LogAnalysis
    overall_severity: SeverityLevel
    requires_immediate_attention: bool = False
