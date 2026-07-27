"""
DataCollector — сбор данных мониторинга: система, сеть, логи.
Использует psutil для системных метрик, seek+inode для чтения логов.
Основано на подходе LogSentinelAI RealtimeLogMonitor.
"""

from __future__ import annotations
import asyncio
import logging
import os
import time
from typing import Optional

logger = logging.getLogger("sais.collector")


class DataCollector:
    """
    Сборщик данных мониторинга.
    Система: CPU, RAM, диск, процессы, пользователи (psutil)
    Сеть: соединения, порты, трафик (psutil.net_connections)
    Логи: инкрементальное чтение с inode-трекингом (LogSentinelAI подход)
    """

    def __init__(self, config: dict):
        self.config = config
        self._last_system = {}
        self._last_network = {}
        self._last_logs = {}

        # Log-трекинг (как LogSentinelAI RealtimeLogMonitor)
        self._log_trackers: dict[str, dict] = {}  # log_path -> {inode, size, buffer}

        # Пытаемся импортировать psutil
        try:
            import psutil as _psutil
            self._psutil = _psutil
            self._has_psutil = True
        except ImportError:
            self._has_psutil = False
            logger.warning("psutil not installed, system monitoring will be limited")

    async def collect_system(self) -> dict:
        """Сбор системных метрик через psutil."""
        result = self._collect_system_sync()
        self._last_system = result
        return result

    def _collect_system_sync(self) -> dict:
        """Синхронный сбор (для вызова из async)."""
        if not self._has_psutil:
            return self._fallback_system()

        psutil = self._psutil
        result = {
            "cpu_percent": psutil.cpu_percent(interval=0.5),
            "cpu_count": psutil.cpu_count(),
            "load_avg": [round(x / psutil.cpu_count() * 100, 1) for x in psutil.getloadavg()] if hasattr(psutil, 'getloadavg') else [],
            "memory_percent": psutil.virtual_memory().percent,
            "memory_used_gb": round(psutil.virtual_memory().used / (1024**3), 1),
            "memory_total_gb": round(psutil.virtual_memory().total / (1024**3), 1),
            "disk_percent": psutil.disk_usage('/').percent,
            "disk_free_gb": round(psutil.disk_usage('/').free / (1024**3), 1),
            "process_count": len(psutil.pids()),
            "users": list(set(u.name for u in psutil.users())),
            "suspicious_processes": self._check_suspicious_processes(psutil),
            "boot_time": psutil.boot_time(),
            "uptime_seconds": int(time.time() - psutil.boot_time()) if hasattr(psutil, 'boot_time') else 0,
            "timestamp": time.time(),
        }

        # Топ процессов по CPU
        result["top_processes"] = self._get_top_processes(psutil, limit=10)

        return result

    def _get_top_processes(self, psutil, limit: int = 10) -> list[dict]:
        """Топ-N процессов по CPU."""
        processes = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'username']):
                try:
                    pinfo = proc.info
                    if pinfo['cpu_percent'] is not None and pinfo['cpu_percent'] > 0:
                        processes.append({
                            "pid": pinfo['pid'],
                            "name": pinfo['name'],
                            "cpu": pinfo['cpu_percent'],
                            "memory": pinfo['memory_percent'],
                            "user": pinfo['username'],
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            processes.sort(key=lambda p: p['cpu'], reverse=True)
        except Exception as e:
            logger.debug("Failed to get top processes: %s", e)
        return processes[:limit]

    def _check_suspicious_processes(self, psutil) -> list[dict]:
        """Проверка подозрительных процессов."""
        suspicious_keywords = [
            "ncat", "netcat", "nmap", "masscan", "hydra",
            "john", "hashcat", "sqlmap", "metasploit",
            "tcpdump", "tshark", "ettercap", "bettercap",
            "proxychains", "nohup",
            "minerd", "xmr", "cryptominer",
            "nc -", "bash -i",
        ]
        found = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
                try:
                    name = (proc.info['name'] or '').lower()
                    cmdline = ' '.join(proc.info['cmdline'] or []).lower()
                    for kw in suspicious_keywords:
                        if kw.lower() in name or kw.lower() in cmdline:
                            found.append({
                                "pid": proc.info['pid'],
                                "name": proc.info['name'],
                                "user": proc.info['username'],
                                "matched": kw,
                            })
                            break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            logger.debug("Suspicious process check failed: %s", e)
        return found

    async def _fallback_system(self) -> dict:
        """Fallback без psutil (только базовая инфа)."""
        import subprocess
        result = {
            "cpu_percent": 0.0,
            "memory_percent": 0.0,
            "disk_percent": 0.0,
            "process_count": 0,
            "users": [],
            "suspicious_processes": [],
            "top_processes": [],
            "timestamp": time.time(),
            "note": "psutil not installed — limited monitoring",
        }
        try:
            out = await asyncio.to_thread(
                lambda: subprocess.run(
                    ["df", "/"], capture_output=True, text=True, timeout=3
                ).stdout
            )
            result["disk_percent"] = float(out.strip().split("\n")[-1].split()[4].rstrip("%"))
        except Exception:
            pass
        return result

    async def collect_network(self) -> dict:
        """Сбор сетевых данных через psutil."""
        if not self._has_psutil:
            result = {"connections": [], "connection_count": 0, "listening_ports": [], "suspicious_connections": [], "timestamp": time.time()}
            self._last_network = result
            return result

        psutil = self._psutil
        result = {
            "connections": [],
            "connection_count": 0,
            "listening_ports": [],
            "suspicious_connections": [],
            "net_io": self._get_net_io(psutil),
            "timestamp": time.time(),
        }

        try:
            # Все соединения
            conns = psutil.net_connections(kind='inet')
            result["connection_count"] = len(conns)

            for conn in conns:
                entry = {
                    "fd": conn.fd,
                    "family": str(conn.family),
                    "type": str(conn.type),
                    "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                    "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                    "status": conn.status,
                    "pid": conn.pid,
                }
                result["connections"].append(entry)

                # Слушающие порты
                if conn.status == 'LISTEN':
                    if conn.laddr:
                        result["listening_ports"].append({
                            "port": conn.laddr.port,
                            "address": conn.laddr.ip,
                            "pid": conn.pid,
                        })

            # Подозрительные соединения (внешние на известные порты)
            suspicious_ports = {22, 23, 3389, 5900, 4444, 6667, 1337, 4443, 8443, 9090, 31337, 44445}
            for conn in conns:
                if conn.raddr and conn.raddr.port in suspicious_ports:
                    if not conn.raddr.ip.startswith(('10.', '172.16.', '172.17.', '192.168.', '127.')):
                        result["suspicious_connections"].append({
                            "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                            "raddr": f"{conn.raddr.ip}:{conn.raddr.port}",
                            "status": conn.status,
                            "pid": conn.pid,
                            "reason": f"suspicious_port_{conn.raddr.port}",
                        })

        except (psutil.AccessDenied, PermissionError) as e:
            logger.warning("Network monitoring requires elevated privileges: %s", e)
        except Exception as e:
            logger.error("Network collection error: %s", e)

        # Лимитируем количество соединений в выводе
        result["connections"] = result["connections"][:100]

        self._last_network = result
        return result

    def _get_net_io(self, psutil) -> dict:
        """Счётчики сетевого трафика."""
        try:
            io = psutil.net_io_counters()
            return {
                "bytes_sent": io.bytes_sent,
                "bytes_recv": io.bytes_recv,
                "packets_sent": io.packets_sent,
                "packets_recv": io.packets_recv,
                "errin": io.errin,
                "errout": io.errout,
                "dropin": io.dropin,
                "dropout": io.dropout,
            }
        except Exception:
            return {}

    async def collect_logs(self) -> dict:
        """Инкрементальное чтение логов с трекингом inode (LogSentinelAI подход)."""
        log_paths = self.config["monitoring"]["logs"].get("paths", [])
        result = {"recent": [], "timestamp": time.time()}

        for log_path in log_paths:
            if not os.path.exists(log_path):
                continue

            try:
                tracker = self._log_trackers.get(log_path, {"inode": None, "size": 0, "buffer": ""})
                current_stat = os.stat(log_path)
                current_inode = current_stat.st_ino
                current_size = current_stat.st_size

                # Ротация лога (inode изменился)
                if tracker["inode"] is not None and current_inode != tracker["inode"]:
                    logger.info("Log rotation detected: %s (inode %d -> %d)", log_path, tracker["inode"], current_inode)
                    tracker["inode"] = current_inode
                    tracker["size"] = current_size
                    tracker["buffer"] = ""
                    continue

                # Файл урезан (truncated)
                if current_size < tracker["size"]:
                    logger.info("Log truncated: %s (%d -> %d)", log_path, tracker["size"], current_size)
                    tracker["size"] = current_size
                    tracker["buffer"] = ""
                    continue

                # Новые данные
                if current_size > tracker["size"]:
                    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                        f.seek(tracker["size"])
                        new_content = f.read()

                        if new_content:
                            # Обрабатываем линии
                            lines = new_content.split('\n')
                            if new_content.endswith('\n'):
                                complete_lines = lines[:-1]
                                incomplete = ""
                            else:
                                complete_lines = lines[:-1]
                                incomplete = lines[-1] if lines else ""

                            # Соединяем с буфером если есть
                            if tracker["buffer"] and complete_lines:
                                complete_lines[0] = tracker["buffer"] + complete_lines[0]

                            # Обновляем буфер
                            if incomplete:
                                tracker["buffer"] = incomplete
                            else:
                                tracker["buffer"] = ""

                            # Обновляем позицию
                            incomplete_bytes = len(incomplete.encode('utf-8')) if incomplete else 0
                            tracker["size"] = current_size - incomplete_bytes
                            tracker["inode"] = current_inode

                            # Добавляем в результат (макс 10 строк на файл)
                            for line in complete_lines:
                                stripped = line.strip()
                                if stripped:
                                    result["recent"].append({
                                        "source": os.path.basename(log_path),
                                        "content": stripped,
                                    })
                                    if len(result["recent"]) >= 30:
                                        break

                            logger.debug("Read %d lines from %s", len(complete_lines), log_path)

                self._log_trackers[log_path] = tracker

            except (OSError, PermissionError) as e:
                logger.debug("Cannot read %s: %s", log_path, e)
                continue
            except Exception as e:
                logger.warning("Error reading %s: %s", log_path, e)
                continue

        self._last_logs = result
        return result

    async def get_live_snapshot(self) -> dict:
        """Быстрый снепшот всех данных."""
        system, network, logs = await asyncio.gather(
            self.collect_system(),
            self.collect_network(),
            self.collect_logs(),
        )
        return {"system": system, "network": network, "logs": logs}

    def get_last_data(self) -> dict:
        """Последние собранные данные."""
        return {
            "system": self._last_system,
            "network": self._last_network,
            "logs": self._last_logs,
        }
