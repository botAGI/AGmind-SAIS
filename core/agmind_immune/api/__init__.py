"""Authenticated read-only Core management boundary."""

from .server import ManagementResponse, ManagementServer, ProtectedRouteProvider

__all__ = ["ManagementResponse", "ManagementServer", "ProtectedRouteProvider"]
