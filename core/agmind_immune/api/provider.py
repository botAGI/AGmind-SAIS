"""Strict read-only projection of the Core runtime for the management boundary."""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Protocol, final

from agmind_immune.actions import ActuatorMirrorError
from agmind_immune.canonicaljson import canonical_json
from agmind_immune.contracts import ActionRecordV1
from agmind_immune.hunter import HunterInvestigationRecord, HunterInvestigationStoreError

from .server import ManagementResponse

_ACTION_ID = re.compile(r"^act_[0-9a-f]{32}$")
_CANDIDATE_ID = re.compile(r"^cand_[0-9a-f]{64}$")
_UINT = re.compile(r"^(?:0|[1-9][0-9]*)$")
_DEFAULT_LIMIT = 50
_MAX_LIMIT = 100
_MAX_ACTION_AFTER = 65_536
# Leave room under ManagementResponse's 64 KiB body limit for page metadata.
_PAGE_ITEM_BUDGET = 60 * 1_024


class CoreRuntimeStatusView(Protocol):
    """Fields deliberately disclosed by the protected status endpoint."""

    @property
    def polls(self) -> int: ...

    @property
    def policy_commits(self) -> int: ...

    @property
    def prepared_plans(self) -> int: ...

    @property
    def quarantined_intents(self) -> int: ...

    @property
    def last_hunter_status(self) -> str | None: ...

    @property
    def hunter_persistence_status(self) -> str: ...

    @property
    def actuator_feedback_status(self) -> str: ...

    @property
    def actuator_journal_records(self) -> int: ...

    @property
    def action_records(self) -> int: ...


class CoreRuntimeReadView(Protocol):
    """Cycle-free subset of CoreRuntime exposed through authenticated reads."""

    @property
    def status(self) -> CoreRuntimeStatusView: ...

    def action_records(
        self,
        *,
        after: int,
        limit: int,
    ) -> tuple[ActionRecordV1, ...]: ...

    def latest_action(self, action_id: str) -> ActionRecordV1 | None: ...

    def hunter_investigations(
        self,
        *,
        after: str | None,
        limit: int,
    ) -> tuple[HunterInvestigationRecord, ...]: ...


class _InvalidQuery(ValueError):
    pass


def _json_response(status_code: int, document: dict[str, object]) -> ManagementResponse:
    return ManagementResponse(status_code, canonical_json(document))


def _error(status_code: int, code: str) -> ManagementResponse:
    return _json_response(status_code, {"error": code})


def _split_target(target: str) -> tuple[str, str | None]:
    path, separator, query = target.partition("?")
    if separator and (not query or "?" in query):
        raise _InvalidQuery("query framing is invalid")
    return path, query if separator else None


def _query_parameters(
    query: str | None,
    *,
    allowed: frozenset[str],
) -> dict[str, str]:
    if query is None:
        return {}
    parameters: dict[str, str] = {}
    for item in query.split("&"):
        if not item or item.count("=") != 1:
            raise _InvalidQuery("query item is invalid")
        name, value = item.split("=", 1)
        if name not in allowed or name in parameters or not value:
            raise _InvalidQuery("query parameter is invalid")
        parameters[name] = value
    return parameters


def _unsigned(value: str, *, maximum: int) -> int:
    if _UINT.fullmatch(value) is None:
        raise _InvalidQuery("unsigned integer is not canonical")
    parsed = int(value)
    if parsed > maximum:
        raise _InvalidQuery("unsigned integer exceeds its bound")
    return parsed


def _limit(parameters: dict[str, str]) -> int:
    value = parameters.get("limit")
    if value is None:
        return _DEFAULT_LIMIT
    parsed = _unsigned(value, maximum=_MAX_LIMIT)
    if parsed == 0:
        raise _InvalidQuery("limit must be positive")
    return parsed


def _bounded_items[T](items: Sequence[T]) -> list[T]:
    selected: list[T] = []
    encoded_size = 2
    for item in items:
        item_size = len(canonical_json(item))
        next_size = encoded_size + item_size + (1 if selected else 0)
        if next_size > _PAGE_ITEM_BUDGET:
            break
        selected.append(item)
        encoded_size = next_size
    if items and not selected:
        raise ValueError("one management record exceeds the page body bound")
    return selected


def _hunter_document(record: HunterInvestigationRecord) -> dict[str, object]:
    return {
        "candidate_id": record.candidate_id,
        "bundle_sha256": record.bundle_sha256,
        "status": record.status,
        "reason_code": record.reason_code,
        "output": record.output(),
        "record_sha256": record.record_sha256,
    }


@final
class CoreRuntimeProvider:
    """Serve only the four explicitly supported authenticated Core views."""

    __slots__ = ("_runtime",)

    def __init__(self, runtime: CoreRuntimeReadView) -> None:
        self._runtime = runtime

    async def get(self, target: str) -> ManagementResponse:
        try:
            path, query = _split_target(target)
            if path == "/v1/status":
                return self._status(query)
            if path == "/v1/actions":
                return self._actions(query)
            if path == "/v1/hunter":
                return self._hunter(query)
            if path.startswith("/v1/actions/"):
                return self._action(path, query)
        except _InvalidQuery:
            return _error(400, "bad_query")
        except (ActuatorMirrorError, HunterInvestigationStoreError):
            return _error(503, "store_unavailable")
        return _error(404, "not_found")

    def _status(self, query: str | None) -> ManagementResponse:
        if query is not None:
            raise _InvalidQuery("status does not accept query parameters")
        status = self._runtime.status
        return _json_response(
            200,
            {
                "schema_version": "agmind.core-runtime-status.v1",
                "polls": status.polls,
                "policy_commits": status.policy_commits,
                "prepared_plans": status.prepared_plans,
                "quarantined_intents": status.quarantined_intents,
                "last_hunter_status": status.last_hunter_status,
                "hunter_persistence_status": status.hunter_persistence_status,
                "actuator_feedback_status": status.actuator_feedback_status,
                "actuator_journal_records": status.actuator_journal_records,
                "action_records": status.action_records,
            },
        )

    def _actions(self, query: str | None) -> ManagementResponse:
        parameters = _query_parameters(query, allowed=frozenset({"after", "limit"}))
        after_value = parameters.get("after")
        after = 0 if after_value is None else _unsigned(after_value, maximum=_MAX_ACTION_AFTER)
        limit = _limit(parameters)
        try:
            records = self._runtime.action_records(after=after, limit=limit)
        except ValueError as error:
            raise _InvalidQuery("action page is invalid") from error
        selected = _bounded_items(records)
        returned = len(selected)
        return _json_response(
            200,
            {
                "schema_version": "agmind.action-record-page.v1",
                "after": after,
                "limit": limit,
                "returned": returned,
                "next_after": after + returned,
                "truncated": returned < len(records),
                "records": selected,
            },
        )

    def _action(self, path: str, query: str | None) -> ManagementResponse:
        if query is not None:
            raise _InvalidQuery("action lookup does not accept query parameters")
        action_id = path.removeprefix("/v1/actions/")
        if _ACTION_ID.fullmatch(action_id) is None:
            return _error(404, "not_found")
        record = self._runtime.latest_action(action_id)
        if record is None:
            return _error(404, "not_found")
        return _json_response(
            200,
            {
                "schema_version": "agmind.action-record-view.v1",
                "record": record,
            },
        )

    def _hunter(self, query: str | None) -> ManagementResponse:
        parameters = _query_parameters(query, allowed=frozenset({"after", "limit"}))
        after = parameters.get("after")
        if after is not None and _CANDIDATE_ID.fullmatch(after) is None:
            raise _InvalidQuery("Hunter cursor is invalid")
        limit = _limit(parameters)
        records = self._runtime.hunter_investigations(after=after, limit=limit)
        documents = [_hunter_document(record) for record in records]
        selected = _bounded_items(documents)
        next_after = after if not selected else str(selected[-1]["candidate_id"])
        return _json_response(
            200,
            {
                "schema_version": "agmind.hunter-investigation-page.v1",
                "after": after,
                "limit": limit,
                "returned": len(selected),
                "next_after": next_after,
                "truncated": len(selected) < len(documents),
                "investigations": selected,
            },
        )


__all__ = ["CoreRuntimeProvider", "CoreRuntimeReadView", "CoreRuntimeStatusView"]
